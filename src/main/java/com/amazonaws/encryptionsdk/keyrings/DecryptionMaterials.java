/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except
 * in compliance with the License. A copy of the License is located at
 *
 * http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.amazonaws.encryptionsdk.keyrings;

import com.amazonaws.encryptionsdk.CryptoAlgorithm;

import javax.crypto.SecretKey;
import java.security.PublicKey;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import static java.util.Objects.requireNonNull;
import static org.apache.commons.lang3.Validate.isTrue;

/**
 * Contains the cryptographic materials needed for a decryption operation with Keyrings.
 */
public final class DecryptionMaterials {
    private final CryptoAlgorithm algorithmSuite;
    private SecretKey plaintextDataKey;
    private final PublicKey verificationKey;
    private final Map<String, String> encryptionContext;
    private final KeyringTrace keyringTrace;

    private DecryptionMaterials(Builder b) {
        requireNonNull(b.algorithmSuite, "algorithmSuite is required");
        requireNonNull(b.keyringTrace, "keyringTrace is required");
        requireNonNull(b.encryptionContext, "encryptionContext is required");
        validatePlaintextDataKey(b.algorithmSuite, b.plaintextDataKey);
        validateVerificationKey(b.algorithmSuite, b.verificationKey);

        algorithmSuite = b.algorithmSuite;
        plaintextDataKey = b.plaintextDataKey;
        verificationKey = b.verificationKey;
        encryptionContext = b.encryptionContext;
        keyringTrace = b.keyringTrace;
    }

    /**
     * The algorithm suite to use for this decryption operation.
     */
    public CryptoAlgorithm getAlgorithmSuite() {
        return algorithmSuite;
    }

    /**
     * Returns true if a plaintext data key has been populated.
     *
     * @return True if plaintext data key is populated, false otherwise.
     */
    public boolean hasPlaintextDataKey() {
        return this.plaintextDataKey != null;
    }

    /**
     * A data key to be used as input for encryption.
     *
     * @return The plaintext data key.
     * @throws IllegalStateException if plaintext data key has not been populated.
     */
    public SecretKey getPlaintextDataKey() throws IllegalStateException {
        if (!hasPlaintextDataKey()) {
            throw new IllegalStateException("plaintextDataKey has not been populated");
        }
        return plaintextDataKey;
    }

    /**
     * Sets the plaintext data key. The plaintext data key must not already be populated.
     *
     * @param plaintextDataKey  The plaintext data key.
     * @param keyringTraceEntry The keyring trace entry recording this action.
     */
    public void setPlaintextDataKey(SecretKey plaintextDataKey, KeyringTraceEntry keyringTraceEntry) {
        if (hasPlaintextDataKey()) {
            throw new IllegalStateException("plaintextDataKey was already populated");
        }
        requireNonNull(plaintextDataKey, "plaintextDataKey is required");
        requireNonNull(keyringTraceEntry, "keyringTraceEntry is required");
        validatePlaintextDataKey(algorithmSuite, plaintextDataKey);
        this.plaintextDataKey = plaintextDataKey;
        keyringTrace.add(keyringTraceEntry);
    }

    /**
     * Returns true if verification key has been populated.
     *
     * @return True if verification key is populated, false otherwise.
     */
    public boolean hasVerificationKey() {
        return verificationKey != null;
    }

    /**
     * The verification key used for signature verification.
     *
     * @return The verification key.
     * @throws IllegalStateException if a verification key has not been populated.
     */
    public PublicKey getVerificationKey() throws IllegalStateException {
        if (!hasVerificationKey()) {
            throw new IllegalStateException(String.format(
                    "Signature verification is not supported by AlgorithmSuite %s", algorithmSuite.name()));
        }
        return verificationKey;
    }

    public Map<String, String> getEncryptionContext() {
        return encryptionContext;
    }

    public KeyringTrace getKeyringTrace() {
        return keyringTrace;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DecryptionMaterials that = (DecryptionMaterials) o;
        return algorithmSuite == that.algorithmSuite &&
                Objects.equals(plaintextDataKey, that.plaintextDataKey) &&
                Objects.equals(verificationKey, that.verificationKey) &&
                Objects.equals(encryptionContext, that.encryptionContext) &&
                Objects.equals(keyringTrace, that.keyringTrace);
    }

    @Override
    public int hashCode() {
        return Objects.hash(algorithmSuite, plaintextDataKey, verificationKey, encryptionContext, keyringTrace);
    }

    public static Builder newBuilder(CryptoAlgorithm algorithm) {
        return new Builder(algorithm);
    }

    public Builder toBuilder() {
        return new Builder(this);
    }

    private void validatePlaintextDataKey(CryptoAlgorithm algorithmSuite, SecretKey plaintextDataKey) throws IllegalArgumentException {
        if (plaintextDataKey != null) {
            isTrue(algorithmSuite.getDataKeyLength() == plaintextDataKey.getEncoded().length,
                    String.format("Incorrect key length. Expected %s but got %s",
                            algorithmSuite.getDataKeyLength(), plaintextDataKey.getEncoded().length));
            isTrue(algorithmSuite.getDataKeyAlgo().equalsIgnoreCase(plaintextDataKey.getAlgorithm()),
                    String.format("Incorrect key algorithm. Expected %s but got %s",
                            algorithmSuite.getDataKeyAlgo(), plaintextDataKey.getAlgorithm()));
        }
    }

    /**
     * Validates that a verification key is specified if and only if
     * the given algorithm suite supports signature verification.
     */
    private void validateVerificationKey(CryptoAlgorithm algorithmSuite, PublicKey verificationKey) throws IllegalArgumentException {
        if (algorithmSuite.getTrailingSignatureAlgo() == null && verificationKey != null) {
            throw new IllegalArgumentException(
                    String.format("Algorithm Suite %s does not support signature verification", algorithmSuite.name()));
        } else if (algorithmSuite.getTrailingSignatureAlgo() != null && verificationKey == null) {
            throw new IllegalArgumentException(
                    String.format("Algorithm %s requires a verification key for signature verification", algorithmSuite.name()));
        }
    }

    public static final class Builder {
        private CryptoAlgorithm algorithmSuite;
        private SecretKey plaintextDataKey;
        private PublicKey verificationKey;
        private Map<String, String> encryptionContext = Collections.emptyMap();
        private KeyringTrace keyringTrace = new KeyringTrace();

        private Builder(CryptoAlgorithm algorithmSuite) {
            this.algorithmSuite = algorithmSuite;
        }

        private Builder(DecryptionMaterials result) {
            this.algorithmSuite = result.algorithmSuite;
            this.plaintextDataKey = result.plaintextDataKey;
            this.verificationKey = result.verificationKey;
            this.encryptionContext = result.encryptionContext;
            this.keyringTrace = result.keyringTrace;
        }

        public Builder algorithmSuite(CryptoAlgorithm algorithmSuite) {
            this.algorithmSuite = algorithmSuite;
            return this;
        }

        public Builder plaintextDataKey(SecretKey plaintextDataKey) {
            this.plaintextDataKey = plaintextDataKey;
            return this;
        }

        public Builder verificationKey(PublicKey verificationKey) {
            this.verificationKey = verificationKey;
            return this;
        }

        public Builder encryptionContext(Map<String, String> encryptionContext) {
            this.encryptionContext = Collections.unmodifiableMap(new HashMap<>(encryptionContext));
            return this;
        }

        public Builder keyringTrace(KeyringTrace keyringTrace) {
            this.keyringTrace = keyringTrace;
            return this;
        }

        public DecryptionMaterials build() {
            return new DecryptionMaterials(this);
        }
    }
}
