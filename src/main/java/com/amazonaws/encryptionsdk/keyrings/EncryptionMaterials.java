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
import com.amazonaws.encryptionsdk.EncryptedDataKey;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import static org.apache.commons.lang3.Validate.isTrue;
import static org.apache.commons.lang3.Validate.notNull;

/**
 * Contains the cryptographic materials needed for an encryption operation with Keyrings.
 */
public final class EncryptionMaterials {
    private final CryptoAlgorithm algorithm;
    private final Map<String, String> encryptionContext;
    private final List<EncryptedDataKey> encryptedDataKeys;
    private SecretKey plaintextDataKey;
    private final PrivateKey signingKey;
    private final KeyringTrace keyringTrace;

    private EncryptionMaterials(Builder b) {
        notNull(b.algorithm, "algorithm is required");
        notNull(b.keyringTrace, "keyringTrace is required");
        validatePlaintextDataKey(b.algorithm, b.plaintextDataKey);
        validateSigningKey(b.algorithm, b.signingKey);
        this.algorithm = b.algorithm;
        this.encryptionContext = b.encryptionContext;
        this.encryptedDataKeys = b.encryptedDataKeys;
        this.plaintextDataKey = b.plaintextDataKey;
        this.signingKey = b.signingKey;
        this.keyringTrace = b.keyringTrace;
    }

    public Builder toBuilder() {
        return new Builder(this);
    }

    public static Builder newBuilder(CryptoAlgorithm algorithm) {
        return new Builder(algorithm);
    }

    /**
     * The algorithm suite to be used for encryption.
     */
    public CryptoAlgorithm getAlgorithm() {
        return algorithm;
    }

    /**
     * The encryption context associated with this encryption.
     */
    public Map<String, String> getEncryptionContext() {
        return encryptionContext;
    }

    /**
     * An unmodifiable list of the encrypted data keys that correspond to the plaintext data key.
     */
    public List<EncryptedDataKey> getEncryptedDataKeys() {
        return Collections.unmodifiableList(encryptedDataKeys);
    }

    /**
     * Add an encrypted data key to the list of encrypted data keys.
     *
     * @param encryptedDataKey  The encrypted data key to add.
     * @param keyringTraceEntry The keyring trace entry recording this action.
     */
    public void addEncryptedDataKey(EncryptedDataKey encryptedDataKey, KeyringTraceEntry keyringTraceEntry) {
        notNull(encryptedDataKey, "encryptedDataKey is required");
        notNull(keyringTraceEntry, "keyringTraceEntry is required");
        encryptedDataKeys.add(encryptedDataKey);
        keyringTrace.add(keyringTraceEntry);
    }

    /**
     * A data key to be used as input for encryption.
     */
    public SecretKey getPlaintextDataKey() {
        return plaintextDataKey;
    }

    /**
     * Sets the plaintext data key. The plaintext data key must not already be populated.
     *
     * @param plaintextDataKey  The plaintext data key.
     * @param keyringTraceEntry The keyring trace entry recording this action.
     */
    public void setPlaintextDataKey(SecretKey plaintextDataKey, KeyringTraceEntry keyringTraceEntry) {
        if (this.plaintextDataKey != null) {
            throw new IllegalStateException("plaintextDataKey was already populated");
        }
        notNull(plaintextDataKey, "plaintextDataKey is required");
        notNull(keyringTraceEntry, "keyringTraceEntry is required");
        validatePlaintextDataKey(algorithm, plaintextDataKey);
        this.plaintextDataKey = plaintextDataKey;
        keyringTrace.add(keyringTraceEntry);
    }

    /**
     * The key to be used as the signing key for signature verification during encryption.
     */
    public PrivateKey getSigningKey() {
        return signingKey;
    }

    /**
     * A keyring trace containing all of the actions that keyrings have taken on this set of encryption materials.
     */
    public KeyringTrace getKeyringTrace() {
        return keyringTrace;
    }

    /**
     * Validates that the given plaintext data key fits the specification
     * for the data key algorithm specified in the given algorithm suite.
     */
    private void validatePlaintextDataKey(CryptoAlgorithm algorithm, SecretKey plaintextDataKey) throws IllegalArgumentException {
        if (plaintextDataKey != null) {
            isTrue(algorithm.getDataKeyLength() == plaintextDataKey.getEncoded().length,
                    String.format("Incorrect data key length. Expected %s but got %s",
                            algorithm.getDataKeyLength(), plaintextDataKey.getEncoded().length));
            isTrue(algorithm.getDataKeyAlgo().equalsIgnoreCase(plaintextDataKey.getAlgorithm()),
                    String.format("Incorrect data key algorithm. Expected %s but got %s",
                            algorithm.getDataKeyAlgo(), plaintextDataKey.getAlgorithm()));
        }
    }

    /**
     * Validates that a signing key is specified only if and only if
     * the given algorithm suite supports signature verification.
     */
    private void validateSigningKey(CryptoAlgorithm algorithm, PrivateKey signingKey) throws IllegalArgumentException {
        if (algorithm.getTrailingSignatureAlgo() == null && signingKey != null) {
            throw new IllegalArgumentException(
                    String.format("Algorithm %s does not support signature verification", algorithm.name()));
        } else if (algorithm.getTrailingSignatureAlgo() != null && signingKey == null) {
            throw new IllegalArgumentException(
                    String.format("Algorithm %s requires a signing key for signature verification", algorithm.name()));
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EncryptionMaterials that = (EncryptionMaterials) o;
        return algorithm == that.algorithm &&
                Objects.equals(encryptionContext, that.encryptionContext) &&
                Objects.equals(encryptedDataKeys, that.encryptedDataKeys) &&
                Objects.equals(plaintextDataKey, that.plaintextDataKey) &&
                Objects.equals(signingKey, that.signingKey) &&
                Objects.equals(keyringTrace, that.keyringTrace);
    }

    @Override
    public int hashCode() {
        return Objects.hash(algorithm, encryptionContext, encryptedDataKeys, plaintextDataKey, signingKey, keyringTrace);
    }

    public static class Builder {
        private CryptoAlgorithm algorithm;
        private Map<String, String> encryptionContext = Collections.emptyMap();
        private List<EncryptedDataKey> encryptedDataKeys = new ArrayList<>();
        private SecretKey plaintextDataKey;
        private PrivateKey signingKey;
        private KeyringTrace keyringTrace = new KeyringTrace();

        private Builder(CryptoAlgorithm algorithm) {
            this.algorithm = algorithm;
        }

        private Builder(EncryptionMaterials r) {
            algorithm = r.algorithm;
            encryptionContext = r.encryptionContext;
            encryptedDataKeys = r.encryptedDataKeys;
            plaintextDataKey = r.plaintextDataKey;
            signingKey = r.signingKey;
            keyringTrace = r.keyringTrace;
        }

        public EncryptionMaterials build() {
            return new EncryptionMaterials(this);
        }

        public Builder setAlgorithm(CryptoAlgorithm algorithm) {
            this.algorithm = algorithm;
            return this;
        }

        public Builder setEncryptionContext(Map<String, String> encryptionContext) {
            this.encryptionContext = Collections.unmodifiableMap(new HashMap<>(encryptionContext));
            return this;
        }

        public Builder setEncryptedDataKeys(List<EncryptedDataKey> encryptedDataKeys) {
            this.encryptedDataKeys = new ArrayList<>(encryptedDataKeys);
            return this;
        }

        public Builder setPlaintextDataKey(SecretKey plaintextDataKey) {
            this.plaintextDataKey = plaintextDataKey;
            return this;
        }

        public Builder setSigningKey(PrivateKey signingKey) {
            this.signingKey = signingKey;
            return this;
        }

        public Builder setKeyringTrace(KeyringTrace keyringTrace) {
            this.keyringTrace = keyringTrace;
            return this;
        }
    }
}
