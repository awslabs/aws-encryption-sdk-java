package com.amazonaws.encryptionsdk.model;

import java.security.PublicKey;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.MasterKey;
import com.amazonaws.encryptionsdk.keyrings.KeyringTrace;

import javax.crypto.SecretKey;

public final class DecryptionMaterials {
    private final CryptoAlgorithm algorithm;
    private SecretKey cleartextDataKey;
    private final MasterKey<?> masterKey;
    private final PublicKey trailingSignatureKey;
    private final Map<String, String> encryptionContext;
    private final KeyringTrace keyringTrace;

    private DecryptionMaterials(Builder b) {
        algorithm = b.getAlgorithm();
        cleartextDataKey = b.getCleartextDataKey();
        masterKey = b.getMasterKey();
        trailingSignatureKey = b.getTrailingSignatureKey();
        encryptionContext = b.getEncryptionContext();
        keyringTrace = b.getKeyringTrace();
    }

    /**
     * The algorithm to use for this decryption operation. Must match the algorithm in DecryptionMaterialsRequest, if that
     * algorithm was non-null.
     */
    public CryptoAlgorithm getAlgorithm() {
        return algorithm;
    }

    public SecretKey getCleartextDataKey() {
        return cleartextDataKey;
    }

    public void setCleartextDataKey(SecretKey cleartextDataKey) {
        if(this.cleartextDataKey != null) {
            throw new IllegalStateException("cleartextDataKey was already populated");
        }

        this.cleartextDataKey = cleartextDataKey;
    }

    /**
     * Gets the MasterKey (if any) used for decrypting the data key. Will be null
     * if a KeyRing was used instead of a MasterKeyProvider.
     * @return The MasterKey
     */
    public MasterKey<?> getMasterKey() {
        return masterKey;
    }

    public PublicKey getTrailingSignatureKey() {
        return trailingSignatureKey;
    }

    public Map<String, String> getEncryptionContext() {
        return encryptionContext;
    }

    public KeyringTrace getKeyringTrace() {
        return keyringTrace;
    }

    public static Builder newBuilder() {
        return new Builder();
    }

    public Builder toBuilder() {
        return new Builder(this);
    }

    public static final class Builder {
        private CryptoAlgorithm algorithm;
        private SecretKey cleartextDataKey;
        private MasterKey<?> masterKey;
        private PublicKey trailingSignatureKey;
        private Map<String, String> encryptionContext;
        private KeyringTrace keyringTrace;

        private Builder(DecryptionMaterials result) {
            this.algorithm = result.getAlgorithm();
            this.cleartextDataKey = result.getCleartextDataKey();
            this.masterKey = result.getMasterKey();
            this.trailingSignatureKey = result.getTrailingSignatureKey();
            this.keyringTrace = result.getKeyringTrace();
        }

        private Builder() {}

        public CryptoAlgorithm getAlgorithm() {
            return algorithm;
        }

        public Builder setAlgorithm(CryptoAlgorithm algorithm) {
            this.algorithm = algorithm;
            return this;
        }

        public SecretKey getCleartextDataKey() {
            return cleartextDataKey;
        }

        public Builder setCleartextDataKey(SecretKey cleartextDataKey) {
            this.cleartextDataKey = cleartextDataKey;
            return this;
        }

        public MasterKey<?> getMasterKey() {
            return masterKey;
        }

        public Builder setMasterKey(MasterKey<?> masterKey) {
            this.masterKey = masterKey;
            return this;
        }

        public PublicKey getTrailingSignatureKey() {
            return trailingSignatureKey;
        }

        public Builder setTrailingSignatureKey(PublicKey trailingSignatureKey) {
            this.trailingSignatureKey = trailingSignatureKey;
            return this;
        }

        public Map<String, String> getEncryptionContext() {
            return encryptionContext;
        }

        public Builder setEncryptionContext(Map<String, String> encryptionContext) {
            this.encryptionContext = Collections.unmodifiableMap(new HashMap<>(encryptionContext));
            return this;
        }

        public KeyringTrace getKeyringTrace() {
            return keyringTrace;
        }

        public Builder setKeyringTrace(KeyringTrace keyringTrace) {
            this.keyringTrace = keyringTrace;
            return this;
        }

        public DecryptionMaterials build() {
            return new DecryptionMaterials(this);
        }
    }
}
