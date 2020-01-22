package com.amazonaws.encryptionsdk.model;

import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.DataKey;
import com.amazonaws.encryptionsdk.keyrings.KeyringTrace;
import com.amazonaws.encryptionsdk.keyrings.KeyringTraceEntry;

import javax.crypto.SecretKey;
import java.security.PublicKey;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import static java.util.Objects.requireNonNull;
import static org.apache.commons.lang3.ArrayUtils.EMPTY_BYTE_ARRAY;
import static org.apache.commons.lang3.Validate.isTrue;

public final class DecryptionMaterials {
    private final CryptoAlgorithm algorithm;
    private final Map<String, String> encryptionContext;
    private DataKey<?> dataKey;
    private final PublicKey trailingSignatureKey;
    private final KeyringTrace keyringTrace;

    private DecryptionMaterials(Builder b) {
        algorithm = b.algorithm;
        encryptionContext = b.encryptionContext;
        dataKey = b.getDataKey();
        trailingSignatureKey = b.getTrailingSignatureKey();
        keyringTrace = b.keyringTrace;
    }

    /**
     * The algorithm suite to use for this decryption operation.
     */
    public CryptoAlgorithm getAlgorithm() {
        return algorithm;
    }

    /**
     * The encryption context
     */
    public Map<String, String> getEncryptionContext() {
        return encryptionContext;
    }

    /**
     * @deprecated Replaced by {@link #getCleartextDataKey()}
     */
    @Deprecated
    public DataKey<?> getDataKey() {
        return dataKey;
    }

    /**
     * Sets the cleartext data key. The cleartext data key must not already be populated.
     *
     * @param cleartextDataKey  The cleartext data key.
     * @param keyringTraceEntry The keyring trace entry recording this action.
     */
    public void setCleartextDataKey(SecretKey cleartextDataKey, KeyringTraceEntry keyringTraceEntry) {
        if (hasCleartextDataKey()) {
            throw new IllegalStateException("cleartextDataKey was already populated");
        }
        requireNonNull(cleartextDataKey, "cleartextDataKey is required");
        requireNonNull(keyringTraceEntry, "keyringTraceEntry is required");
        validateCleartextDataKey(algorithm, cleartextDataKey);
        this.dataKey = new DataKey<>(cleartextDataKey, EMPTY_BYTE_ARRAY, EMPTY_BYTE_ARRAY, null);
        keyringTrace.add(keyringTraceEntry);
    }

    public SecretKey getCleartextDataKey() {
        return dataKey == null ? null : dataKey.getKey();
    }

    /**
     * Returns true if a cleartext data key has been populated.
     *
     * @return True if cleartext data key is populated, false otherwise.
     */
    public boolean hasCleartextDataKey() {
        return this.dataKey != null;
    }

    public PublicKey getTrailingSignatureKey() {
        return trailingSignatureKey;
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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DecryptionMaterials that = (DecryptionMaterials) o;

        return algorithm == that.algorithm &&
                Objects.equals(getCleartextDataKey(), that.getCleartextDataKey()) &&
                Objects.equals(trailingSignatureKey, that.trailingSignatureKey) &&
                Objects.equals(encryptionContext, that.encryptionContext) &&
                Objects.equals(keyringTrace, that.keyringTrace);
    }

    @Override
    public int hashCode() {
        return Objects.hash(algorithm, getCleartextDataKey(), trailingSignatureKey, encryptionContext, keyringTrace);
    }

    private void validateCleartextDataKey(CryptoAlgorithm algorithm, SecretKey cleartextDataKey) throws IllegalArgumentException {
        if (algorithm != null && cleartextDataKey != null) {
            isTrue(algorithm.getDataKeyLength() == cleartextDataKey.getEncoded().length,
                    String.format("Incorrect key length. Expected %s but got %s",
                            algorithm.getDataKeyLength(), cleartextDataKey.getEncoded().length));
            isTrue(algorithm.getDataKeyAlgo().equalsIgnoreCase(cleartextDataKey.getAlgorithm()),
                    String.format("Incorrect key algorithm. Expected %s but got %s",
                            algorithm.getDataKeyAlgo(), cleartextDataKey.getAlgorithm()));
        }
    }

    public static final class Builder {
        private CryptoAlgorithm algorithm;
        private Map<String, String> encryptionContext = Collections.emptyMap();
        private DataKey<?> dataKey;
        private PublicKey trailingSignatureKey;
        private KeyringTrace keyringTrace = new KeyringTrace();

        private Builder(DecryptionMaterials result) {
            this.algorithm = result.getAlgorithm();
            this.encryptionContext = result.getEncryptionContext();
            this.dataKey = result.getDataKey();
            this.trailingSignatureKey = result.getTrailingSignatureKey();
            this.keyringTrace = result.keyringTrace;
        }

        private Builder() {}

        public CryptoAlgorithm getAlgorithm() {
            return algorithm;
        }

        public Builder setAlgorithm(CryptoAlgorithm algorithm) {
            requireNonNull(algorithm, "algorithm is required");
            this.algorithm = algorithm;
            return this;
        }

        public Map<String, String> getEncryptionContext() {
            return encryptionContext;
        }

        public Builder setEncryptionContext(Map<String, String> encryptionContext) {
            requireNonNull(encryptionContext, "encryptionContext is required");
            this.encryptionContext = Collections.unmodifiableMap(new HashMap<>(encryptionContext));
            return this;
        }

        @Deprecated
        public DataKey<?> getDataKey() {
            return dataKey;
        }

        @Deprecated
        public Builder setDataKey(DataKey<?> dataKey) {
            this.dataKey = dataKey;
            return this;
        }

        /**
         * Sets the cleartext data key.
         *
         * @param cleartextDataKey  The cleartext data key.
         */
        public Builder setCleartextDataKey(SecretKey cleartextDataKey) {
            requireNonNull(cleartextDataKey, "cleartextDataKey is required");
            this.dataKey = new DataKey<>(cleartextDataKey, EMPTY_BYTE_ARRAY, EMPTY_BYTE_ARRAY, null);
            return this;
        }

        public PublicKey getTrailingSignatureKey() {
            return trailingSignatureKey;
        }

        public Builder setTrailingSignatureKey(PublicKey trailingSignatureKey) {
            this.trailingSignatureKey = trailingSignatureKey;
            return this;
        }

        public KeyringTrace getKeyringTrace() {
            return keyringTrace;
        }

        public Builder setKeyringTrace(KeyringTrace keyringTrace) {
            requireNonNull(keyringTrace, "keyringTrace is required");
            this.keyringTrace = keyringTrace;
            return this;
        }

        public DecryptionMaterials build() {
            return new DecryptionMaterials(this);
        }
    }
}
