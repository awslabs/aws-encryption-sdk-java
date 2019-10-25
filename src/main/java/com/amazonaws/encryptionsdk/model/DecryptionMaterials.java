package com.amazonaws.encryptionsdk.model;

import java.security.PublicKey;

import com.amazonaws.encryptionsdk.DataKey;
import com.amazonaws.encryptionsdk.keyrings.KeyringTrace;

public final class DecryptionMaterials {
    private final DataKey<?> dataKey;
    private final PublicKey trailingSignatureKey;
    private final KeyringTrace keyringTrace;

    private DecryptionMaterials(Builder b) {
        dataKey = b.getDataKey();
        trailingSignatureKey = b.getTrailingSignatureKey();
        keyringTrace = b.getKeyringTrace();
    }

    public DataKey<?> getDataKey() {
        return dataKey;
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

    public static final class Builder {
        private DataKey<?> dataKey;
        private PublicKey trailingSignatureKey;
        private KeyringTrace keyringTrace;

        private Builder(DecryptionMaterials result) {
            this.dataKey = result.getDataKey();
            this.trailingSignatureKey = result.getTrailingSignatureKey();
            this.keyringTrace = result.getKeyringTrace();
        }

        private Builder() {}

        public DataKey<?> getDataKey() {
            return dataKey;
        }

        public Builder setDataKey(DataKey<?> dataKey) {
            this.dataKey = dataKey;
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
            this.keyringTrace = keyringTrace;
            return this;
        }

        public DecryptionMaterials build() {
            return new DecryptionMaterials(this);
        }
    }
}
