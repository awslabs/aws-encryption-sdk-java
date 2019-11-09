package com.amazonaws.encryptionsdk.model;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.MasterKey;
import com.amazonaws.encryptionsdk.keyrings.KeyringTrace;

/**
 * Contains the cryptographic materials needed for an encryption operation.
 *
 * @see com.amazonaws.encryptionsdk.CryptoMaterialsManager#getMaterialsForEncrypt(EncryptionMaterialsRequest)
 */
public final class EncryptionMaterials {
    private final CryptoAlgorithm algorithm;
    private final Map<String, String> encryptionContext;
    private final List<KeyBlob> encryptedDataKeys;
    private SecretKey cleartextDataKey;
    private final PrivateKey trailingSignatureKey;
    private final List<MasterKey> masterKeys;
    private final KeyringTrace keyringTrace;

    private EncryptionMaterials(Builder b) {
        this.algorithm = b.algorithm;
        this.encryptionContext = b.encryptionContext;
        this.encryptedDataKeys = b.encryptedDataKeys;
        this.cleartextDataKey = b.cleartextDataKey;
        this.trailingSignatureKey = b.trailingSignatureKey;
        this.masterKeys = b.getMasterKeys();
        this.keyringTrace = b.keyringTrace;
    }

    public Builder toBuilder() {
        return new Builder(this);
    }

    public static Builder newBuilder() {
        return new Builder();
    }

    /**
     * The algorithm to use for this encryption operation. Must match the algorithm in EncryptionMaterialsRequest, if that
     * algorithm was non-null.
     */
    public CryptoAlgorithm getAlgorithm() {
        return algorithm;
    }

    /**
     * The encryption context to use for the encryption operation. Does not need to match the EncryptionMaterialsRequest.
     */
    public Map<String, String> getEncryptionContext() {
        return encryptionContext;
    }

    /**
     * The KeyBlobs to serialize (in cleartext) into the encrypted message.
     */
    public List<KeyBlob> getEncryptedDataKeys() {
        return encryptedDataKeys;
    }

    /**
     * The cleartext data key to use for encrypting this message. Note that this is the data key prior to
     * any key derivation required by the crypto algorithm in use.
     */
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
     * The private key to be used to sign the message trailer. Must be present if any only if required by the
     * crypto algorithm, and the key type must likewise match the algorithm in use.
     *
     * Note that it's the {@link com.amazonaws.encryptionsdk.CryptoMaterialsManager}'s responsibility to find a place
     * to put the public key; typically, this will be in the encryption context, to improve cross-compatibility,
     * but this is not a strict requirement.
     */
    public PrivateKey getTrailingSignatureKey() {
        return trailingSignatureKey;
    }

    public KeyringTrace getKeyringTrace() {
        return keyringTrace;
    }

    /**
     * Contains a list of all MasterKeys that could decrypt this message.
     */
    public List<MasterKey> getMasterKeys() {
        return masterKeys;
    }

    @Override public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EncryptionMaterials that = (EncryptionMaterials) o;
        return algorithm == that.algorithm &&
                Objects.equals(encryptionContext, that.encryptionContext) &&
                Objects.equals(encryptedDataKeys, that.encryptedDataKeys) &&
                Objects.equals(cleartextDataKey, that.cleartextDataKey) &&
                Objects.equals(trailingSignatureKey, that.trailingSignatureKey) &&
                Objects.equals(masterKeys, that.masterKeys) &&
                Objects.equals(keyringTrace, that.keyringTrace);
    }

    @Override public int hashCode() {
        return Objects.hash(algorithm, encryptionContext, encryptedDataKeys, cleartextDataKey, trailingSignatureKey,
                            masterKeys, keyringTrace);
    }

    public static class Builder {
        private CryptoAlgorithm algorithm;
        private Map<String, String> encryptionContext = Collections.emptyMap();
        private List<KeyBlob> encryptedDataKeys = new ArrayList<>();
        private SecretKey cleartextDataKey;
        private PrivateKey trailingSignatureKey;
        private List<MasterKey> masterKeys = Collections.emptyList();
        private KeyringTrace keyringTrace;

        private Builder() {}

        private Builder(EncryptionMaterials r) {
            algorithm = r.algorithm;
            encryptionContext = r.encryptionContext;
            encryptedDataKeys = r.encryptedDataKeys;
            cleartextDataKey = r.cleartextDataKey;
            trailingSignatureKey = r.trailingSignatureKey;
            setMasterKeys(r.masterKeys);
            keyringTrace = r.keyringTrace;
        }

        public EncryptionMaterials build() {
            return new EncryptionMaterials(this);
        }

        public CryptoAlgorithm getAlgorithm() {
            return algorithm;
        }

        public Builder setAlgorithm(CryptoAlgorithm algorithm) {
            this.algorithm = algorithm;
            return this;
        }

        public Map<String, String> getEncryptionContext() {
            return encryptionContext;
        }

        public Builder setEncryptionContext(Map<String, String> encryptionContext) {
            this.encryptionContext = Collections.unmodifiableMap(new HashMap<>(encryptionContext));
            return this;
        }

        public List<KeyBlob> getEncryptedDataKeys() {
            return encryptedDataKeys;
        }

        public Builder setEncryptedDataKeys(List<KeyBlob> encryptedDataKeys) {
            this.encryptedDataKeys = new ArrayList<>(encryptedDataKeys);
            return this;
        }

        public SecretKey getCleartextDataKey() {
            return cleartextDataKey;
        }

        public Builder setCleartextDataKey(SecretKey cleartextDataKey) {
            this.cleartextDataKey = cleartextDataKey;
            return this;
        }

        public PrivateKey getTrailingSignatureKey() {
            return trailingSignatureKey;
        }

        public Builder setTrailingSignatureKey(PrivateKey trailingSignatureKey) {
            this.trailingSignatureKey = trailingSignatureKey;
            return this;
        }

        public List<MasterKey> getMasterKeys() {
            return masterKeys;
        }

        public Builder setMasterKeys(List<MasterKey> masterKeys) {
            this.masterKeys = Collections.unmodifiableList(new ArrayList<>(masterKeys));
            return this;
        }

        public KeyringTrace getKeyringTrace() {
            return keyringTrace;
        }

        public Builder setKeyringTrace(KeyringTrace keyringTrace) {
            this.keyringTrace = keyringTrace;
            return this;
        }
    }
}
