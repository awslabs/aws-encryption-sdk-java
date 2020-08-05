package com.amazonaws.encryptionsdk;

import static com.amazonaws.encryptionsdk.AwsCrypto.getDefaultCryptoAlgorithm;
import static java.util.Objects.requireNonNull;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.CannotUnwrapDataKeyException;
import com.amazonaws.encryptionsdk.internal.Constants;
import com.amazonaws.encryptionsdk.internal.TrailingSignatureAlgorithm;
import com.amazonaws.encryptionsdk.keyrings.Keyring;
import com.amazonaws.encryptionsdk.model.DecryptionMaterials;
import com.amazonaws.encryptionsdk.model.DecryptionMaterialsRequest;
import com.amazonaws.encryptionsdk.model.EncryptionMaterials;
import com.amazonaws.encryptionsdk.model.EncryptionMaterialsRequest;
import com.amazonaws.encryptionsdk.model.KeyBlob;

/**
 * The default implementation of {@link CryptoMaterialsManager}, used implicitly when passing a
 * {@link MasterKeyProvider} or {@link Keyring} to methods in {@link AwsCrypto}.
 *
 * This default implementation delegates to a specific {@link MasterKeyProvider} or {@link Keyring} specified at
 * construction time. It also handles generating trailing signature keys when needed, placing them in the
 * encryption context (and extracting them at decrypt time).
 */
public class DefaultCryptoMaterialsManager implements CryptoMaterialsManager {
    // Exactly one of keyring or mkp should be null
    private final Keyring keyring;
    private final MasterKeyProvider<?> mkp;

    /**
     * @param masterKeyProvider The master key provider to delegate to
     *
     * @deprecated Replaced by {@link #DefaultCryptoMaterialsManager(Keyring)}
     */
    @Deprecated
    public DefaultCryptoMaterialsManager(MasterKeyProvider<?> masterKeyProvider) {
        requireNonNull(masterKeyProvider, "masterKeyProvider is required");
        this.mkp = masterKeyProvider;
        this.keyring = null;
    }

    /**
     * @param keyring The keyring to delegate to
     */
    public DefaultCryptoMaterialsManager(Keyring keyring) {
        requireNonNull(keyring, "keyring is required");
        this.keyring = keyring;
        this.mkp = null;
    }

    @Override
    public EncryptionMaterials getMaterialsForEncrypt(EncryptionMaterialsRequest request) {
        if(keyring != null) {
            return getEncryptionMaterialsForKeyring(request);
        }

        return getEncryptionMaterialsForMasterKeyProvider(request);
    }

    @Override
    public DecryptionMaterials decryptMaterials(DecryptionMaterialsRequest request) {
       if(keyring != null) {
           return getDecryptionMaterialsForKeyring(request);
        }

        return getDecryptionMaterialsForMasterKeyProvider(request);
    }

    private EncryptionMaterials getEncryptionMaterialsForKeyring(EncryptionMaterialsRequest request) {
        final CryptoAlgorithm algorithmSuite = request.getRequestedAlgorithm() != null ?
                request.getRequestedAlgorithm() : getDefaultCryptoAlgorithm();
        final Map<String, String> encryptionContext = new HashMap<>(request.getContext());
        final PrivateKey signingKey = getSigningKey(algorithmSuite, encryptionContext);

        final EncryptionMaterials encryptionMaterials =
                EncryptionMaterials.newBuilder()
                        .setAlgorithm(algorithmSuite)
                        .setEncryptionContext(encryptionContext)
                        .setTrailingSignatureKey(signingKey)
                        .build();

        return keyring.onEncrypt(encryptionMaterials);
    }

    private EncryptionMaterials getEncryptionMaterialsForMasterKeyProvider(EncryptionMaterialsRequest request) {
        final Map<String, String> encryptionContext = new HashMap<>(request.getContext());
        final CryptoAlgorithm algorithmSuite = request.getRequestedAlgorithm() != null ?
                request.getRequestedAlgorithm() : getDefaultCryptoAlgorithm();
        final PrivateKey trailingSignatureKey = getSigningKey(algorithmSuite, encryptionContext);

        final MasterKeyRequest.Builder mkRequestBuilder = MasterKeyRequest.newBuilder()
                .setEncryptionContext(encryptionContext)
                .setStreaming(request.getPlaintextSize() == -1);
        if (request.getPlaintext() != null) {
            mkRequestBuilder.setPlaintext(request.getPlaintext());
        } else {
            mkRequestBuilder.setSize(request.getPlaintextSize());
        }

        @SuppressWarnings("unchecked")
        final List<MasterKey> masterKeys = (List<MasterKey>) mkp.getMasterKeysForEncryption(mkRequestBuilder.build());

        if (masterKeys.isEmpty()) {
            throw new IllegalArgumentException("No master keys provided");
        }

        final DataKey<?> dataKey = masterKeys.get(0).generateDataKey(algorithmSuite, encryptionContext);

        final List<KeyBlob> keyBlobs = new ArrayList<>(masterKeys.size());
        keyBlobs.add(new KeyBlob(dataKey));

        for (int i = 1; i < masterKeys.size(); i++) {
            //noinspection unchecked
            keyBlobs.add(new KeyBlob(masterKeys.get(i).encryptDataKey(algorithmSuite, encryptionContext, dataKey)));
        }

        return EncryptionMaterials.newBuilder()
                .setAlgorithm(algorithmSuite)
                .setCleartextDataKey(dataKey.getKey())
                .setEncryptedDataKeys(keyBlobs)
                .setEncryptionContext(encryptionContext)
                .setTrailingSignatureKey(trailingSignatureKey)
                .setMasterKeys(masterKeys)
                .build();
    }

    private DecryptionMaterials getDecryptionMaterialsForKeyring(DecryptionMaterialsRequest request) {
        final PublicKey verificationKey = getVerificationKey(request);

        final DecryptionMaterials decryptionMaterials =
                DecryptionMaterials.newBuilder()
                        .setAlgorithm(request.getAlgorithm())
                        .setEncryptionContext(request.getEncryptionContext())
                        .setTrailingSignatureKey(verificationKey)
                        .build();

        final DecryptionMaterials result = keyring.onDecrypt(decryptionMaterials, request.getEncryptedDataKeys());

        if(!result.hasCleartextDataKey()) {
            throw new CannotUnwrapDataKeyException("Could not decrypt any data keys");
        }

        return result;
    }

    private DecryptionMaterials getDecryptionMaterialsForMasterKeyProvider(DecryptionMaterialsRequest request) {
        final DataKey<?> dataKey = mkp.decryptDataKey(
                request.getAlgorithm(),
                request.getEncryptedDataKeys(),
                request.getEncryptionContext());

        if (dataKey == null) {
            throw new CannotUnwrapDataKeyException("Could not decrypt any data keys");
        }

        return DecryptionMaterials.newBuilder()
                .setDataKey(dataKey)
                .setTrailingSignatureKey(getVerificationKey(request))
                .build();
    }

    private PrivateKey getSigningKey(CryptoAlgorithm algorithmSuite, Map<String, String> encryptionContext) {
        if (algorithmSuite.getTrailingSignatureLength() > 0) {
            try {
                final KeyPair trailingKeys = generateTrailingSigKeyPair(algorithmSuite);
                if (encryptionContext.containsKey(Constants.EC_PUBLIC_KEY_FIELD)) {
                    throw new IllegalArgumentException("EncryptionContext contains reserved field "
                            + Constants.EC_PUBLIC_KEY_FIELD);
                }
                encryptionContext.put(Constants.EC_PUBLIC_KEY_FIELD, serializeTrailingKeyForEc(algorithmSuite, trailingKeys));
                return trailingKeys.getPrivate();
            } catch (final GeneralSecurityException ex) {
                throw new AwsCryptoException(ex);
            }
        }

        return null;
    }

    private PublicKey getVerificationKey(DecryptionMaterialsRequest request) {
        if (request.getAlgorithm().getTrailingSignatureLength() > 0) {
            try {
                final String serializedPubKey = request.getEncryptionContext().get(Constants.EC_PUBLIC_KEY_FIELD);

                if (serializedPubKey == null) {
                    throw new AwsCryptoException("Missing trailing signature public key");
                }

                return TrailingSignatureAlgorithm.forCryptoAlgorithm(
                        request.getAlgorithm()).deserializePublicKey(serializedPubKey);
            } catch (final IllegalStateException ex) {
                throw new AwsCryptoException(ex);
            }
        }

        return null;
    }

    private static String serializeTrailingKeyForEc(CryptoAlgorithm algo, KeyPair trailingKeys) {
        return TrailingSignatureAlgorithm.forCryptoAlgorithm(algo).serializePublicKey(trailingKeys.getPublic());
    }

    private static KeyPair generateTrailingSigKeyPair(CryptoAlgorithm algo) throws GeneralSecurityException {
        return TrailingSignatureAlgorithm.forCryptoAlgorithm(algo).generateKey();
    }
}
