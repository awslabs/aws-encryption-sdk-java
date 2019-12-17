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

import com.amazonaws.encryptionsdk.DataKey;
import com.amazonaws.encryptionsdk.EncryptedDataKey;
import com.amazonaws.encryptionsdk.MasterKey;
import com.amazonaws.encryptionsdk.MasterKeyProvider;
import com.amazonaws.encryptionsdk.MasterKeyRequest;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.CannotUnwrapDataKeyException;
import com.amazonaws.encryptionsdk.jce.JceMasterKey;
import com.amazonaws.encryptionsdk.kms.KmsMasterKey;

import java.util.ArrayList;
import java.util.List;

import static com.amazonaws.encryptionsdk.keyrings.KeyringTraceFlag.DECRYPTED_DATA_KEY;
import static com.amazonaws.encryptionsdk.keyrings.KeyringTraceFlag.ENCRYPTED_DATA_KEY;
import static com.amazonaws.encryptionsdk.keyrings.KeyringTraceFlag.SIGNED_ENCRYPTION_CONTEXT;
import static com.amazonaws.encryptionsdk.keyrings.KeyringTraceFlag.VERIFIED_ENCRYPTION_CONTEXT;
import static java.util.Objects.requireNonNull;
import static org.apache.commons.lang3.ArrayUtils.EMPTY_BYTE_ARRAY;

/**
 * A keyring which wraps a legacy MasterKeyProvider to
 * facilitate transition to keyrings.
 */
class MasterKeyProviderKeyring<K extends MasterKey<K>> implements Keyring {

    private final MasterKeyProvider<K> masterKeyProvider;

    MasterKeyProviderKeyring(MasterKeyProvider<K> masterKeyProvider) {
        requireNonNull(masterKeyProvider, "masterKeyProvider is required");

        this.masterKeyProvider = masterKeyProvider;
    }

    @Override
    public void onEncrypt(EncryptionMaterials encryptionMaterials) {
        requireNonNull(encryptionMaterials, "encryptionMaterials are required");

        final List<K> masterKeys = masterKeyProvider.getMasterKeysForEncryption(MasterKeyRequest.newBuilder()
                .setEncryptionContext(encryptionMaterials.getEncryptionContext()).build());

        if (masterKeys == null || masterKeys.isEmpty()) {
            throw new AwsCryptoException("No master keys available from the master key provider.");
        }

        final K primaryMasterKey = masterKeys.get(0);
        final List<K> masterKeysToEncryptWith = new ArrayList<>(masterKeys);

        if (!encryptionMaterials.hasPlaintextDataKey()) {
            final DataKey<K> dataKey = primaryMasterKey.generateDataKey(
                    encryptionMaterials.getAlgorithmSuite(), encryptionMaterials.getEncryptionContext());
            encryptionMaterials.setPlaintextDataKey(dataKey.getKey(), new KeyringTraceEntry(
                    primaryMasterKey.getProviderId(), primaryMasterKey.getKeyId(), KeyringTraceFlag.GENERATED_DATA_KEY));
            encryptionMaterials.addEncryptedDataKey(dataKey, encryptTraceEntry(primaryMasterKey));
            // The primary master key has already been used for encryption, so remove it from the list to encrypt with
            masterKeysToEncryptWith.remove(primaryMasterKey);
        }

        final DataKey<K> dataKey = new DataKey<>(encryptionMaterials.getPlaintextDataKey(), EMPTY_BYTE_ARRAY,
                EMPTY_BYTE_ARRAY, primaryMasterKey);

        for (K masterKey : masterKeysToEncryptWith) {
            final EncryptedDataKey encryptedDataKey = masterKey.encryptDataKey(encryptionMaterials.getAlgorithmSuite(),
                    encryptionMaterials.getEncryptionContext(), dataKey);
            encryptionMaterials.addEncryptedDataKey(encryptedDataKey, encryptTraceEntry(masterKey));
        }
    }

    @Override
    public void onDecrypt(DecryptionMaterials decryptionMaterials, List<? extends EncryptedDataKey> encryptedDataKeys) {
        requireNonNull(decryptionMaterials, "decryptionMaterials are required");
        requireNonNull(encryptedDataKeys, "encryptedDataKeys are required");

        if (decryptionMaterials.hasPlaintextDataKey()) {
            return;
        }

        final DataKey<K> dataKey;
        try {
            dataKey = masterKeyProvider.decryptDataKey(decryptionMaterials.getAlgorithmSuite(), encryptedDataKeys,
                    decryptionMaterials.getEncryptionContext());
        } catch (CannotUnwrapDataKeyException e) {
            return;
        }

        decryptionMaterials.setPlaintextDataKey(dataKey.getKey(), decryptTraceEntry(dataKey.getMasterKey()));
    }

    private boolean signedEncryptionContext(MasterKey<K> masterKey) {
        if (masterKey instanceof KmsMasterKey) {
            return true;
        }

        if (masterKey instanceof JceMasterKey) {
            return ((JceMasterKey) masterKey).isEncryptionContextSigned();
        }

        return false;
    }

    private KeyringTraceEntry encryptTraceEntry(MasterKey<K> masterKey) {
        final List<KeyringTraceFlag> flags = new ArrayList<>();
        flags.add(ENCRYPTED_DATA_KEY);

        if (signedEncryptionContext(masterKey)) {
            flags.add(SIGNED_ENCRYPTION_CONTEXT);
        }

        return new KeyringTraceEntry(masterKey.getProviderId(), masterKey.getKeyId(), flags.toArray(new KeyringTraceFlag[]{}));
    }

    private KeyringTraceEntry decryptTraceEntry(MasterKey<K> masterKey) {
        final List<KeyringTraceFlag> flags = new ArrayList<>();
        flags.add(DECRYPTED_DATA_KEY);

        if (signedEncryptionContext(masterKey)) {
            flags.add(VERIFIED_ENCRYPTION_CONTEXT);
        }

        return new KeyringTraceEntry(masterKey.getProviderId(), masterKey.getKeyId(), flags.toArray(new KeyringTraceFlag[]{}));
    }
}
