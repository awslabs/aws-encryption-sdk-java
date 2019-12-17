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

import com.amazonaws.encryptionsdk.EncryptedDataKey;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.CannotUnwrapDataKeyException;
import com.amazonaws.encryptionsdk.exception.MalformedArnException;
import com.amazonaws.encryptionsdk.kms.DataKeyEncryptionDao;
import com.amazonaws.encryptionsdk.kms.DataKeyEncryptionDao.DecryptDataKeyResult;
import com.amazonaws.encryptionsdk.kms.DataKeyEncryptionDao.GenerateDataKeyResult;
import com.amazonaws.encryptionsdk.kms.KmsUtils;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static com.amazonaws.encryptionsdk.EncryptedDataKey.PROVIDER_ENCODING;
import static com.amazonaws.encryptionsdk.kms.KmsUtils.KMS_PROVIDER_ID;
import static com.amazonaws.encryptionsdk.kms.KmsUtils.isArnWellFormed;
import static java.util.Collections.emptyList;
import static java.util.Collections.unmodifiableList;
import static java.util.Objects.requireNonNull;

/**
 * A keyring which interacts with AWS Key Management Service (KMS) to create,
 * encrypt, and decrypt data keys using KMS defined Customer Master Keys (CMKs).
 */
class KmsKeyring implements Keyring {

    private final DataKeyEncryptionDao dataKeyEncryptionDao;
    private final List<String> keyIds;
    private final String generatorKeyId;
    private final boolean isDiscovery;

    KmsKeyring(DataKeyEncryptionDao dataKeyEncryptionDao, List<String> keyIds, String generatorKeyId) {
        requireNonNull(dataKeyEncryptionDao, "dataKeyEncryptionDao is required");
        this.dataKeyEncryptionDao = dataKeyEncryptionDao;
        this.keyIds = keyIds == null ? emptyList() : unmodifiableList(new ArrayList<>(keyIds));
        this.generatorKeyId = generatorKeyId;
        this.isDiscovery = this.generatorKeyId == null && this.keyIds.isEmpty();

        if (!this.keyIds.stream().allMatch(KmsUtils::isArnWellFormed)) {
            throw new MalformedArnException("keyIds must contain only CMK aliases and well formed ARNs");
        }

        if (generatorKeyId != null) {
            if (!isArnWellFormed(generatorKeyId)) {
                throw new MalformedArnException("generatorKeyId must be either a CMK alias or a well formed ARN");
            }
            if (this.keyIds.contains(generatorKeyId)) {
                throw new IllegalArgumentException("KeyIds should not contain the generatorKeyId");
            }
        }
    }

    @Override
    public void onEncrypt(EncryptionMaterials encryptionMaterials) {
        requireNonNull(encryptionMaterials, "encryptionMaterials are required");

        // If this keyring is a discovery keyring, OnEncrypt MUST return the input encryption materials unmodified.
        if (isDiscovery) {
            return;
        }

        // If the input encryption materials do not contain a plaintext data key and this keyring does not
        // have a generator defined, OnEncrypt MUST not modify the encryption materials and MUST fail.
        if (!encryptionMaterials.hasPlaintextDataKey() && generatorKeyId == null) {
            throw new AwsCryptoException("Encryption materials must contain either a plaintext data key or a generator");
        }

        final List<String> keyIdsToEncrypt = new ArrayList<>(keyIds);

        // If the input encryption materials do not contain a plaintext data key and a generator is defined onEncrypt
        // MUST attempt to generate a new plaintext data key and encrypt that data key by calling KMS GenerateDataKey.
        if (!encryptionMaterials.hasPlaintextDataKey()) {
            generateDataKey(encryptionMaterials);
        } else if (generatorKeyId != null) {
            // If this keyring's generator is defined and was not used to generate a data key, OnEncrypt
            // MUST also attempt to encrypt the plaintext data key using the CMK specified by the generator.
            keyIdsToEncrypt.add(generatorKeyId);
        }

        // Given a plaintext data key in the encryption materials, OnEncrypt MUST attempt
        // to encrypt the plaintext data key using each CMK specified in it's key IDs list.
        for (String keyId : keyIdsToEncrypt) {
            encryptDataKey(keyId, encryptionMaterials);
        }
    }

    private void generateDataKey(final EncryptionMaterials encryptionMaterials) {
        final GenerateDataKeyResult result = dataKeyEncryptionDao.generateDataKey(generatorKeyId,
                encryptionMaterials.getAlgorithmSuite(), encryptionMaterials.getEncryptionContext());

        encryptionMaterials.setPlaintextDataKey(result.getPlaintextDataKey(),
                new KeyringTraceEntry(KMS_PROVIDER_ID, generatorKeyId, KeyringTraceFlag.GENERATED_DATA_KEY));
        encryptionMaterials.addEncryptedDataKey(result.getEncryptedDataKey(),
                new KeyringTraceEntry(KMS_PROVIDER_ID, generatorKeyId, KeyringTraceFlag.ENCRYPTED_DATA_KEY, KeyringTraceFlag.SIGNED_ENCRYPTION_CONTEXT));
    }

    private void encryptDataKey(final String keyId, final EncryptionMaterials encryptionMaterials) {
        final EncryptedDataKey encryptedDataKey = dataKeyEncryptionDao.encryptDataKey(keyId,
                encryptionMaterials.getPlaintextDataKey(), encryptionMaterials.getEncryptionContext());

        encryptionMaterials.addEncryptedDataKey(encryptedDataKey,
                new KeyringTraceEntry(KMS_PROVIDER_ID, keyId, KeyringTraceFlag.ENCRYPTED_DATA_KEY, KeyringTraceFlag.SIGNED_ENCRYPTION_CONTEXT));
    }

    @Override
    public void onDecrypt(DecryptionMaterials decryptionMaterials, List<? extends EncryptedDataKey> encryptedDataKeys) {
        requireNonNull(decryptionMaterials, "decryptionMaterials are required");
        requireNonNull(encryptedDataKeys, "encryptedDataKeys are required");

        if (decryptionMaterials.hasPlaintextDataKey() || encryptedDataKeys.isEmpty()) {
            return;
        }

        final Set<String> configuredKeyIds = new HashSet<>(keyIds);

        if (generatorKeyId != null) {
            configuredKeyIds.add(generatorKeyId);
        }

        for (EncryptedDataKey encryptedDataKey : encryptedDataKeys) {
            if (okToDecrypt(encryptedDataKey, configuredKeyIds)) {
                try {
                    final DecryptDataKeyResult result = dataKeyEncryptionDao.decryptDataKey(encryptedDataKey,
                            decryptionMaterials.getAlgorithmSuite(), decryptionMaterials.getEncryptionContext());

                    decryptionMaterials.setPlaintextDataKey(result.getPlaintextDataKey(),
                            new KeyringTraceEntry(KMS_PROVIDER_ID, result.getKeyArn(),
                                    KeyringTraceFlag.DECRYPTED_DATA_KEY, KeyringTraceFlag.VERIFIED_ENCRYPTION_CONTEXT));
                    return;
                } catch (CannotUnwrapDataKeyException e) {
                    continue;
                }
            }
        }
    }

    private boolean okToDecrypt(EncryptedDataKey encryptedDataKey, Set<String> configuredKeyIds) {
        // Only attempt to decrypt keys provided by KMS
        if (!encryptedDataKey.getProviderId().equals(KMS_PROVIDER_ID)) {
            return false;
        }

        // If the key ARN cannot be parsed, skip it
        if(!isArnWellFormed(new String(encryptedDataKey.getProviderInformation(), PROVIDER_ENCODING)))
        {
            return false;
        }

        // If this keyring is a discovery keyring, OnDecrypt MUST attempt to
        // decrypt every encrypted data key in the input encrypted data key list
        if (isDiscovery) {
            return true;
        }

        // OnDecrypt MUST attempt to decrypt each input encrypted data key in the input
        // encrypted data key list where the key provider info has a value equal to one
        // of the ARNs in this keyring's key IDs or the generator
        return configuredKeyIds.contains(new String(encryptedDataKey.getProviderInformation(), PROVIDER_ENCODING));
    }
}
