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
import com.amazonaws.encryptionsdk.kms.AwsKmsCmkId;
import com.amazonaws.encryptionsdk.kms.DataKeyEncryptionDao;
import com.amazonaws.encryptionsdk.kms.DataKeyEncryptionDao.DecryptDataKeyResult;
import com.amazonaws.encryptionsdk.kms.DataKeyEncryptionDao.GenerateDataKeyResult;
import com.amazonaws.encryptionsdk.model.DecryptionMaterials;
import com.amazonaws.encryptionsdk.model.EncryptionMaterials;
import com.amazonaws.encryptionsdk.model.KeyBlob;
import org.apache.commons.lang3.Validate;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static com.amazonaws.encryptionsdk.EncryptedDataKey.PROVIDER_ENCODING;
import static com.amazonaws.encryptionsdk.internal.Constants.AWS_KMS_PROVIDER_ID;
import static com.amazonaws.encryptionsdk.kms.AwsKmsCmkId.isKeyIdWellFormed;
import static java.util.Collections.emptyList;
import static java.util.Collections.unmodifiableList;
import static java.util.Objects.requireNonNull;

/**
 * A keyring which interacts with AWS Key Management Service (KMS) to create,
 * encrypt, and decrypt data keys using AWS KMS defined Customer Master Keys (CMKs).
 */
class AwsKmsKeyring implements Keyring {

    private final DataKeyEncryptionDao dataKeyEncryptionDao;
    private final List<AwsKmsCmkId> keyIds;
    private final AwsKmsCmkId generatorKeyId;
    private final boolean isDiscovery;

    AwsKmsKeyring(DataKeyEncryptionDao dataKeyEncryptionDao, List<AwsKmsCmkId> keyIds, AwsKmsCmkId generatorKeyId, boolean isDiscovery) {
        requireNonNull(dataKeyEncryptionDao, "dataKeyEncryptionDao is required");
        this.dataKeyEncryptionDao = dataKeyEncryptionDao;
        this.keyIds = keyIds == null ? emptyList() : unmodifiableList(new ArrayList<>(keyIds));
        this.generatorKeyId = generatorKeyId;
        this.isDiscovery = isDiscovery;

        if(isDiscovery) {
            Validate.isTrue(generatorKeyId == null && this.keyIds.isEmpty(),
                    "AWS KMS Discovery keyrings cannot specify any key IDs");
        } else {
            Validate.isTrue(generatorKeyId != null || !this.keyIds.isEmpty(),
                    "GeneratorKeyId or KeyIds are required for non-discovery AWS KMS Keyrings.");
        }

        if (this.keyIds.contains(generatorKeyId)) {
            throw new IllegalArgumentException("KeyIds should not contain the generatorKeyId");
        }
    }

    @Override
    public EncryptionMaterials onEncrypt(EncryptionMaterials encryptionMaterials) {
        requireNonNull(encryptionMaterials, "encryptionMaterials are required");

        // If this keyring is a discovery keyring, OnEncrypt MUST return the input encryption materials unmodified.
        if (isDiscovery) {
            return encryptionMaterials;
        }

        EncryptionMaterials resultMaterials = encryptionMaterials;

        // If the input encryption materials do not contain a plaintext data key and this keyring does not
        // have a generator defined, OnEncrypt MUST not modify the encryption materials and MUST fail.
        if (!encryptionMaterials.hasCleartextDataKey() && generatorKeyId == null) {
            throw new AwsCryptoException("Encryption materials must contain either a plaintext data key or a generator");
        }

        final List<AwsKmsCmkId> keyIdsToEncrypt = new ArrayList<>(keyIds);

        // If the input encryption materials do not contain a plaintext data key and a generator is defined onEncrypt
        // MUST attempt to generate a new plaintext data key and encrypt that data key by calling KMS GenerateDataKey.
        if (!encryptionMaterials.hasCleartextDataKey()) {
            resultMaterials = generateDataKey(encryptionMaterials);
        } else if (generatorKeyId != null) {
            // If this keyring's generator is defined and was not used to generate a data key, OnEncrypt
            // MUST also attempt to encrypt the plaintext data key using the CMK specified by the generator.
            keyIdsToEncrypt.add(generatorKeyId);
        }

        // Given a plaintext data key in the encryption materials, OnEncrypt MUST attempt
        // to encrypt the plaintext data key using each CMK specified in it's key IDs list.
        for (AwsKmsCmkId keyId : keyIdsToEncrypt) {
            resultMaterials = encryptDataKey(keyId, resultMaterials);
        }

        return resultMaterials;
    }

    private EncryptionMaterials generateDataKey(final EncryptionMaterials encryptionMaterials) {
        final GenerateDataKeyResult result = dataKeyEncryptionDao.generateDataKey(generatorKeyId,
                encryptionMaterials.getAlgorithm(), encryptionMaterials.getEncryptionContext());

        return encryptionMaterials
                .withCleartextDataKey(result.getPlaintextDataKey())
                .withEncryptedDataKey(new KeyBlob(result.getEncryptedDataKey()));
    }

    private EncryptionMaterials encryptDataKey(final AwsKmsCmkId keyId, final EncryptionMaterials encryptionMaterials) {
        final EncryptedDataKey encryptedDataKey = dataKeyEncryptionDao.encryptDataKey(keyId,
                encryptionMaterials.getCleartextDataKey(), encryptionMaterials.getEncryptionContext());

        return encryptionMaterials.withEncryptedDataKey(new KeyBlob(encryptedDataKey));
    }

    @Override
    public DecryptionMaterials onDecrypt(DecryptionMaterials decryptionMaterials, List<? extends EncryptedDataKey> encryptedDataKeys) {
        requireNonNull(decryptionMaterials, "decryptionMaterials are required");
        requireNonNull(encryptedDataKeys, "encryptedDataKeys are required");

        if (decryptionMaterials.hasCleartextDataKey() || encryptedDataKeys.isEmpty()) {
            return decryptionMaterials;
        }

        final Set<AwsKmsCmkId> configuredKeyIds = new HashSet<>(keyIds);

        if (generatorKeyId != null) {
            configuredKeyIds.add(generatorKeyId);
        }

        for (EncryptedDataKey encryptedDataKey : encryptedDataKeys) {
            if (okToDecrypt(encryptedDataKey, configuredKeyIds)) {
                try {
                    final DecryptDataKeyResult result = dataKeyEncryptionDao.decryptDataKey(encryptedDataKey,
                            decryptionMaterials.getAlgorithm(), decryptionMaterials.getEncryptionContext());

                    return decryptionMaterials.withCleartextDataKey(result.getPlaintextDataKey());
                } catch (CannotUnwrapDataKeyException e) {
                    continue;
                }
            }
        }

        return decryptionMaterials;
    }

    private boolean okToDecrypt(EncryptedDataKey encryptedDataKey, Set<AwsKmsCmkId> configuredKeyIds) {
        // Only attempt to decrypt keys provided by KMS
        if (!encryptedDataKey.getProviderId().equals(AWS_KMS_PROVIDER_ID)) {
            return false;
        }

        // If the key ID cannot be parsed, skip it
        if(!isKeyIdWellFormed(new String(encryptedDataKey.getProviderInformation(), PROVIDER_ENCODING)))
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
        return configuredKeyIds.contains(
                AwsKmsCmkId.fromString(new String(encryptedDataKey.getProviderInformation(), PROVIDER_ENCODING)));
    }
}
