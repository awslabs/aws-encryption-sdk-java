// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk.keyrings;

import com.amazonaws.encryptionsdk.EncryptedDataKey;
import com.amazonaws.encryptionsdk.kms.AwsKmsCmkId;
import com.amazonaws.encryptionsdk.kms.DataKeyEncryptionDao;
import com.amazonaws.encryptionsdk.model.DecryptionMaterials;
import com.amazonaws.encryptionsdk.model.EncryptionMaterials;
import com.amazonaws.encryptionsdk.model.KeyBlob;

import java.util.List;

import static com.amazonaws.encryptionsdk.EncryptedDataKey.PROVIDER_ENCODING;
import static com.amazonaws.encryptionsdk.internal.Constants.AWS_KMS_PROVIDER_ID;
import static java.util.Objects.requireNonNull;

/**
 * A keyring which interacts with AWS Key Management Service (KMS) to create,
 * encrypt, and decrypt data keys using an AWS KMS defined Customer Master Key (CMK).
 */
public class AwsKmsSymmetricKeyring implements Keyring {

    private final DataKeyEncryptionDao dataKeyEncryptionDao;
    private final AwsKmsCmkId keyName;

    AwsKmsSymmetricKeyring(DataKeyEncryptionDao dataKeyEncryptionDao, AwsKmsCmkId keyName) {
        requireNonNull(dataKeyEncryptionDao, "dataKeyEncryptionDao is required");
        requireNonNull(keyName, "keyName is required");

        this.dataKeyEncryptionDao = dataKeyEncryptionDao;
        this.keyName = keyName;
    }

    @Override
    public EncryptionMaterials onEncrypt(EncryptionMaterials encryptionMaterials) {
        requireNonNull(encryptionMaterials, "encryptionMaterials are required");

        EncryptionMaterials resultMaterials = encryptionMaterials;

        // If the input encryption materials do not contain a plaintext data key,
        // onEncrypt MUST attempt to generate a new plaintext data key
        // and encrypt that data key by calling KMS GenerateDataKey.
        if (!encryptionMaterials.hasCleartextDataKey()) {
            return generateDataKey(encryptionMaterials);
        }

        // Given a plaintext data key in the encryption materials, OnEncrypt MUST attempt
        // to encrypt the plaintext data key using the provided key name
        resultMaterials = encryptDataKey(resultMaterials);
        return resultMaterials;
    }

    private EncryptionMaterials generateDataKey(final EncryptionMaterials encryptionMaterials) {
        final DataKeyEncryptionDao.GenerateDataKeyResult result = this.dataKeyEncryptionDao.generateDataKey(
            this.keyName, encryptionMaterials.getAlgorithm(), encryptionMaterials.getEncryptionContext());
        return encryptionMaterials
            .withCleartextDataKey(result.getPlaintextDataKey())
            .withEncryptedDataKey(new KeyBlob(result.getEncryptedDataKey()));
    }

    private EncryptionMaterials encryptDataKey(final EncryptionMaterials encryptionMaterials) {
        final EncryptedDataKey encryptedDataKey = this.dataKeyEncryptionDao.encryptDataKey(
            this.keyName, encryptionMaterials.getCleartextDataKey(), encryptionMaterials.getEncryptionContext());
        return encryptionMaterials.withEncryptedDataKey(new KeyBlob(encryptedDataKey));
    }

    @Override
    public DecryptionMaterials onDecrypt(DecryptionMaterials decryptionMaterials, List<? extends EncryptedDataKey> encryptedDataKeys) {
        requireNonNull(decryptionMaterials, "decryptionMaterials are required");
        requireNonNull(encryptedDataKeys, "encryptedDataKeys are required");

        if (decryptionMaterials.hasCleartextDataKey() || encryptedDataKeys.isEmpty()) {
            return decryptionMaterials;
        }

        for (EncryptedDataKey encryptedDataKey : encryptedDataKeys) {
            if (okToDecrypt(encryptedDataKey)) {
                final DataKeyEncryptionDao.DecryptDataKeyResult result = this.dataKeyEncryptionDao.decryptDataKey(
                    encryptedDataKey, decryptionMaterials.getAlgorithm(), decryptionMaterials.getEncryptionContext());
                return decryptionMaterials.withCleartextDataKey(result.getPlaintextDataKey());
            }
        }

        return decryptionMaterials;
    }

    private boolean okToDecrypt(EncryptedDataKey encryptedDataKey) {
        // Only attempt to decrypt keys provided by KMS
        if (encryptedDataKey == null || !encryptedDataKey.getProviderId().equals(AWS_KMS_PROVIDER_ID)) {
            return false;
        }

        // If the key name cannot be parsed, skip it
        final String edkKeyName = new String(encryptedDataKey.getProviderInformation(), PROVIDER_ENCODING);
        if (!AwsKmsCmkId.isKeyIdWellFormed(edkKeyName)) {
            return false;
        }

        // OnDecrypt MUST attempt to decrypt each input encrypted data key in the input encrypted data key list
        // where the key provider info has a value equal to the keyring's key name
        return this.keyName.equals(AwsKmsCmkId.fromString(edkKeyName));
    }
}
