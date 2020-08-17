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

import com.amazonaws.encryptionsdk.kms.AwsKmsCmkId;
import com.amazonaws.encryptionsdk.kms.DataKeyEncryptionDao;

import java.util.Arrays;
import java.util.List;

/**
 * Factory methods for instantiating the standard {@code Keyring}s provided by the AWS Encryption SDK.
 */
public class StandardKeyrings {

    private StandardKeyrings() {
    }

    /**
     * Returns a {@link RawAesKeyringBuilder} for use in constructing a keyring which does local AES-GCM encryption
     * decryption of data keys using a provided wrapping key.
     *
     * @return The {@link RawAesKeyringBuilder}
     */
    public static RawAesKeyringBuilder rawAesBuilder() {
        return RawAesKeyringBuilder.standard();
    }

    /**
     * Constructs a {@code RawRsaKeyringBuilder} which does local RSA encryption and decryption of data keys using the
     * provided public and private keys. If {@code privateKey} is {@code null} then the returned {@code Keyring}
     * can only be used for encryption.
     *
     * @return The {@link RawRsaKeyringBuilder}
     */
    public static RawRsaKeyringBuilder rawRsaBuilder() {
        return RawRsaKeyringBuilder.standard();
    }

    /**
     * Constructs an {@code AwsKmsSymmetricKeyring} which interacts with AWS Key Management Service (KMS) to create,
     * encrypt, and decrypt data keys using the supplied AWS KMS defined Customer Master Key (CMK)
     * and DataKeyEncryptionDao.
     *
     * @param dataKeyEncryptionDao A {@link DataKeyEncryptionDao} used to make calls to AWS KMS.
     * @param keyName              An {@link AwsKmsCmkId} in ARN, CMK Alias, ARN Alias or Key Id format that identifies an
     *                             AWS KMS CMK responsible for generating a data key, as well as encrypting and
     *                             decrypting data keys.
     * @return The {@code Keyring}
     */
    public static Keyring awsKmsSymmetric(DataKeyEncryptionDao dataKeyEncryptionDao, AwsKmsCmkId keyName) {
        return new AwsKmsSymmetricKeyring(dataKeyEncryptionDao, keyName);
    }

    /**
     * Constructs a {@code MultiKeyring} of an {@code AwsKmsSymmetricKeyring},
     * which interacts with AWS Key Management Service (KMS) to create,
     * encrypt, and decrypt data keys using the supplied AWS KMS defined Customer Master Keys (CMKs).
     *
     * @param generatorKeyName An {@link AwsKmsCmkId} in ARN, CMK Alias, ARN Alias or Key Id format that identifies an
     *                         AWS KMS CMK responsible for generating a data key, as well as encrypting and
     *                         decrypting data keys.
     * @return The {@code Keyring}
     */
    public static Keyring awsKmsSymmetricMultiCmk(AwsKmsCmkId generatorKeyName) {
        return AwsKmsSymmetricMultiCmkKeyringBuilder.standard()
            .generator(generatorKeyName)
            .build();
    }

    /**
     * Constructs a {@code MultiKeyring} of {@code AwsKmsSymmetricKeyring}(s),
     * which interacts with AWS Key Management Service (KMS) to create,
     * encrypt, and decrypt data keys using the supplied AWS KMS defined Customer Master Keys (CMKs).
     *
     * @param generatorKeyName An {@link AwsKmsCmkId} in ARN, CMK Alias, ARN Alias or Key Id format that identifies an
     *                         AWS KMS CMK responsible for generating a data key, as well as encrypting and
     *                         decrypting data keys.
     * @param keyNames         A list of {@link AwsKmsCmkId} in ARN, CMK Alias, ARN Alias or Key Id format that identifies
     *                         AWS KMS CMKs responsible for encrypting and decrypting data keys.
     * @return The {@code Keyring}
     */
    public static Keyring awsKmsSymmetricMultiCmk(AwsKmsCmkId generatorKeyName, List<AwsKmsCmkId> keyNames) {
        return AwsKmsSymmetricMultiCmkKeyringBuilder.standard()
            .generator(generatorKeyName)
            .keyNames(keyNames)
            .build();
    }

    /**
     * Construct an {@code AwsKmsSymmetricMultiCmkKeyringBuilder} for use in constructing a keyring which interacts with
     * AWS Key Management Service (KMS) to create, encrypt, and decrypt data keys using AWS KMS defined
     * Customer Master Keys (CMKs).
     *
     * @return The {@code AwsKmsSymmetricMultiCmkKeyringBuilder}
     */
    public static AwsKmsSymmetricMultiCmkKeyringBuilder awsKmsSymmetricMultiCmkBuilder() {
        return AwsKmsSymmetricMultiCmkKeyringBuilder.standard();
    }

    /**
     * Constructs an {@code AwsKmsSymmetricRegionDiscoveryKeyring} which interacts with AWS Key Management Service (KMS)
     * in the specified AWS region using the provided DataKeyEncryptionDao.
     *
     * @param dataKeyEncryptionDao A {@link DataKeyEncryptionDao} used to make calls to AWS KMS.
     * @param regionId             A string representing the AWS region to attempt decryption in.
     * @return The {@code Keyring}
     */
    public static Keyring awsKmsSymmetricRegionDiscovery(DataKeyEncryptionDao dataKeyEncryptionDao, String regionId) {
        return new AwsKmsSymmetricRegionDiscoveryKeyring(dataKeyEncryptionDao, regionId, null);
    }

    /**
     * Constructs an {@code AwsKmsSymmetricRegionDiscoveryKeyring} which interacts with AWS Key Management Service (KMS)
     * in the specified AWS region using the provided DataKeyEncryptionDao.
     * If an {@code awsAccountId} is provided,
     * the {@code AwsKmsSymmetricRegionDiscoveryKeyring} will only attempt to decrypt encrypted data keys
     * associated with that AWS account.
     *
     * @param dataKeyEncryptionDao A {@link DataKeyEncryptionDao} used to make calls to AWS KMS.
     * @param regionId             A string representing the AWS region to attempt decryption in.
     * @param awsAccountId         An optional string representing an AWS account Id.
     * @return The {@code Keyring}
     */
    public static Keyring awsKmsSymmetricRegionDiscovery(DataKeyEncryptionDao dataKeyEncryptionDao, String regionId, String awsAccountId) {
        return new AwsKmsSymmetricRegionDiscoveryKeyring(dataKeyEncryptionDao, regionId, awsAccountId);
    }

    /**
     * Constructs a {@code MultiKeyring} of {@code AwsKmsSymmetricRegionDiscoveryKeyring}(s)
     * which interacts with AWS Key Management Service (KMS) to decrypt data keys
     * in the specified AWS regions.
     *
     * @param regionIds A list of strings representing AWS regions to attempt decryption in.
     * @return The {@code Keyring}
     */
    public static Keyring awsKmsSymmetricMultiRegionDiscovery(List<String> regionIds) {
        return AwsKmsSymmetricMultiRegionDiscoveryKeyringBuilder.standard()
            .regions(regionIds)
            .build();
    }

    /**
     * Constructs an {@code AwsKmsSymmetricMultiRegionDiscoveryKeyringBuilder}
     * for use in constructing an AWS KMS symmetric multi-region discovery keyring.
     * 'Discovery' keyrings do not specify any CMKs to decrypt with, and thus will attempt to decrypt
     * using any encrypted data key in the specified region(s). 'Discovery' keyrings do not perform encryption.
     *
     * @return The {@code AwsKmsKeyringBuilder}
     */
    public static AwsKmsSymmetricMultiRegionDiscoveryKeyringBuilder awsKmsSymmetricMultiRegionDiscoveryKeyringBuilder() {
        return AwsKmsSymmetricMultiRegionDiscoveryKeyringBuilder.standard();
    }

    /**
     * Constructs a {@code Keyring} which combines other keyrings, allowing one OnEncrypt or OnDecrypt call
     * to modify the encryption or decryption materials using more than one keyring.
     *
     * @param generatorKeyring A keyring that can generate data keys. Required if childKeyrings is empty.
     * @param childKeyrings A list of keyrings to be used to modify the encryption or decryption materials.
     *                         At least one is required if generatorKeyring is null.
     * @return The {@link Keyring}
     */
    public static Keyring multi(Keyring generatorKeyring, List<Keyring> childKeyrings) {
        return new MultiKeyring(generatorKeyring, childKeyrings);
    }

    /**
     * Constructs a {@code Keyring} which combines other keyrings, allowing one OnEncrypt or OnDecrypt call
     * to modify the encryption or decryption materials using more than one keyring.
     *
     * @param generatorKeyring A keyring that can generate data keys. Required if childKeyrings is empty.
     * @param childKeyrings Keyrings to be used to modify the encryption or decryption materials.
     *                         At least one is required if generatorKeyring is null.
     * @return The {@link Keyring}
     */
    public static Keyring multi(Keyring generatorKeyring, Keyring... childKeyrings) {
        return new MultiKeyring(generatorKeyring, Arrays.asList(childKeyrings));
    }
}
