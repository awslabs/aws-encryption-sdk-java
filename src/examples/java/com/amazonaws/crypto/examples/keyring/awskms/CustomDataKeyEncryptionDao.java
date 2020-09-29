// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.keyring.awskms;

import com.amazonaws.arn.Arn;
import com.amazonaws.auth.profile.ProfileCredentialsProvider;
import com.amazonaws.encryptionsdk.*;
import com.amazonaws.encryptionsdk.keyrings.Keyring;
import com.amazonaws.encryptionsdk.keyrings.StandardKeyrings;
import com.amazonaws.encryptionsdk.kms.AwsKmsCmkId;
import com.amazonaws.encryptionsdk.kms.AwsKmsDataKeyEncryptionDaoBuilder;
import com.amazonaws.encryptionsdk.kms.DataKeyEncryptionDao;
import com.amazonaws.regions.Regions;

import javax.crypto.SecretKey;
import java.util.*;

/**
 * The AWS KMS symmetric keyring is associated with a single DataKeyEncryptionDao and a single key name.
 * Builders are provided to allow for quick generation of a multi-keyring of AWS KMS symmetric keyrings,
 * where each AWS KMS symmetric keyring is initialized with a DataKeyEncryptionDao that encapsulates an AWS KMS service client.
 * Builders are additionally provided to allow for customization of all required AWS KMS service clients.
 * <p>
 * However, if you need different behavior,
 * such as having each AWS KMS service client using a different AWS KMS client configuration,
 * you can utilize the base AWS KMS symmetric keyring directly and provide it a custom DataKeyEncryptionDao.
 *
 * <p>
 * You might use this
 * if you need different credentials in different AWS regions.
 * This might be because you are crossing partitions (ex: "aws" and "aws-cn")
 * or if you are working with regions that have separate authentication silos
 * like "ap-east-1" and "me-south-1".
 * <p>
 * This example shows how to create an AWS KMS symmetric keyring
 * that is configured with AWS KMS clients that have valid credentials for the target region,
 * even when working with regions that need different credentials.
 * <p>
 * https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/choose-keyring.html#use-kms-keyring
 * <p>
 * For an example of how to use the AWS KMS symmetric multi-CMK keyring with CMKs in multiple regions,
 * see the {@link MultipleRegions} example.
 * <p>
 * For another example of how to use the AWS KMS symmetric multi-CMK keyring with a custom client configuration,
 * see the {@link CustomKmsClientConfig} example.
 * <p>
 * For examples of how to use the AWS KMS symmetric multi-region discovery keyring on decrypt,
 * see the {@link DiscoveryDecryptInRegionOnly}
 * and {@link DiscoveryDecryptWithPreferredRegions} examples.
 */
public class CustomDataKeyEncryptionDao {

    static class CustomMultiPartitionDao implements DataKeyEncryptionDao {

        private static final AwsKmsDataKeyEncryptionDaoBuilder CHINA_BUILDER = AwsKmsDataKeyEncryptionDaoBuilder.defaultBuilder()
            .credentialsProvider(new ProfileCredentialsProvider("china"))
            .regionId(Regions.CN_NORTH_1.getName());
        private static final AwsKmsDataKeyEncryptionDaoBuilder MIDDLE_EAST_BUILDER = AwsKmsDataKeyEncryptionDaoBuilder.defaultBuilder()
            .credentialsProvider(new ProfileCredentialsProvider("middle-east"))
            .regionId(Regions.ME_SOUTH_1.getName());
        private static final AwsKmsDataKeyEncryptionDaoBuilder HONG_KONG_BUILDER = AwsKmsDataKeyEncryptionDaoBuilder.defaultBuilder()
            .credentialsProvider(new ProfileCredentialsProvider("hong-kong"))
            .regionId(Regions.AP_EAST_1.getName());

        private final DataKeyEncryptionDao usableDao;

        private CustomMultiPartitionDao(DataKeyEncryptionDao usableDao) {
            this.usableDao = usableDao;
        }

        static CustomMultiPartitionDao daoGivenRegionId(String regionId) {
            if (regionId.startsWith("cn-")) {
                return new CustomMultiPartitionDao(CHINA_BUILDER.build());
            } else if (regionId.startsWith("me-")) {
                return new CustomMultiPartitionDao(MIDDLE_EAST_BUILDER.build());
            } else if (regionId.equals("ap-east-1")) {
                return new CustomMultiPartitionDao(HONG_KONG_BUILDER.build());
            } else {
                return new CustomMultiPartitionDao(
                    AwsKmsDataKeyEncryptionDaoBuilder.defaultBuilder().regionId(regionId).build());
            }
        }

        @Override
        public GenerateDataKeyResult generateDataKey(AwsKmsCmkId keyId, CryptoAlgorithm algorithmSuite, Map<String, String> encryptionContext) {
            return this.usableDao.generateDataKey(keyId, algorithmSuite, encryptionContext);
        }

        @Override
        public EncryptedDataKey encryptDataKey(final AwsKmsCmkId keyId, SecretKey plaintextDataKey, Map<String, String> encryptionContext) {
            return this.usableDao.encryptDataKey(keyId, plaintextDataKey, encryptionContext);
        }

        @Override
        public DecryptDataKeyResult decryptDataKey(EncryptedDataKey encryptedDataKey, CryptoAlgorithm algorithmSuite, Map<String, String> encryptionContext) {
            return this.usableDao.decryptDataKey(encryptedDataKey, algorithmSuite, encryptionContext);
        }
    }

    /**
     * Demonstrate an encrypt/decrypt cycle using multiple AWS KMS symmetric keyrings, each with a unique dao.
     *
     * @param awsKmsCmk       The ARN of an AWS KMS CMK that protects data keys
     * @param sourcePlaintext Plaintext to encrypt
     */
    public static void run(final AwsKmsCmkId awsKmsCmk, final byte[] sourcePlaintext) {
        // Instantiate the AWS Encryption SDK.
        final AwsCrypto awsEncryptionSdk = AwsCrypto.standard();

        // Prepare your encryption context.
        // Remember that your encryption context is NOT SECRET.
        // https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#encryption-context
        final Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("encryption", "context");
        encryptionContext.put("is not", "secret");
        encryptionContext.put("but adds", "useful metadata");
        encryptionContext.put("that can help you", "be confident that");
        encryptionContext.put("the data you are handling", "is what you think it is");

        // Create the keyring that determines how your data keys are protected.
        final String region = Arn.fromString(awsKmsCmk.toString()).getRegion();
        final Keyring keyring = StandardKeyrings.awsKmsSymmetric(
            CustomMultiPartitionDao.daoGivenRegionId(region),
            awsKmsCmk);

        // Encrypt your plaintext data.
        final AwsCryptoResult<byte[]> encryptResult = awsEncryptionSdk.encrypt(
            EncryptRequest.builder()
                .keyring(keyring)
                .encryptionContext(encryptionContext)
                .plaintext(sourcePlaintext).build());
        final byte[] ciphertext = encryptResult.getResult();

        // Demonstrate that the ciphertext and plaintext are different.
        assert !Arrays.equals(ciphertext, sourcePlaintext);

        // Decrypt your encrypted data using the same keyring you used on encrypt.
        //
        // You do not need to specify the encryption context on decrypt because
        // the header of the encrypted message includes the encryption context.
        final AwsCryptoResult<byte[]> decryptResult = awsEncryptionSdk.decrypt(
            DecryptRequest.builder()
                .keyring(keyring)
                .ciphertext(ciphertext).build());
        final byte[] decrypted = decryptResult.getResult();

        // Demonstrate that the decrypted plaintext is identical to the original plaintext.
        assert Arrays.equals(decrypted, sourcePlaintext);

        // Verify that the encryption context used in the decrypt operation includes
        // the encryption context that you specified when encrypting.
        // The AWS Encryption SDK can add pairs, so don't require an exact match.
        //
        // In production, always use a meaningful encryption context.
        encryptionContext.forEach((k, v) -> {
            assert v.equals(decryptResult.getEncryptionContext().get(k));
        });
    }
}
