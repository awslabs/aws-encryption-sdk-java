// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.keyring.awskms;

import com.amazonaws.auth.profile.ProfileCredentialsProvider;
import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.AwsCryptoResult;
import com.amazonaws.encryptionsdk.DecryptRequest;
import com.amazonaws.encryptionsdk.EncryptRequest;
import com.amazonaws.encryptionsdk.keyrings.Keyring;
import com.amazonaws.encryptionsdk.keyrings.StandardKeyrings;
import com.amazonaws.encryptionsdk.kms.AwsKmsClientSupplier;
import com.amazonaws.encryptionsdk.kms.AwsKmsCmkId;
import com.amazonaws.encryptionsdk.kms.StandardAwsKmsClientSuppliers;
import com.amazonaws.services.kms.AWSKMS;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * By default, the AWS KMS keyring uses a client supplier that
 * supplies a client with the same configuration for every region.
 * If you need different behavior, you can write your own client supplier.
 * <p>
 * You might use this
 * if you need different credentials in different AWS regions.
 * This might be because you are crossing partitions (ex: "aws" and "aws-cn")
 * or if you are working with regions that have separate authentication silos
 * like "ap-east-1" and "me-south-1".
 * <p>
 * This example shows how to create a client supplier
 * that will supply KMS clients with valid credentials for the target region
 * even when working with regions that need different credentials.
 * <p>
 * https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/choose-keyring.html#use-kms-keyring
 * <p>
 * For an example of how to use the AWS KMS keyring with CMKs in multiple regions,
 * see the {@link MultipleRegions} example.
 * <p>
 * For another example of how to use the AWS KMS keyring with a custom client configuration,
 * see the {@link CustomKmsClientConfig} example.
 * <p>
 * For examples of how to use the AWS KMS Discovery keyring on decrypt,
 * see the {@link DiscoveryDecrypt}, {@link DiscoveryDecryptInRegionOnly},
 * and {@link DiscoveryDecryptWithPreferredRegions} examples.
 */
public class CustomClientSupplier {

    static class MultiPartitionClientSupplier implements AwsKmsClientSupplier {

        private final AwsKmsClientSupplier chinaSupplier = StandardAwsKmsClientSuppliers.defaultBuilder()
                .credentialsProvider(new ProfileCredentialsProvider("china")).build();
        private final AwsKmsClientSupplier middleEastSupplier = StandardAwsKmsClientSuppliers.defaultBuilder()
                .credentialsProvider(new ProfileCredentialsProvider("middle-east")).build();
        private final AwsKmsClientSupplier hongKongSupplier = StandardAwsKmsClientSuppliers.defaultBuilder()
                .credentialsProvider(new ProfileCredentialsProvider("hong-kong")).build();
        private final AwsKmsClientSupplier defaultSupplier = StandardAwsKmsClientSuppliers.defaultBuilder().build();

        /**
         * Returns a client for the requested region.
         *
         * @param regionId The AWS region
         * @return The AWSKMS client
         */
        @Override
        public AWSKMS getClient(String regionId) {
            if (regionId.startsWith("cn-")) {
                return chinaSupplier.getClient(regionId);
            } else if (regionId.startsWith("me-")) {
                return middleEastSupplier.getClient(regionId);
            } else if (regionId.equals("ap-east-1")) {
                return hongKongSupplier.getClient(regionId);
            } else {
                return defaultSupplier.getClient(regionId);
            }
        }
    }

    /**
     * Demonstrate an encrypt/decrypt cycle using an AWS KMS keyring with a custom client supplier.
     *
     * @param awsKmsCmk       The ARN of an AWS KMS CMK that protects data keys
     * @param sourcePlaintext Plaintext to encrypt
     */
    public static void run(final AwsKmsCmkId awsKmsCmk, final byte[] sourcePlaintext) {
        // Instantiate the AWS Encryption SDK.
        final AwsCrypto awsEncryptionSdk = new AwsCrypto();

        // Prepare your encryption context.
        // https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#encryption-context
        final Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("encryption", "context");
        encryptionContext.put("is not", "secret");
        encryptionContext.put("but adds", "useful metadata");
        encryptionContext.put("that can help you", "be confident that");
        encryptionContext.put("the data you are handling", "is what you think it is");

        // Create the keyring that determines how your data keys are protected.
        final Keyring keyring = StandardKeyrings.awsKmsBuilder()
                .generatorKeyId(awsKmsCmk)
                .awsKmsClientSupplier(new MultiPartitionClientSupplier())
                .build();

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
