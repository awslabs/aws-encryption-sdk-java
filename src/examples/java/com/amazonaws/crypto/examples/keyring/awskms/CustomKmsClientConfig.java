// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.keyring.awskms;

import com.amazonaws.ClientConfiguration;
import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.AwsCryptoResult;
import com.amazonaws.encryptionsdk.DecryptRequest;
import com.amazonaws.encryptionsdk.EncryptRequest;
import com.amazonaws.encryptionsdk.internal.VersionInfo;
import com.amazonaws.encryptionsdk.keyrings.Keyring;
import com.amazonaws.encryptionsdk.keyrings.StandardKeyrings;
import com.amazonaws.encryptionsdk.kms.AwsKmsClientSupplier;
import com.amazonaws.encryptionsdk.kms.AwsKmsCmkId;
import com.amazonaws.encryptionsdk.kms.StandardAwsKmsClientSuppliers;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * By default, the AWS KMS keyring uses the default configurations
 * for all KMS clients and uses the default discoverable credentials.
 * If you need to change this configuration,
 * you can configure the client supplier.
 * <p>
 * This example shows how to use custom-configured clients with the AWS KMS keyring.
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
public class CustomKmsClientConfig {

    /**
     * Demonstrate an encrypt/decrypt cycle using an AWS KMS keyring with custom KMS client configuration.
     *
     * @param awsKmsCmk       The ARN of an AWS KMS CMK that protects data keys
     * @param sourcePlaintext Plaintext to encrypt
     */
    public static void run(final AwsKmsCmkId awsKmsCmk, final byte[] sourcePlaintext) {
        // Instantiate the AWS Encryption SDK.
        final AwsCrypto awsEncryptionSdk = new AwsCrypto();

        // Prepare your encryption context.
        // Remember that your encryption context is NOT SECRET.
        // https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#encryption-context
        final Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("encryption", "context");
        encryptionContext.put("is not", "secret");
        encryptionContext.put("but adds", "useful metadata");
        encryptionContext.put("that can help you", "be confident that");
        encryptionContext.put("the data you are handling", "is what you think it is");

        // Prepare your custom configuration values.
        //
        // Set your custom connection timeout value.
        // https://docs.aws.amazon.com/AWSJavaSDK/latest/javadoc/com/amazonaws/ClientConfiguration.html
        final ClientConfiguration clientConfiguration = new ClientConfiguration()
                .withConnectionTimeout(10000)   // 10,000 milliseconds
                .withUserAgentSuffix(VersionInfo.USER_AGENT);

        // Use your custom configuration values to configure your client supplier.
        // For this example we will just use the default credentials provider
        // but if you need to, you can set a custom credentials provider as well.
        final AwsKmsClientSupplier clientSupplier = StandardAwsKmsClientSuppliers.defaultBuilder()
                .clientConfiguration(clientConfiguration)
                .build();

        // Create the keyring that determines how your data keys are protected,
        // providing the client supplier that you created.
        final Keyring keyring = StandardKeyrings.awsKmsBuilder()
                .generatorKeyId(awsKmsCmk)
                .awsKmsClientSupplier(clientSupplier)
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
