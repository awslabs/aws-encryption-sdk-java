// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.keyring.awskms;

import com.amazonaws.arn.Arn;
import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.AwsCryptoResult;
import com.amazonaws.encryptionsdk.DecryptRequest;
import com.amazonaws.encryptionsdk.EncryptRequest;
import com.amazonaws.encryptionsdk.keyrings.Keyring;
import com.amazonaws.encryptionsdk.keyrings.StandardKeyrings;
import com.amazonaws.encryptionsdk.kms.AwsKmsCmkId;
import com.amazonaws.encryptionsdk.kms.StandardAwsKmsClientSuppliers;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static java.util.Collections.singleton;

/**
 * When you give the AWS KMS keyring specific key IDs it will use those CMKs and nothing else.
 * This is true both on encrypt and on decrypt.
 * However, sometimes you need more flexibility on decrypt,
 * especially if you don't know which CMK was used to encrypt a message.
 * To address this need, you can use an AWS KMS discovery keyring.
 * The AWS KMS discovery keyring does nothing on encrypt
 * but attempts to decrypt *any* data keys that were encrypted under an AWS KMS CMK.
 * <p>
 * However, sometimes you need to be a *bit* more restrictive than that.
 * To address this need, you can use a client supplier that restricts the regions an AWS KMS keyring can talk to.
 * <p>
 * This example shows how to configure and use an AWS KMS regional discovery keyring that is restricted to one region.
 * <p>
 * https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/choose-keyring.html#use-kms-keyring
 * <p>
 * For an example of how to use the AWS KMS keyring with CMKs in multiple regions,
 * see the {@link MultipleRegions} example.
 * <p>
 * For examples of how to use the AWS KMS keyring with custom client configurations,
 * see the {@link CustomClientSupplier}
 * and {@link CustomKmsClientConfig} examples.
 * <p>
 * For examples of how to use the AWS KMS discovery keyring on decrypt,
 * see the {@link DiscoveryDecrypt},
 * and {@link DiscoveryDecryptWithPreferredRegions} examples.
 */
public class DiscoveryDecryptInRegionOnly {

    /**
     * Demonstrate configuring an AWS KMS keyring to only work within a single region.
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
        final Keyring encryptKeyring = StandardKeyrings.awsKms(awsKmsCmk);

        // Extract the region from the CMK ARN.
        final String decryptRegion = Arn.fromString(awsKmsCmk.toString()).getRegion();

        // Create the AWS KMS discovery keyring that we will use on decrypt.
        //
        // The client supplier that we specify here will only supply clients for the specified region.
        // The keyring only attempts to decrypt data keys if it can get a client for that region,
        // so this keyring will now ignore any data keys that were encrypted under a CMK in another region.
        final Keyring decryptKeyring = StandardKeyrings.awsKmsDiscoveryBuilder()
                .awsKmsClientSupplier(StandardAwsKmsClientSuppliers.allowRegionsBuilder(singleton(decryptRegion)).build())
                .build();

        // Encrypt your plaintext data.
        final AwsCryptoResult<byte[]> encryptResult = awsEncryptionSdk.encrypt(
                EncryptRequest.builder()
                        .keyring(encryptKeyring)
                        .encryptionContext(encryptionContext)
                        .plaintext(sourcePlaintext).build());
        final byte[] ciphertext = encryptResult.getResult();

        // Demonstrate that the ciphertext and plaintext are different.
        assert !Arrays.equals(ciphertext, sourcePlaintext);

        // Decrypt your encrypted data using the AWS KMS discovery keyring.
        //
        // You do not need to specify the encryption context on decrypt because
        // the header of the encrypted message includes the encryption context.
        final AwsCryptoResult<byte[]> decryptResult = awsEncryptionSdk.decrypt(
                DecryptRequest.builder()
                        .keyring(decryptKeyring)
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
