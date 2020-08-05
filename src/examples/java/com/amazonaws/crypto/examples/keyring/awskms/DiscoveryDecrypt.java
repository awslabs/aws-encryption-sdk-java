// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.keyring.awskms;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.AwsCryptoResult;
import com.amazonaws.encryptionsdk.DecryptRequest;
import com.amazonaws.encryptionsdk.EncryptRequest;
import com.amazonaws.encryptionsdk.keyrings.Keyring;
import com.amazonaws.encryptionsdk.keyrings.StandardKeyrings;
import com.amazonaws.encryptionsdk.kms.AwsKmsCmkId;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * When you give the AWS KMS keyring specific key IDs it will use those CMKs and nothing else.
 * This is true both on encrypt and on decrypt.
 * However, sometimes you need more flexibility on decrypt,
 * especially when you don't know which CMKs were used to encrypt a message.
 * To address this need, you can use an AWS KMS discovery keyring.
 * The AWS KMS discovery keyring does nothing on encrypt.
 * On decrypt it reviews each encrypted data key (EDK).
 * If an EDK was encrypted under an AWS KMS CMK,
 * the AWS KMS discovery keyring attempts to decrypt it.
 * Whether decryption succeeds depends on permissions on the CMK.
 * This continues until the AWS KMS discovery keyring either runs out of EDKs
 * or succeeds in decrypting an EDK.
 * <p>
 * This example shows how to configure and use an AWS KMS discovery keyring.
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
 * see the {@link DiscoveryDecryptInRegionOnly},
 * and {@link DiscoveryDecryptWithPreferredRegions} examples.
 */
public class DiscoveryDecrypt {

    /**
     * Demonstrate configuring an AWS KMS discovery keyring for decryption.
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

        // Create the keyring that determines how your data keys are protected.
        final Keyring encryptKeyring = StandardKeyrings.awsKms(awsKmsCmk);

        // Create an AWS KMS discovery keyring to use on decrypt.
        final Keyring decryptKeyring = StandardKeyrings.awsKmsDiscoveryBuilder().build();

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
