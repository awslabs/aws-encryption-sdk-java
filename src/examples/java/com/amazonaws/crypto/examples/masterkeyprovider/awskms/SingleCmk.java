// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.masterkeyprovider.awskms;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoResult;
import com.amazonaws.encryptionsdk.kms.AwsKmsCmkId;
import com.amazonaws.encryptionsdk.kms.KmsMasterKey;
import com.amazonaws.encryptionsdk.kms.KmsMasterKeyProvider;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * This example is intended to serve as reference material for users migrating away from master key providers.
 * We recommend using keyrings rather than master key providers.
 * For examples using keyrings, see the 'examples/keyring' directory.
 * <p>
 * This example shows how to configure and use a KMS master key with a single KMS CMK.
 * <p>
 * https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#master-key-provider
 * <p>
 * For an example of how to use the KMS master key provider with CMKs in multiple regions,
 * see the {@link MultipleRegions} example.
 * <p>
 * For an example of how to use the KMS master key provider in discovery mode on decrypt,
 * see the {@link DiscoveryDecrypt} example.
 */
public class SingleCmk {

    /**
     * Demonstrate an encrypt/decrypt cycle using a KMS master key provider with a single CMK.
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

        // Create the master key provider that determines how your data keys are protected.
        final KmsMasterKeyProvider masterKeyProvider = KmsMasterKeyProvider.builder()
                .withKeysForEncryption(awsKmsCmk.toString()).build();

        // Encrypt your plaintext data.
        final CryptoResult<byte[], KmsMasterKey> encryptResult = awsEncryptionSdk.encryptData(
                masterKeyProvider,
                sourcePlaintext,
                encryptionContext);
        final byte[] ciphertext = encryptResult.getResult();

        // Demonstrate that the ciphertext and plaintext are different.
        assert !Arrays.equals(ciphertext, sourcePlaintext);

        // Decrypt your encrypted data using the same master key provider you used on encrypt.
        //
        // You do not need to specify the encryption context on decrypt because
        // the header of the encrypted message includes the encryption context.
        final CryptoResult<byte[], KmsMasterKey> decryptResult = awsEncryptionSdk.decryptData(
                masterKeyProvider,
                ciphertext);
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
