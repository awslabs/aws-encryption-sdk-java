// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.cryptomaterialsmanager.caching;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.AwsCryptoResult;
import com.amazonaws.encryptionsdk.CryptoMaterialsManager;
import com.amazonaws.encryptionsdk.DecryptRequest;
import com.amazonaws.encryptionsdk.EncryptRequest;
import com.amazonaws.encryptionsdk.caching.CachingCryptoMaterialsManager;
import com.amazonaws.encryptionsdk.caching.LocalCryptoMaterialsCache;
import com.amazonaws.encryptionsdk.keyrings.Keyring;
import com.amazonaws.encryptionsdk.keyrings.StandardKeyrings;
import com.amazonaws.encryptionsdk.kms.AwsKmsCmkId;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * The default cryptographic materials manager (CMM)
 * creates new encryption and decryption materials
 * on every call.
 * This means every encrypted message is protected by a unique data key,
 * but it also means that you need to interact with your key management system
 * in order to process any message.
 * If this causes performance, operations, or cost issues for you,
 * you might benefit from data key caching.
 * <p>
 * https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/data-key-caching.html
 * <p>
 * This example shows how to configure the caching CMM
 * to reuse data keys across multiple encrypted messages.
 * <p>
 * In this example, we use an AWS KMS customer master key (CMK),
 * but you can use other key management options with the AWS Encryption SDK.
 * For examples that demonstrate how to use other key management configurations,
 * see the 'keyring' and 'masterkeyprovider' directories.
 * <p>
 * In this example, we use the one-step encrypt and decrypt APIs.
 */
public class SimpleCache {

    /**
     * Demonstrate an encrypt/decrypt cycle using the caching cryptographic materials manager.
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
        final Keyring keyring = StandardKeyrings.awsKms(awsKmsCmk);

        // Create the caching cryptographic materials manager using your keyring.
        final CryptoMaterialsManager cmm = CachingCryptoMaterialsManager.newBuilder()
                .withKeyring(keyring)
                // The cache is where the caching CMM stores the materials.
                //
                // LocalCryptoMaterialsCache gives you a local, in-memory, cache.
                .withCache(new LocalCryptoMaterialsCache(100))
                // Max Age determines how long the caching CMM will reuse materials.
                //
                // This example uses two minutes.
                // In production, always chose as small a value as possible
                // that works for your requirements.
                .withMaxAge(2, TimeUnit.MINUTES)
                // Message Use Limit determines how many messages
                // the caching CMM will protect with the same materials.
                //
                // In production, always choose as small a value as possible
                // that works for your requirements.
                .withMessageUseLimit(10)
                .build();

        // Encrypt your plaintext data.
        final AwsCryptoResult<byte[]> encryptResult = awsEncryptionSdk.encrypt(
                EncryptRequest.builder()
                        .cryptoMaterialsManager(cmm)
                        .encryptionContext(encryptionContext)
                        .plaintext(sourcePlaintext).build());
        final byte[] ciphertext = encryptResult.getResult();

        // Demonstrate that the ciphertext and plaintext are different.
        assert !Arrays.equals(ciphertext, sourcePlaintext);

        // Decrypt your encrypted data using the same cryptographic materials manager you used on encrypt.
        //
        // You do not need to specify the encryption context on decrypt because
        // the header of the encrypted message includes the encryption context.
        final AwsCryptoResult<byte[]> decryptResult = awsEncryptionSdk.decrypt(
                DecryptRequest.builder()
                        .cryptoMaterialsManager(cmm)
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
