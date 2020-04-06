// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.masterkeyprovider.rawaes;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoResult;
import com.amazonaws.encryptionsdk.jce.JceMasterKey;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * This example is intended to serve as reference material for users migrating away from master key providers.
 * We recommend using keyrings rather than master key providers.
 * For examples using keyrings, see the 'examples/keyring' directory.
 * <p>
 * This examples shows how to configure and use a raw AES master key.
 * <p>
 * https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#master-key-provider
 * <p>
 * In this example, we use the one-step encrypt and decrypt APIs.
 */
public class RawAes {

    /**
     * Demonstrate an encrypt/decrypt cycle using a raw AES master key.
     *
     * @param sourcePlaintext Plaintext to encrypt
     */
    public static void run(final byte[] sourcePlaintext) {
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

        // Generate an AES key to use with your master key.
        //
        // In practice, you should get this key from a secure key management system such as an HSM.
        SecureRandom rnd = new SecureRandom();
        byte[] rawKey = new byte[32]; // 256 bits
        rnd.nextBytes(rawKey);
        SecretKey key = new SecretKeySpec(rawKey, "AES");

        // Create the master key that determines how your data keys are protected.
        final JceMasterKey masterKey = JceMasterKey.getInstance(
                // The key namespace and key name are defined by you
                // and are used by the raw AES master key
                // to determine whether it should attempt to decrypt
                // an encrypted data key.
                key,
                "some managed raw keys",    // provider corresponds to key namespace for keyrings
                "my AES wrapping key",      // key ID corresponds to key name for keyrings
                "AES/GCM/NOPADDING");       // the AES JceMasterKey only supports AES/GCM/NOPADDING

        // Encrypt your plaintext data.
        final CryptoResult<byte[], JceMasterKey> encryptResult = awsEncryptionSdk.encryptData(
                masterKey,
                sourcePlaintext,
                encryptionContext);
        final byte[] ciphertext = encryptResult.getResult();

        // Demonstrate that the ciphertext and plaintext are different.
        assert !Arrays.equals(ciphertext, sourcePlaintext);

        // Decrypt your encrypted data using the same master key you used on encrypt.
        //
        // You do not need to specify the encryption context on decrypt because
        // the header of the encrypted message includes the encryption context.
        final CryptoResult<byte[], JceMasterKey> decryptResult = awsEncryptionSdk.decryptData(
                masterKey,
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
