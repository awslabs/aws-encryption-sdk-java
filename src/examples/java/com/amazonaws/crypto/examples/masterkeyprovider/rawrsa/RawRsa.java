// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.masterkeyprovider.rawrsa;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoResult;
import com.amazonaws.encryptionsdk.jce.JceMasterKey;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * This example is intended to serve as reference material for users migrating away from master key providers.
 * We recommend using keyrings rather than master key providers.
 * For examples using keyrings, see the 'examples/keyring' directory.
 * <p>
 * This examples shows how to configure and use a raw RSA master key using a pre-loaded RSA key pair.
 * <p>
 * https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#master-key-provider
 * <p>
 * In this example, we use the one-step encrypt and decrypt APIs.
 */
public class RawRsa {

    /**
     * Demonstrate an encrypt/decrypt cycle using a raw RSA master key.
     *
     * @param sourcePlaintext Plaintext to encrypt
     */
    public static void run(final byte[] sourcePlaintext) throws GeneralSecurityException {
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

        // Generate an RSA key pair to use with your master key.
        // In practice, you should get this key from a secure key management system such as an HSM.
        final KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA");
        // The National Institute of Standards and Technology (NIST) recommends a minimum of 2048-bit keys for RSA.
        // https://www.nist.gov/publications/transitioning-use-cryptographic-algorithms-and-key-lengths
        kg.initialize(4096);
        final KeyPair keyPair = kg.generateKeyPair();

        // Create the master key that determines how your data keys are protected.
        final JceMasterKey masterKey = JceMasterKey.getInstance(
                keyPair.getPublic(),
                keyPair.getPrivate(),
                // The provider ID and key ID are defined by you
                // and are used by the raw RSA master key
                // to determine whether it should attempt to decrypt
                // an encrypted data key.
                "some managed raw keys",    // provider corresponds to key namespace for keyrings
                "my RSA wrapping key",      // key ID corresponds to key name for keyrings
                // The padding scheme tells the raw RSA master key
                // how to use your wrapping key to encrypt data keys.
                //
                // We recommend using OAEP_SHA256_MGF1.
                // You should not use PKCS1 unless you require it for backwards compatibility.
                "RSA/ECB/OAEPWithSHA-256AndMGF1Padding");

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
