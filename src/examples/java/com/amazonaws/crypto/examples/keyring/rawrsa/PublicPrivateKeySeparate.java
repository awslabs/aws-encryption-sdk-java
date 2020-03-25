// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.keyring.rawrsa;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.AwsCryptoResult;
import com.amazonaws.encryptionsdk.DecryptRequest;
import com.amazonaws.encryptionsdk.EncryptRequest;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.keyrings.Keyring;
import com.amazonaws.encryptionsdk.keyrings.RawRsaKeyringBuilder;
import com.amazonaws.encryptionsdk.keyrings.StandardKeyrings;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * One of the benefits of asymmetric encryption
 * is that you can encrypt with just the public key.
 * This means that you can give someone the ability to encrypt
 * without giving them the ability to decrypt.
 * <p>
 * The raw RSA keyring supports encrypt-only operations
 * when it only has access to a public key.
 * <p>
 * This example shows how to construct and use the raw RSA keyring
 * to encrypt with only the public key and decrypt with the private key.
 * <p>
 * If your RSA key is in DER format,
 * see the {@link RawRsaDerEncoded} example.
 * <p>
 * https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/choose-keyring.html#use-raw-rsa-keyring
 * <p>
 * In this example, we use the one-step encrypt and decrypt APIs.
 */
public class PublicPrivateKeySeparate {

    /**
     * Demonstrate an encrypt/decrypt cycle using separate public and private raw RSA keyrings.
     *
     * @param sourcePlaintext Plaintext to encrypt
     */
    public static void run(final byte[] sourcePlaintext) throws GeneralSecurityException {
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

        // Generate an RSA key pair to use with your keyring.
        // In practice, you should get this key from a secure key management system such as an HSM.
        final KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA");
        // The National Institute of Standards and Technology (NIST) recommends a minimum of 2048-bit keys for RSA.
        // https://www.nist.gov/publications/transitioning-use-cryptographic-algorithms-and-key-lengths
        kg.initialize(4096);
        final KeyPair keyPair = kg.generateKeyPair();

        // Create the keyring that determines how your data keys are protected.
        //
        // Create the encrypt keyring that only has access to the public key.
        final Keyring publicKeyKeyring = StandardKeyrings.rawRsaBuilder()
                // The key namespace and key name are defined by you
                // and are used by the raw RSA keyring
                // to determine whether it should attempt to decrypt
                // an encrypted data key.
                //
                // https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/choose-keyring.html#use-raw-rsa-keyring
                .keyNamespace("some managed raw keys")
                .keyName("my RSA wrapping key")
                .publicKey(keyPair.getPublic())
                // The padding scheme tells the raw RSA keyring
                // how to use your wrapping key to encrypt data keys.
                //
                // We recommend using OAEP_SHA256_MGF1.
                // You should not use PKCS1 unless you require it for backwards compatibility.
                .paddingScheme(RawRsaKeyringBuilder.RsaPaddingScheme.OAEP_SHA256_MGF1)
                .build();

        // Create the decrypt keyring that has access to the private key.
        final Keyring privateKeyKeyring = StandardKeyrings.rawRsaBuilder()
                // The key namespace and key name MUST match the encrypt keyring.
                .keyNamespace("some managed raw keys")
                .keyName("my RSA wrapping key")
                .privateKey(keyPair.getPrivate())
                // The padding scheme MUST match the encrypt keyring.
                .paddingScheme(RawRsaKeyringBuilder.RsaPaddingScheme.OAEP_SHA256_MGF1)
                .build();

        // Encrypt your plaintext data using the encrypt keyring.
        final AwsCryptoResult<byte[]> encryptResult = awsEncryptionSdk.encrypt(
                EncryptRequest.builder()
                        .keyring(publicKeyKeyring)
                        .encryptionContext(encryptionContext)
                        .plaintext(sourcePlaintext).build());
        final byte[] ciphertext = encryptResult.getResult();

        // Demonstrate that the ciphertext and plaintext are different.
        assert !Arrays.equals(ciphertext, sourcePlaintext);

        // Try to decrypt your encrypted data using the *encrypt* keyring.
        // This demonstrates that you cannot decrypt using the public key.
        try {
            awsEncryptionSdk.decrypt(
                    DecryptRequest.builder()
                            .keyring(publicKeyKeyring)
                            .ciphertext(ciphertext)
                            .build());
            throw new AssertionError("The public key can never decrypt!");
        } catch (AwsCryptoException ex) {
            // The public key cannot decrypt.
            // Reaching this point means everything is working as expected.
        }

        // Decrypt your encrypted data using the decrypt keyring.
        //
        // You do not need to specify the encryption context on decrypt because
        // the header of the encrypted message includes the encryption context.
        final AwsCryptoResult<byte[]> decryptResult = awsEncryptionSdk.decrypt(
                DecryptRequest.builder()
                        .keyring(privateKeyKeyring)
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
