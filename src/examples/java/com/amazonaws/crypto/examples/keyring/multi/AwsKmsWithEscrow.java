// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.keyring.multi;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.AwsCryptoResult;
import com.amazonaws.encryptionsdk.DecryptRequest;
import com.amazonaws.encryptionsdk.EncryptRequest;
import com.amazonaws.encryptionsdk.keyrings.Keyring;
import com.amazonaws.encryptionsdk.keyrings.RawRsaKeyringBuilder.RsaPaddingScheme;
import com.amazonaws.encryptionsdk.keyrings.StandardKeyrings;
import com.amazonaws.encryptionsdk.kms.AwsKmsCmkId;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * One use-case that we have seen customers need is
 * the ability to enjoy the benefits of AWS KMS during normal operation
 * but retain the ability to decrypt encrypted messages without access to AWS KMS.
 * This example shows how you can use the multi-keyring to achieve this
 * by combining an AWS KMS keyring with a raw RSA keyring.
 * <p>
 * https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/choose-keyring.html#use-multi-keyring
 * <p>
 * For more examples of how to use the AWS KMS keyring, see the keyring/awskms examples.
 * <p>
 * For more examples of how to use the raw RSA keyring, see the keyring/rawrsa examples.
 * <p>
 * In this example we generate an RSA keypair
 * but in practice you would want to keep your private key in an HSM
 * or other key management system.
 * <p>
 * In this example, we use the one-step encrypt and decrypt APIs.
 */
public class AwsKmsWithEscrow {

    /**
     * Demonstrate configuring a keyring to use an AWS KMS CMK and an RSA wrapping key.
     *
     * @param awsKmsCmk       The ARN of an AWS KMS CMK that protects data keys
     * @param sourcePlaintext Plaintext to encrypt
     */
    public static void run(final AwsKmsCmkId awsKmsCmk, final byte[] sourcePlaintext) throws GeneralSecurityException {
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

        // Create the encrypt keyring that only has access to the public key.
        final Keyring escrowEncryptKeyring = StandardKeyrings.rawRsaBuilder()
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
                .paddingScheme(RsaPaddingScheme.OAEP_SHA256_MGF1)
                .build();

        // Create the decrypt keyring that has access to the private key.
        final Keyring escrowDecryptKeyring = StandardKeyrings.rawRsaBuilder()
                // The key namespace and key name MUST match the encrypt keyring.
                .keyNamespace("some managed raw keys")
                .keyName("my RSA wrapping key")
                .privateKey(keyPair.getPrivate())
                // The padding scheme MUST match the encrypt keyring.
                .paddingScheme(RsaPaddingScheme.OAEP_SHA256_MGF1)
                .build();

        // Create the AWS KMS keyring that you will use from decryption during normal operations.
        final Keyring kmsKeyring = StandardKeyrings.awsKms(awsKmsCmk);

        // Combine the AWS KMS keyring and the escrow encrypt keyring using the multi-keyring.
        final Keyring encryptKeyring = StandardKeyrings.multi(kmsKeyring, escrowEncryptKeyring);

        // Encrypt your plaintext data using the multi-keyring.
        final AwsCryptoResult<byte[]> encryptResult = awsEncryptionSdk.encrypt(
                EncryptRequest.builder()
                        .keyring(encryptKeyring)
                        .encryptionContext(encryptionContext)
                        .plaintext(sourcePlaintext).build());
        final byte[] ciphertext = encryptResult.getResult();

        // Verify that the header contains the expected number of encrypted data keys (EDKs).
        // It should contain one EDK for AWS KMS and one for the escrow key.
        assert encryptResult.getHeaders().getEncryptedKeyBlobCount() == 2;

        // Demonstrate that the ciphertext and plaintext are different.
        assert !Arrays.equals(ciphertext, sourcePlaintext);

        // Decrypt your encrypted data separately using the AWS KMS keyring and the escrow decrypt keyring.
        //
        // You do not need to specify the encryption context on decrypt because
        // the header of the encrypted message includes the encryption context.
        final AwsCryptoResult<byte[]> decryptedKmsResult = awsEncryptionSdk.decrypt(
                DecryptRequest.builder()
                        .keyring(kmsKeyring)
                        .ciphertext(ciphertext).build());
        final byte[] decryptedKms = decryptedKmsResult.getResult();
        final AwsCryptoResult<byte[]> decryptedEscrowResult = awsEncryptionSdk.decrypt(
                DecryptRequest.builder()
                        .keyring(escrowDecryptKeyring)
                        .ciphertext(ciphertext).build());
        final byte[] decryptedEscrow = decryptedKmsResult.getResult();

        // Demonstrate that the decrypted plaintext is identical to the original plaintext.
        assert Arrays.equals(decryptedKms, sourcePlaintext);
        assert Arrays.equals(decryptedEscrow, sourcePlaintext);

        // Verify that the encryption context used in the decrypt operation includes
        // the encryption context that you specified when encrypting.
        // The AWS Encryption SDK can add pairs, so don't require an exact match.
        //
        // In production, always use a meaningful encryption context.
        encryptionContext.forEach((k, v) -> {
            assert v.equals(decryptedKmsResult.getEncryptionContext().get(k));
            assert v.equals(decryptedEscrowResult.getEncryptionContext().get(k));
        });
    }
}
