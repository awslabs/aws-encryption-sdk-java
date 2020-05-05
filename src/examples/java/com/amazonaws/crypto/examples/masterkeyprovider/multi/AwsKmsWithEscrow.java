// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.masterkeyprovider.multi;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoResult;
import com.amazonaws.encryptionsdk.MasterKeyProvider;
import com.amazonaws.encryptionsdk.jce.JceMasterKey;
import com.amazonaws.encryptionsdk.kms.AwsKmsCmkId;
import com.amazonaws.encryptionsdk.kms.KmsMasterKey;
import com.amazonaws.encryptionsdk.kms.KmsMasterKeyProvider;
import com.amazonaws.encryptionsdk.multi.MultipleProviderFactory;

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
 * One use-case that we have seen customers need is
 * the ability to enjoy the benefits of AWS KMS during normal operation
 * but retain the ability to decrypt encrypted messages without access to AWS KMS.
 * This example shows how you can achieve this
 * by combining an AWS KMS master key with a raw RSA master key.
 * <p>
 * https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#master-key-provider
 * <p>
 * For more examples of how to use the AWS KMS master key provider, see the
 * 'masterkeyprovider/awskms' examples'
 * <p>
 * For more examples of how to use the raw RSA master key, see the
 * see the 'masterkeyprovider/rawrsa' examples.
 * <p>
 * In this example we generate a RSA keypair
 * but in practice you would want to keep your private key in an HSM
 * or other key management system.
 * <p>
 * In this example, we use the one-step encrypt and decrypt APIs.
 */
public class AwsKmsWithEscrow {

    /**
     * Demonstrate configuring a master key provider to use an AWS KMS CMK and a RSA wrapping key.
     *
     * @param awsKmsCmk       The ARN of an AWS KMS CMK that protects data keys
     * @param sourcePlaintext Plaintext to encrypt
     */
    public static void run(final AwsKmsCmkId awsKmsCmk, final byte[] sourcePlaintext) throws GeneralSecurityException {
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

        // Create the encrypt master key that only has access to the public key.
        final JceMasterKey escrowEncryptMasterKey = JceMasterKey.getInstance(
                keyPair.getPublic(),
                null,   // Private key is null
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

        // Create the decrypt master key that has access to the private key.
        final JceMasterKey escrowDecryptMasterKey = JceMasterKey.getInstance(
                null,   // Public key is null
                keyPair.getPrivate(),
                // The key namespace and key name MUST match the encrypt master key.
                "some managed raw keys",  // provider corresponds to key namespace for keyrings
                "my RSA wrapping key",    // key ID corresponds to key name for keyrings
                // The wrapping algorithm MUST match the encrypt master key.
                "RSA/ECB/OAEPWithSHA-256AndMGF1Padding");


        // Create the AWS KMS master key that you will use for decryption during normal operations.
        final KmsMasterKeyProvider kmsMasterKeyProvider = KmsMasterKeyProvider.builder()
                .withKeysForEncryption(awsKmsCmk.toString()).build();

        // Combine the AWS KMS and escrow providers into a single master key provider.
        final MasterKeyProvider<?> masterKeyProvider = MultipleProviderFactory.buildMultiProvider(
                kmsMasterKeyProvider, escrowEncryptMasterKey);

        // Encrypt your plaintext data using the combined master keys.
        final CryptoResult<byte[], ?> encryptResult = awsEncryptionSdk.encryptData(
                masterKeyProvider,
                sourcePlaintext,
                encryptionContext);
        final byte[] ciphertext = encryptResult.getResult();

        // Verify that the header contains the expected number of encrypted data keys (EDKs).
        // It should contain one EDK for AWS KMS and one for the escrow key.
        assert encryptResult.getHeaders().getEncryptedKeyBlobCount() == 2;

        // Demonstrate that the ciphertext and plaintext are different.
        assert !Arrays.equals(ciphertext, sourcePlaintext);

        // Decrypt your encrypted data separately using the AWS KMS master key provider
        // and the escrow decrypt master key.
        //
        // You do not need to specify the encryption context on decrypt because
        // the header of the encrypted message includes the encryption context.
        final CryptoResult<byte[], KmsMasterKey> decryptedKmsResult = awsEncryptionSdk.decryptData(
                kmsMasterKeyProvider,
                ciphertext);
        final byte[] decryptedKms = decryptedKmsResult.getResult();
        final CryptoResult<byte[], JceMasterKey> decryptedEscrowResult = awsEncryptionSdk.decryptData(
                escrowDecryptMasterKey,
                ciphertext);
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
