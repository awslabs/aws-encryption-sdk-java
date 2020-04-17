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
import com.amazonaws.encryptionsdk.kms.KmsMasterKeyProvider;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Before there were keyrings, there were master key providers.
 * Master key providers were the original configuration structure
 * that we provided for defining how you want to protect your data keys.
 * <p>
 * The AWS KMS master key provider was the tool that we provided for interacting with AWS KMS.
 * Like the AWS KMS keyring,
 * the AWS KMS master key provider encrypts with all CMKs that you identify,
 * but unlike the AWS KMS keyring,
 * the AWS KMS master key provider always attempts to decrypt
 * *any* data keys that were encrypted under an AWS KMS CMK.
 * We have found that separating these two behaviors
 * makes it more clear what behavior to expect,
 * so that is what we did with the AWS KMS keyring and the AWS KMS discovery keyring.
 * However, as you migrate away from master key providers to keyrings,
 * you might need to replicate the behavior of the AWS KMS master key provider.
 * <p>
 * This example shows how to configure a keyring that behaves like an AWS KMS master key provider.
 * <p>
 * For more examples of how to use the AWS KMS keyring,
 * see the 'keyring/awskms' directory.
 */
public class ActLikeAwsKmsMasterKeyProvider {

    /**
     * Demonstrate how to create a keyring that behaves like an AWS KMS master key provider.
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

        // This is the master key provider whose behavior we want to replicate.
        //
        // On encrypt, this master key provider only uses the single target AWS KMS CMK.
        // However, on decrypt, this master key provider attempts to decrypt
        // any data keys that were encrypted under an AWS KMS CMK.
        final KmsMasterKeyProvider masterKeyProviderToReplicate = KmsMasterKeyProvider.builder()
                .withKeysForEncryption(awsKmsCmk.toString()).build();

        // Create a keyring that encrypts and decrypts using a single AWS KMS CMK.
        final Keyring singleCmkKeyring = StandardKeyrings.awsKms(awsKmsCmk);

        // Create an AWS KMS discovery keyring that will attempt to decrypt
        // any data keys that were encrypted under an AWS KMS CMK.
        final Keyring discoveryKeyring = StandardKeyrings.awsKmsDiscoveryBuilder().build();

        // Combine the single-CMK and discovery keyrings
        // to create a keyring that behaves like an AWS KMS master key provider.
        final Keyring keyring = StandardKeyrings.multi(singleCmkKeyring, discoveryKeyring);

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
