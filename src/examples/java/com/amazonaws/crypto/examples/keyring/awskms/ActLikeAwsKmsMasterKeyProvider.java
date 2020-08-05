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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.util.stream.Collectors.toList;

/**
 * You might have used master key providers to protect your data keys
 * in an earlier version of the AWS Encryption SDK.
 * This example shows how to configure a keyring that behaves like an AWS KMS master key provider.
 * <p>
 * The AWS Encryption SDK provided an AWS KMS master key provider for
 * interacting with AWS Key Management Service (AWS KMS).
 * On encrypt, the AWS KMS master key provider behaves like the AWS KMS keyring
 * and encrypts with all CMKs that you identify.
 * However, on decrypt,
 * the AWS KMS master key provider reviews each encrypted data key (EDK).
 * If the EDK was encrypted under an AWS KMS CMK,
 * the AWS KMS master key provider attempts to decrypt it.
 * Whether decryption succeeds depends on permissions on the CMK.
 * This continues until the AWS KMS master key provider either runs out of EDKs
 * or succeeds in decrypting an EDK.
 * We have found that separating these two behaviors
 * makes the expected behavior clearer,
 * so that is what we did with the AWS KMS keyring and the AWS KMS discovery keyring.
 * However, as you migrate from master key providers to keyrings,
 * you might want a keyring that behaves like the AWS KMS master key provider.
 * <p>
 * For more examples of how to use the AWS KMS keyring,
 * see the 'keyring/awskms' directory.
 */
public class ActLikeAwsKmsMasterKeyProvider {

    /**
     * Demonstrate how to create a keyring that behaves like an AWS KMS master key provider.
     *
     * @param awsKmsCmk             The ARN of an AWS KMS CMK that protects data keys
     * @param awsKmsAdditionalCmks  Additional ARNs of secondary AWS KMS CMKs
     * @param sourcePlaintext       Plaintext to encrypt
     */
    public static void run(final AwsKmsCmkId awsKmsCmk, final List<AwsKmsCmkId> awsKmsAdditionalCmks, byte[] sourcePlaintext) {
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

        // This is the master key provider whose behavior we want to reproduce.
        //
        // When encrypting, this master key provider generates the data key using the first CMK in the list
        // and encrypts the data key using all specified CMKs.
        // However, when decrypting, this master key provider attempts to decrypt
        // any data keys that were encrypted under an AWS KMS CMK.
        final List<String> masterKeyProviderCmks = new ArrayList<>();
        masterKeyProviderCmks.add(awsKmsCmk.toString());
        masterKeyProviderCmks.addAll(awsKmsAdditionalCmks.stream().map(AwsKmsCmkId::toString).collect(toList()));
        final KmsMasterKeyProvider masterKeyProviderToReplicate = KmsMasterKeyProvider.builder()
                .withKeysForEncryption(masterKeyProviderCmks).build();

        // Create a CMK keyring that encrypts and decrypts using the specified AWS KMS CMKs.
        //
        // This keyring reproduces the encryption behavior of the AWS KMS master key provider.
        //
        // The AWS KMS keyring requires that you explicitly identify the CMK
        // that you want the keyring to use to generate the data key.
        final Keyring cmkKeyring = StandardKeyrings.awsKmsBuilder()
                .generatorKeyId(awsKmsCmk)
                .keyIds(awsKmsAdditionalCmks)
                .build();

        // Create an AWS KMS discovery keyring that will attempt to decrypt
        // any data keys that were encrypted under an AWS KMS CMK.
        final Keyring discoveryKeyring = StandardKeyrings.awsKmsDiscoveryBuilder().build();

        // Combine the CMK and discovery keyrings
        // to create a keyring that behaves like an AWS KMS master key provider.
        //
        // The CMK keyring reproduces the encryption behavior
        // and the discovery keyring reproduces the decryption behavior.
        // This also means that it does not matter if the CMK keyring fails to decrypt.
        // For example, if you configured the CMK keyring with aliases,
        // it works on encrypt but fails to match any encrypted data keys on decrypt
        // because the serialized key name is the resulting CMK ARN rather than the alias name.
        // However, because the discovery keyring attempts to decrypt any AWS KMS-encrypted
        // data keys that it finds, the message still decrypts successfully.
        final Keyring keyring = StandardKeyrings.multi(cmkKeyring, discoveryKeyring);

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
