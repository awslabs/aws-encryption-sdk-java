// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.masterkeyprovider.awskms;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoResult;
import com.amazonaws.encryptionsdk.kms.AwsKmsCmkId;
import com.amazonaws.encryptionsdk.kms.KmsMasterKey;
import com.amazonaws.encryptionsdk.kms.KmsMasterKeyProvider;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.util.stream.Collectors.toList;

/**
 * This example is intended to serve as reference material for users migrating away from master key providers.
 * We recommend using keyrings rather than master key providers.
 * For examples using keyrings, see the 'examples/keyring' directory.
 * <p>
 * This example shows how to configure and use an AWS KMS master key provider with with CMKs in multiple regions.
 * <p>
 * https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#master-key-provider
 * <p>
 * For an example of how to use the AWS KMS master key with a single CMK,
 * see the {@link SingleCmk} example.
 * <p>
 * For an example of how to use the AWS KMS master key provider in discovery mode on decrypt,
 * see the {@link DiscoveryDecrypt} example.
 */
public class MultipleRegions {

    /**
     * Demonstrate an encrypt/decrypt cycle using an AWS KMS master key provider with CMKs in multiple regions.
     *
     * @param awsKmsGeneratorCmk   The ARN of an AWS KMS CMK that protects data keys
     * @param awsKmsAdditionalCmks Additional ARNs of secondary AWS KMS CMKs
     * @param sourcePlaintext      Plaintext to encrypt
     */
    public static void run(final AwsKmsCmkId awsKmsGeneratorCmk, final List<AwsKmsCmkId> awsKmsAdditionalCmks, final byte[] sourcePlaintext) {
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

        // Create the master key provider that will encrypt your data keys under all requested CMKs.
        //
        // The AWS KMS master key provider generates the data key using the first key ID in the list.
        final List<String> awsKmsCmks = new ArrayList<>();
        awsKmsCmks.add(awsKmsGeneratorCmk.toString());
        awsKmsCmks.addAll(awsKmsAdditionalCmks.stream().map(AwsKmsCmkId::toString).collect(toList()));
        final KmsMasterKeyProvider masterKeyProvider = KmsMasterKeyProvider.builder()
                .withKeysForEncryption(awsKmsCmks).build();

        // Create master key providers that each only use one of the CMKs.
        // We will use these later to demonstrate that any of the CMKs can be used to decrypt the message.
        final KmsMasterKeyProvider singleCmkMasterKeyThatGenerated = KmsMasterKeyProvider.builder()
                .withKeysForEncryption(awsKmsGeneratorCmk.toString()).build();
        final KmsMasterKeyProvider singleCmkMasterKeyThatEncrypted = KmsMasterKeyProvider.builder()
                .withKeysForEncryption(awsKmsAdditionalCmks.get(0).toString()).build();

        // Encrypt your plaintext data using the master key provider that uses all requests CMKs.
        final CryptoResult<byte[], KmsMasterKey> encryptResult = awsEncryptionSdk.encryptData(
                masterKeyProvider,
                sourcePlaintext,
                encryptionContext);
        final byte[] ciphertext = encryptResult.getResult();

        // Verify that the header contains the expected number of encrypted data keys (EDKs).
        // It should contain one EDK for each CMK.
        assert encryptResult.getHeaders().getEncryptedKeyBlobCount() == awsKmsAdditionalCmks.size() + 1;

        // Demonstrate that the ciphertext and plaintext are different.
        assert !Arrays.equals(ciphertext, sourcePlaintext);

        // Decrypt your encrypted data separately using the single-CMK master keys.
        //
        // You do not need to specify the encryption context on decrypt because
        // the header of the encrypted message includes the encryption context.
        final CryptoResult<byte[], KmsMasterKey> decryptResult1 = awsEncryptionSdk.decryptData(
                singleCmkMasterKeyThatGenerated,
                ciphertext);
        final byte[] decrypted1 = decryptResult1.getResult();
        final CryptoResult<byte[], KmsMasterKey> decryptResult2 = awsEncryptionSdk.decryptData(
                singleCmkMasterKeyThatEncrypted,
                ciphertext);
        final byte[] decrypted2 = decryptResult2.getResult();

        // Demonstrate that the decrypted plaintext is identical to the original plaintext.
        assert Arrays.equals(decrypted1, sourcePlaintext);
        assert Arrays.equals(decrypted2, sourcePlaintext);

        // Verify that the encryption context used in the decrypt operation includes
        // the encryption context that you specified when encrypting.
        // The AWS Encryption SDK can add pairs, so don't require an exact match.
        //
        // In production, always use a meaningful encryption context.
        encryptionContext.forEach((k, v) -> {
            assert v.equals(decryptResult1.getEncryptionContext().get(k));
            assert v.equals(decryptResult2.getEncryptionContext().get(k));
        });
    }
}
