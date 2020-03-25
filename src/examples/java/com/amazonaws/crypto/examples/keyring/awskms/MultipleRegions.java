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

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This example shows how to configure and use a KMS keyring with CMKs in multiple regions.
 * <p>
 * https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/choose-keyring.html#use-kms-keyring
 * <p>
 * For an example of how to use the KMS keyring with a single CMK,
 * see the {@link SingleCmk} example.
 * <p>
 * For examples of how to use the KMS keyring with custom client configurations,
 * see the {@link CustomClientSupplier}
 * and {@link CustomKmsClientConfig} examples.
 * <p>
 * For examples of how to use the KMS Discovery keyring on decrypt,
 * see the {@link DiscoveryDecrypt},
 * {@link DiscoveryDecryptInRegionOnly},
 * and {@link DiscoveryDecryptWithPreferredRegions} examples.
 */
public class MultipleRegions {

    /**
     * Demonstrate an encrypt/decrypt cycle using a KMS keyring with CMKs in multiple regions.
     *
     * @param awsKmsGeneratorCmk   The ARN of an AWS KMS CMK that protects data keys
     * @param awsKmsAdditionalCmks Additional ARNs of secondary KMS CMKs
     * @param sourcePlaintext      Plaintext to encrypt
     */
    public static void run(final AwsKmsCmkId awsKmsGeneratorCmk, final List<AwsKmsCmkId> awsKmsAdditionalCmks, byte[] sourcePlaintext) {
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

        // Create the keyring that will encrypt your data keys under all requested CMKs.
        final Keyring manyCmksKeyring = StandardKeyrings.awsKmsBuilder()
                .generatorKeyId(awsKmsGeneratorCmk)
                .keyIds(awsKmsAdditionalCmks)
                .build();

        // Create keyrings that each only use one of the CMKs.
        // We will use these later to demonstrate that any of the CMKs can be used to decrypt the message.
        //
        // We provide these in "keyIds" rather than "generatorKeyId"
        // so that these keyrings cannot be used to generate a new data key.
        // We will only be using them on decrypt.
        final Keyring singleCmkKeyringThatGenerated = StandardKeyrings.awsKmsBuilder()
                .keyIds(Collections.singletonList(awsKmsGeneratorCmk))
                .build();
        final Keyring singleCmkKeyringThatEncrypted = StandardKeyrings.awsKmsBuilder()
                .keyIds(Collections.singletonList(awsKmsAdditionalCmks.get(0)))
                .build();

        // Encrypt your plaintext data using the keyring that uses all requests CMKs.
        final AwsCryptoResult<byte[]> encryptResult = awsEncryptionSdk.encrypt(
                EncryptRequest.builder()
                        .keyring(manyCmksKeyring)
                        .encryptionContext(encryptionContext)
                        .plaintext(sourcePlaintext).build());
        final byte[] ciphertext = encryptResult.getResult();

        // Verify that the header contains the expected number of encrypted data keys (EDKs).
        // It should contain one EDK for each CMK.
        assert encryptResult.getHeaders().getEncryptedKeyBlobCount() == awsKmsAdditionalCmks.size() + 1;

        // Demonstrate that the ciphertext and plaintext are different.
        assert !Arrays.equals(ciphertext, sourcePlaintext);

        // Decrypt your encrypted data separately using the single-CMK keyrings.
        //
        // You do not need to specify the encryption context on decrypt because
        // the header of the encrypted message includes the encryption context.
        final AwsCryptoResult<byte[]> decryptResult1 = awsEncryptionSdk.decrypt(
                DecryptRequest.builder()
                        .keyring(singleCmkKeyringThatGenerated)
                        .ciphertext(ciphertext).build());
        final byte[] decrypted1 = decryptResult1.getResult();
        final AwsCryptoResult<byte[]> decryptResult2 = awsEncryptionSdk.decrypt(
                DecryptRequest.builder()
                        .keyring(singleCmkKeyringThatEncrypted)
                        .ciphertext(ciphertext).build());
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
