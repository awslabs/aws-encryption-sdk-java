// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.keyring.awskms;

import com.amazonaws.arn.Arn;
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
 * This example shows how to configure a keyring that behaves similarly to an AWS KMS master key provider in strict mode.
 * <p>
 * The AWS Encryption SDK provided an AWS KMS master key provider for
 * interacting with AWS Key Management Service (AWS KMS).
 *
 * On encrypt, the AWS KMS master key provider in strict mode behaves like the AWS KMS symmetric multi-CMK keyring
 * and encrypts with all CMKs that you identify.
 *
 * On decrypt, the AWS KMS master key provider in discovery reviews each encrypted data key (EDK).
 * If the EDK was encrypted under an AWS KMS CMK,
 * the AWS KMS master key provider attempts to decrypt it.
 * Whether decryption succeeds depends on permissions on the CMK.
 * This continues until the AWS KMS master key provider in discovery mode either runs out of EDKs
 * or succeeds in decrypting an EDK.
 * In order to maintain a similar behavior,
 * we use an AWS KMS symmetric multi-region keyring
 * that has a list of regions it will attempt decryption in.
 *
 * The AWS KMS symmetric multi-region keyring throws an error on encryption,
 * so it cannot be combined with an AWS KMS symmetric multi-CMK in a multi-keyring,
 * if the encrypt operation is ever called.
 * Therefore, we have two separate keyrings.
 * One for encrypting with a specific list of CMKs
 * and one for decrypting with a specific list of regions.
 * <p>
 * For more examples of how to use the AWS KMS keyrings,
 * see the 'keyring/awskms' directory.
 */
public class ActLikeAwsKmsMasterKeyProvider {

    /**
     * Demonstrate how to create keyrings that behave like an AWS KMS master key provider.
     *
     * @param awsKmsCmk             The ARN of an AWS KMS CMK that protects data keys
     * @param awsKmsAdditionalCmks  Additional ARNs of secondary AWS KMS CMKs
     * @param sourcePlaintext       Plaintext to encrypt
     */
    public static void run(final AwsKmsCmkId awsKmsCmk, final List<AwsKmsCmkId> awsKmsAdditionalCmks, byte[] sourcePlaintext) {
        // Instantiate the AWS Encryption SDK.
        final AwsCrypto awsEncryptionSdk = AwsCrypto.standard();

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
        final List<String> masterKeyProviderCmks = new ArrayList<>();
        masterKeyProviderCmks.add(awsKmsCmk.toString());
        masterKeyProviderCmks.addAll(awsKmsAdditionalCmks.stream().map(AwsKmsCmkId::toString).collect(toList()));
        final KmsMasterKeyProvider masterKeyProviderToReplicate = KmsMasterKeyProvider.builder().buildStrict(masterKeyProviderCmks);

        // Create a keyring that encrypts and decrypts using the specified AWS KMS CMKs.
        //
        // This keyring reproduces the encryption behavior of the AWS KMS master key provider in strict mode.
        //
        // The AWS KMS symmetric multi-CMK keyring requires that you explicitly identify the CMK
        // that you want the keyring to use to generate the data key.
        final Keyring cmkKeyring = StandardKeyrings.awsKmsSymmetricMultiCmkBuilder()
                .generator(awsKmsCmk)
                .keyNames(awsKmsAdditionalCmks)
                .build();

        // Create an AWS KMS symmetric multi-region discovery keyring that will attempt to decrypt
        // any data keys that were encrypted under an AWS KMS CMK in a specific list of AWS regions.
        //
        // Please note that the multi-region discovery keyring requires the specific list of AWS regions
        // it may communicate with.
        //
        // In production, if you need a keyring that attempts decryption in all AWS regions,
        // you should call a service/API to get an updated list of AWS regions
        // and configure the keyring with that list.
        // Although there are ways of getting a list of AWS regions directly from the AWS SDK,
        // this is more prone to staleness
        // than making a service/API call.
        //
        // In most cases, you should simply call StandardKeyrings.awsKmsSymmetricMultiRegionDiscovery
        // with the specific AWS regions you require for decryption
        // and not attempt to configure the keyring with all available AWS regions.
        // You should only provide the regions you need.
        //
        // This will provide flexibility for adding more regions over time,
        // without allowing unnecessary access to regions that are not currently required.
        final List<String> allRegionIds = new ArrayList<>();
        allRegionIds.add(Arn.fromString(awsKmsCmk.toString()).getRegion());
        for (final AwsKmsCmkId additionalKeyName : awsKmsAdditionalCmks) {
            allRegionIds.add(Arn.fromString(additionalKeyName.toString()).getRegion());
        }
        final Keyring discoveryKeyring = StandardKeyrings.awsKmsSymmetricMultiRegionDiscovery(allRegionIds);

        // Note that you cannot combine the AWS KMS symmetric multi-CMK and AWS KMS symmetric multi-region keyrings
        // using a multi-keyring because the AWS KMS symmetric multi-region keyring throws an error
        // when calling the encryption operation.
        //
        // Therefore, you should use these keyrings separately (one for encrypt and one for decrypt).
        //
        // cmkKeyring reproduces the encryption behavior of the master key provider in strict mode
        // and discoveryKeyring reproduces the decryption behavior of the master key provider in discovery mode
        // with additional filtering.

        // Encrypt your plaintext data.
        final AwsCryptoResult<byte[]> encryptResult = awsEncryptionSdk.encrypt(
                EncryptRequest.builder()
                        .keyring(cmkKeyring)
                        .encryptionContext(encryptionContext)
                        .plaintext(sourcePlaintext).build());
        final byte[] ciphertext = encryptResult.getResult();

        // Demonstrate that the ciphertext and plaintext are different.
        assert !Arrays.equals(ciphertext, sourcePlaintext);

        // Decrypt your encrypted data using the AWS KMS symmetric multi-region keyring.
        //
        // You do not need to specify the encryption context on decrypt because
        // the header of the encrypted message includes the encryption context.
        final AwsCryptoResult<byte[]> decryptResult = awsEncryptionSdk.decrypt(
                DecryptRequest.builder()
                        .keyring(discoveryKeyring)
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
