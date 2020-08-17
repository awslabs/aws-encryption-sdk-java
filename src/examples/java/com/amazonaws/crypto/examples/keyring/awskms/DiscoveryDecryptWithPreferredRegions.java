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
import com.amazonaws.regions.Regions;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import org.apache.commons.lang3.StringUtils;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * When you give the AWS KMS symmetric multi-CMK keyring specific key names it will use those CMKs and nothing else.
 * This is true both on encrypt and on decrypt.
 * However, sometimes you need more flexibility on decrypt,
 * especially if you don't know which CMK was used to encrypt a message.
 * To address this need, you can use an AWS KMS symmetric multi-region discovery keyring.
 * The AWS KMS symmetric multi-region discovery keyring is a multi-keyring of AWS KMS symmetric region discovery keyrings.
 * AWS KMS symmetric region discovery keyrings throw errors on encryption.
 * On decrypt each AWS KMS symmetric region discovery keyring reviews each encrypted data key (EDK).
 * If an EDK was encrypted under an AWS KMS CMK,
 * the AWS KMS symmetric region discovery keyring attempts to decrypt it if the EDK's region matches the region associated
 * with the AWS KMS symmetric region discovery keyring.
 * Whether decryption succeeds depends on permissions on the CMK.
 * This continues until all child AWS KMS symmetric region discovery keyrings either run out of EDKs
 * or a child succeeds in decrypting an EDK.
 * <p>
 * Each AWS KMS symmetric region discovery keyring is restricted to a single AWS region.
 * Additionally, an AWS KMS symmetric multi-region discovery keyring restricts communication to the configured regions,
 * in their configured order.
 * <p>
 * A more complex but more common use-case is that you would *prefer* to stay within a region,
 * but you would rather make calls to other regions than fail to decrypt the message.
 * In this case, you want a keyring that will try to decrypt data keys in this region first,
 * then try other regions.
 * <p>
 * This example shows how to configure and use an AWS KMS symmetric multi-region discovery keyring
 * that prefers the current AWS region while also failing over to other AWS regions.
 * <p>
 * https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/choose-keyring.html#use-kms-keyring
 * <p>
 * For an example of how to use the AWS KMS symmetric multi-CMK keyring with CMKs in multiple regions,
 * see the {@link MultipleRegions} example.
 * <p>
 * For examples of how to use the AWS KMS symmetric keyring
 * and the AWS KMS symmetric multi-CMK keyring with custom client configurations,
 * see the {@link CustomDataKeyEncryptionDao}
 * and {@link CustomKmsClientConfig} examples.
 * <p>
 * For more examples of how to use the AWS KMS symmetric multi-region discovery keyring on decrypt,
 * see the {@link DiscoveryDecryptInRegionOnly} examples.
 */
public class DiscoveryDecryptWithPreferredRegions {

    /**
     * Demonstrate configuring a keyring preferring a particular AWS region and failing over to others.
     *
     * @param awsKmsCmk       The ARN of an AWS KMS CMK that protects data keys
     * @param sourcePlaintext Plaintext to encrypt
     */
    public static void run(final AwsKmsCmkId awsKmsCmk, final byte[] sourcePlaintext) {
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

        // Create the keyring that determines how your data keys are protected.
        final Keyring encryptKeyring = StandardKeyrings.awsKmsSymmetricMultiCmk(awsKmsCmk);

        // To create our decrypt keyring, we need to know our current default AWS region.
        // Please note that this *may* return a null region.
        // As a result, we recommend specifying the region you are operating in directly
        // or having a fallback to prevent the keyring builder from failing.
        String localRegion = AWSKMSClientBuilder.standard().getRegion();
        localRegion = StringUtils.isBlank(localRegion) ? Regions.US_EAST_1.getName() : localRegion;

        // Now, use that region name to create an AWS KMS symmetric multi-region discovery keyring.
        // The AWS KMS symmetric multi-region discovery keyring represents a multi-keying
        // of child AWS KMS symmetric region discovery keyrings.
        //
        // The multi-keyring steps through its member keyrings in the order that you provide them,
        // attempting to decrypt every encrypted data key with each keyring before moving on to the next keyring.
        // Because of this, otherRegionsDecryptKeyring will not be called
        // unless localRegionDecryptKeyring fails to decrypt every encrypted data key.
        //
        // In this example, we first try our localRegion and then fall back to 'us-west-2'
        final Keyring decryptKeyring = StandardKeyrings.awsKmsSymmetricMultiRegionDiscovery(
            Arrays.asList(localRegion, Regions.US_WEST_2.getName()));

        // Encrypt your plaintext data.
        final AwsCryptoResult<byte[]> encryptResult = awsEncryptionSdk.encrypt(
                EncryptRequest.builder()
                        .keyring(encryptKeyring)
                        .encryptionContext(encryptionContext)
                        .plaintext(sourcePlaintext).build());
        final byte[] ciphertext = encryptResult.getResult();

        // Demonstrate that the ciphertext and plaintext are different.
        assert !Arrays.equals(ciphertext, sourcePlaintext);

        // Decrypt your encrypted data using the multi-keyring.
        //
        // You do not need to specify the encryption context on decrypt because
        // the header of the encrypted message includes the encryption context.
        final AwsCryptoResult<byte[]> decryptResult = awsEncryptionSdk.decrypt(
                DecryptRequest.builder()
                        .keyring(decryptKeyring)
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
