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
import com.amazonaws.encryptionsdk.kms.StandardAwsKmsClientSuppliers;
import com.amazonaws.services.kms.AWSKMSClientBuilder;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static java.util.Collections.singleton;

/**
 * When you give the KMS keyring specific key IDs it will use those CMKs and nothing else.
 * This is true both on encrypt and on decrypt.
 * However, sometimes you need more flexibility on decrypt,
 * especially if you might not know beforehand which CMK was used to encrypt a message.
 * To address this need, you can use a KMS discovery keyring.
 * The KMS discovery keyring will do nothing on encrypt
 * but will attempt to decrypt *any* data keys that were encrypted under a KMS CMK.
 * <p>
 * However, sometimes you need to be a *bit* more restrictive than that.
 * To address this need, you can use a client supplier to restrict what regions a KMS keyring can talk to.
 * <p>
 * A more complex but more common use-case is that you would *prefer* to stay within a region,
 * but you would rather make calls to other regions than fail to decrypt the message.
 * In this case, you want a keyring that will try to decrypt data keys in this region first,
 * then try other regions.
 * <p>
 * This example shows how to configure and use a multi-keyring with the KMS keyring
 * to prefer the current AWS region while also failing over to other AWS regions.
 * <p>
 * https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/choose-keyring.html#use-kms-keyring
 * <p>
 * For an example of how to use the KMS keyring with CMKs in multiple regions,
 * see the {@link MultipleRegions} example.
 * <p>
 * For examples of how to use the KMS keyring with custom client configurations,
 * see the {@link CustomClientSupplier}
 * and {@link CustomKmsClientConfig} examples.
 * <p>
 * For examples of how to use the KMS discovery keyring on decrypt,
 * see the {@link DiscoveryDecrypt},
 * and {@link DiscoveryDecryptInRegionOnly} examples.
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
        // https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#encryption-context
        final Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("encryption", "context");
        encryptionContext.put("is not", "secret");
        encryptionContext.put("but adds", "useful metadata");
        encryptionContext.put("that can help you", "be confident that");
        encryptionContext.put("the data you are handling", "is what you think it is");

        // Create the keyring that determines how your data keys are protected.
        final Keyring encryptKeyring = StandardKeyrings.awsKms(awsKmsCmk);

        // To create our decrypt keyring, we need to know our current default AWS region.
        final String localRegion = AWSKMSClientBuilder.standard().getRegion();

        // Now, use that region name to create two KMS discovery keyrings:
        //
        // One that only works in the local region
        final Keyring localRegionDecryptKeyring = StandardKeyrings.awsKmsDiscoveryBuilder()
                .awsKmsClientSupplier(StandardAwsKmsClientSuppliers.allowRegionsBuilder(singleton(localRegion)).build())
                .build();
        // and one that will work in any other region but NOT the local region.
        final Keyring otherRegionsDecryptKeyring = StandardKeyrings.awsKmsDiscoveryBuilder()
                .awsKmsClientSupplier(StandardAwsKmsClientSuppliers.denyRegionsBuilder(singleton(localRegion)).build())
                .build();

        // Finally, combine those two keyrings into a multi-keyring.
        //
        // The multi-keyring steps through its member keyrings in the order that you provide them,
        // attempting to decrypt every encrypted data key with each keyring before moving on to the next keyring.
        // Because of this, otherRegionsDecryptKeyring will not be called
        // unless localRegionDecryptKeyring fails to decrypt every encrypted data key.
        final Keyring decryptKeyring = StandardKeyrings.multi(localRegionDecryptKeyring, otherRegionsDecryptKeyring);

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
