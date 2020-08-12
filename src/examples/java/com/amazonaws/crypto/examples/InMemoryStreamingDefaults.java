// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.AwsCryptoInputStream;
import com.amazonaws.encryptionsdk.AwsCryptoResult;
import com.amazonaws.encryptionsdk.CreateDecryptingInputStreamRequest;
import com.amazonaws.encryptionsdk.CreateEncryptingInputStreamRequest;
import com.amazonaws.encryptionsdk.keyrings.Keyring;
import com.amazonaws.encryptionsdk.keyrings.StandardKeyrings;
import com.amazonaws.encryptionsdk.kms.AwsKmsCmkId;
import com.amazonaws.util.IOUtils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * This example shows how to use the streaming encrypt and decrypt APIs on data in memory.
 * <p>
 * One benefit of using the streaming API is that
 * we can check the encryption context before we start decrypting.
 * <p>
 * In this example, we use an AWS KMS customer master key (CMK),
 * but you can use other key management options with the AWS Encryption SDK.
 * For examples that demonstrate how to use other key management configurations,
 * see the 'keyring' and 'masterkeyprovider' directories.
 */
public class InMemoryStreamingDefaults {

    /**
     * Demonstrate an encrypt/decrypt cycle using the streaming encrypt/decrypt APIs in-memory.
     *
     * @param awsKmsCmk       The ARN of an AWS KMS CMK that protects data keys
     * @param sourcePlaintext Plaintext to encrypt
     */
    public static void run(final AwsKmsCmkId awsKmsCmk, final byte[] sourcePlaintext) throws IOException {
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
        final Keyring keyring = StandardKeyrings.awsKmsSymmetricMultiCmk(awsKmsCmk);

        ByteArrayInputStream inputStream = new ByteArrayInputStream(sourcePlaintext);

        // Create the encrypting input stream with the keyring and encryption context.
        final AwsCryptoInputStream encryptingStream = awsEncryptionSdk.createEncryptingInputStream(
                CreateEncryptingInputStreamRequest.builder()
                        .keyring(keyring)
                        .encryptionContext(encryptionContext)
                        .inputStream(inputStream).build());

        // Encrypt the plaintext and write the results into the ciphertext.
        ByteArrayOutputStream ciphertext = new ByteArrayOutputStream();
        IOUtils.copy(encryptingStream, ciphertext);

        // Demonstrate that the ciphertext and plaintext are different.
        assert !Arrays.equals(ciphertext.toByteArray(), sourcePlaintext);

        // Decrypt your encrypted data using the same keyring you used on encrypt.
        //
        // You do not need to specify the encryption context on decrypt because
        // the header of the encrypted message includes the encryption context.
        final AwsCryptoInputStream decryptingStream = awsEncryptionSdk.createDecryptingInputStream(
                CreateDecryptingInputStreamRequest.builder()
                        .keyring(keyring)
                        .inputStream(new ByteArrayInputStream(ciphertext.toByteArray())).build());

        // Check the encryption context before we start decrypting.
        //
        // Verify that the encryption context used in the decrypt operation includes
        // the encryption context that you specified when encrypting.
        // The AWS Encryption SDK can add pairs, so don't require an exact match.
        //
        // In production, always use a meaningful encryption context.
        final AwsCryptoResult<AwsCryptoInputStream> decryptResult = decryptingStream.getAwsCryptoResult();
        encryptionContext.forEach((k, v) -> {
            assert v.equals(decryptResult.getEncryptionContext().get(k));
        });

        // Now that we are more confident that we will decrypt the right message,
        // we can start decrypting.
        ByteArrayOutputStream decrypted = new ByteArrayOutputStream();
        IOUtils.copy(decryptingStream, decrypted);

        // Demonstrate that the decrypted plaintext is identical to the original plaintext.
        assert Arrays.equals(decrypted.toByteArray(), sourcePlaintext);
    }
}
