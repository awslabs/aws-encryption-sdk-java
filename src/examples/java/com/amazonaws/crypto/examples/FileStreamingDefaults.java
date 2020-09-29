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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * This example shows how to use the streaming encrypt and decrypt APIs when working with files.
 * <p>
 * One benefit of using the streaming API is that
 * we can check the encryption context before we start decrypting.
 * <p>
 * In this example, we use an AWS KMS customer master key (CMK),
 * but you can use other key management options with the AWS Encryption SDK.
 * For examples that demonstrate how to use other key management configurations,
 * see the 'keyring' and 'masterkeyprovider' directories.
 */
public class FileStreamingDefaults {

    /**
     * Demonstrate an encrypt/decrypt cycle using the streaming encrypt/decrypt APIs with files.
     *
     * @param awsKmsCmk           The ARN of an AWS KMS CMK that protects data keys
     * @param sourcePlaintextFile Plaintext file to encrypt
     */
    public static void run(final AwsKmsCmkId awsKmsCmk, final File sourcePlaintextFile) throws IOException {
        // Instantiate the AWS Encryption SDK.
        final AwsCrypto awsEncryptionSdk = AwsCrypto.standard();

        // We assume that you can also write to the directory containing the plaintext file,
        // so that is where we will put all of the results.
        final File encryptedFile = new File(sourcePlaintextFile.getPath() + ".encrypted");
        final File decryptedFile = new File(sourcePlaintextFile.getPath() + ".decrypted");
        encryptedFile.deleteOnExit();
        decryptedFile.deleteOnExit();

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

        // Create the encrypting input stream with the keyring and encryption context.
        // Because the file might be too large to load into memory,
        // we stream the data, instead of loading it all at once.
        try (final AwsCryptoInputStream encryptingStream = awsEncryptionSdk.createEncryptingInputStream(
                CreateEncryptingInputStreamRequest.builder()
                        .keyring(keyring)
                        .encryptionContext(encryptionContext)
                        .inputStream(new FileInputStream(sourcePlaintextFile)).build())) {

            // Encrypt the data and write the ciphertext to the encrypted file.
            try (FileOutputStream out = new FileOutputStream(encryptedFile)) {
                IOUtils.copy(encryptingStream, out);
            }
        }

        // Demonstrate that the ciphertext and plaintext are different.
        assert !compareFiles(sourcePlaintextFile, encryptedFile);

        // Create the decrypting input stream with the keyring.
        try (final AwsCryptoInputStream decryptingStream = awsEncryptionSdk.createDecryptingInputStream(
                CreateDecryptingInputStreamRequest.builder()
                        .keyring(keyring)
                        .inputStream(new FileInputStream(encryptedFile)).build())) {

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
            try (FileOutputStream out = new FileOutputStream(decryptedFile)) {
                IOUtils.copy(decryptingStream, out);
            }
        }

        // Demonstrate that the decrypted plaintext is identical to the original plaintext.
        assert compareFiles(sourcePlaintextFile, decryptedFile);
    }

    private static boolean compareFiles(File file1, File file2) throws IOException {
        if (file1.length() != file2.length()) {
            return false;
        }

        try (BufferedReader file1Reader = Files.newBufferedReader(file1.toPath());
             BufferedReader file2Reader = Files.newBufferedReader(file2.toPath())) {
            String file1Line;
            String file2Line;

            while ((file1Line = file1Reader.readLine()) != null &&
                    (file2Line = file2Reader.readLine()) != null) {
                if (!Objects.equals(file1Line, file2Line)) {
                    return false;
                }
            }

            return true;
        }
    }
}
