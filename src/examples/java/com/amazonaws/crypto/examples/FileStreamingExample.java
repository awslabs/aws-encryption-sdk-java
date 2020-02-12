/*
 * Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except
 * in compliance with the License. A copy of the License is located at
 *
 * http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.amazonaws.crypto.examples;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.AwsCryptoInputStream;
import com.amazonaws.encryptionsdk.CreateDecryptingInputStreamRequest;
import com.amazonaws.encryptionsdk.CreateEncryptingInputStreamRequest;
import com.amazonaws.encryptionsdk.keyrings.Keyring;
import com.amazonaws.encryptionsdk.keyrings.StandardKeyrings;
import com.amazonaws.util.IOUtils;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;

/**
 * <p>
 * Encrypts and then decrypts a file under a random key.
 *
 * <p>
 * Arguments:
 * <ol>
 * <li>Name of file containing plaintext data to encrypt
 * </ol>
 *
 * <p>
 * This program demonstrates using a standard Java {@link SecretKey} object in a {@link Keyring} to
 * encrypt and decrypt streaming data.
 */
public class FileStreamingExample {

    public static void main(String[] args) throws IOException {
        final File srcFile = new File(args[0]);
        final File encryptedFile = new File(args[1]);
        final File decryptedFile = new File(args[2]);

        encryptAndDecrypt(srcFile, encryptedFile, decryptedFile);

    }

    static void encryptAndDecrypt(final File srcFile, final File encryptedFile, final File decryptedFile) throws IOException {
        // 1. Instantiate the SDK
        final AwsCrypto crypto = new AwsCrypto();

        // 2. Get an encryption key. In this example, we generate a random key.
        //    In practice, you would get a key from an existing key store.
        final SecretKey cryptoKey = generateEncryptKey();

        // 3. Instantiate a RawAesKeyring using the random key
        final Keyring keyring = StandardKeyrings.rawAesBuilder()
                .keyNamespace("Example")
                .keyName("RandomKey")
                .wrappingKey(cryptoKey)
                .build();

        // 4. Create an encryption context
        //
        //    Most encrypted data should have an associated encryption context
        //    to protect integrity. This sample uses placeholder values.
        //
        //    For more information see:
        //    blogs.aws.amazon.com/security/post/Tx2LZ6WBJJANTNW/How-to-Protect-the-Integrity-of-Your-Encrypted-Data-by-Using-AWS-Key-Management
        final Map<String, String> encryptionContext = Collections.singletonMap("Example", "FileStreaming");

        // 5. Create the encrypting input stream with the keyring and encryption context.
        //    Because the file might be too large to load into memory,
        //    we stream the data, instead of loading it all at once.
        try (final AwsCryptoInputStream encryptingStream = crypto.createEncryptingInputStream(
                CreateEncryptingInputStreamRequest.builder()
                        .keyring(keyring)
                        .encryptionContext(encryptionContext)
                        .inputStream(new FileInputStream(srcFile)).build())) {

            // 6. Copy the encrypted data into the encrypted file.
            try (FileOutputStream out = new FileOutputStream(encryptedFile)) {
                IOUtils.copy(encryptingStream, out);
            }
        }

        // 7. Create the decrypting input stream with the keyring.
        try (final AwsCryptoInputStream decryptingStream = crypto.createDecryptingInputStream(
                CreateDecryptingInputStreamRequest.builder()
                        .keyring(keyring)
                        .inputStream(new FileInputStream(encryptedFile)).build())) {

            // 8. Verify that the encryption context that was used to decrypt the data is the one that you expect.
            //    This helps to ensure that the ciphertext that you decrypted was the one that you intended.
            //
            //    When verifying, test that your expected encryption context is a subset of the actual encryption context,
            //    not an exact match. When appropriate, the Encryption SDK adds the signing key to the encryption context.
            assert "FileStreaming".equals(decryptingStream.getAwsCryptoResult().getEncryptionContext().get("Example"));

            // 9. Copy the plaintext data to a file
            try (FileOutputStream out = new FileOutputStream(decryptedFile)) {
                IOUtils.copy(decryptingStream, out);
            }
        }

        // 10. Compare the decrypted file to the original
        compareFiles(decryptedFile, srcFile);
    }

    /**
     * In practice, this key would be saved in a secure location.
     * In this example, we generate a new random key for each operation.
     */
    private static SecretKey generateEncryptKey() {
        SecureRandom rnd = new SecureRandom();
        byte[] rawKey = new byte[16]; // 128 bits
        rnd.nextBytes(rawKey);
        return new SecretKeySpec(rawKey, "AES");
    }

    private static void compareFiles(File file1, File file2) throws IOException {
        assert file1.length() == file2.length();

        try (BufferedReader file1Reader = Files.newBufferedReader(file1.toPath());
             BufferedReader file2Reader = Files.newBufferedReader(file2.toPath())) {
            String file1Line;
            String file2Line;

            while ((file1Line = file1Reader.readLine()) != null &&
                    (file2Line = file2Reader.readLine()) != null) {
                assert Objects.equals(file1Line, file2Line);
            }
        }
    }

}
