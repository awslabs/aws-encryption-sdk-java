// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.legacy;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoInputStream;
import com.amazonaws.encryptionsdk.MasterKey;
import com.amazonaws.encryptionsdk.jce.JceMasterKey;
import com.amazonaws.encryptionsdk.CommitmentPolicy;
import com.amazonaws.util.IOUtils;

/**
 * <p>
 * Encrypts and then decrypts a file under a random key.
 * NOTE: Master key providers are deprecated and replaced by keyrings.
 *       We keep these older examples as reference material,
 *       but we recommend that you use the new examples in examples/keyring
 *       The new examples reflect our current guidance for using the library.
 *
 * <p>
 * Arguments:
 * <ol>
 * <li>Name of file containing plaintext data to encrypt
 * </ol>
 *
 * <p>
 * This program demonstrates using a standard Java {@link SecretKey} object as a {@link MasterKey} to
 * encrypt and decrypt streaming data.
 */
public class FileStreamingExample {

    public static void run(final File sourcePlaintextFile) throws IOException {
        final String srcFile = sourcePlaintextFile.getAbsolutePath();

        // In this example, we generate a random key. In practice,
        // you would get a key from an existing store.
        SecretKey cryptoKey = retrieveEncryptionKey();

        // Create a JCE master key provider using the random key and an AES-GCM encryption algorithm.
        JceMasterKey masterKey = JceMasterKey.getInstance(cryptoKey, "Example", "RandomKey", "AES/GCM/NoPadding");

        // Instantiate the SDK.
        // This builds the AwsCrypto client with the RequireEncryptRequireDecrypt commitment policy,
        // which enforces that this client only encrypts using committing algorithm suites and enforces
        // that this client will only decrypt encrypted messages that were created with a committing algorithm suite.
        // This is the default commitment policy if you build the client with `AwsCrypto.builder().build()`
        // or `AwsCrypto.standard()`.
        final AwsCrypto crypto = AwsCrypto.builder()
                .withCommitmentPolicy(CommitmentPolicy.RequireEncryptRequireDecrypt)
                .build();

        // Create an encryption context to identify this ciphertext.
        Map<String, String> context = Collections.singletonMap("Example", "FileStreaming");

        // Because the file might be to large to load into memory, we stream the data, instead of
        //loading it all at once.
        FileInputStream in = new FileInputStream(srcFile);
        CryptoInputStream<JceMasterKey> encryptingStream = crypto.createEncryptingStream(masterKey, in, context);

        FileOutputStream out = new FileOutputStream(srcFile + ".encrypted");
        IOUtils.copy(encryptingStream, out);
        encryptingStream.close();
        out.close();

        // Decrypt the file. Verify the encryption context before returning the plaintext.
        in = new FileInputStream(srcFile + ".encrypted");
        CryptoInputStream<JceMasterKey> decryptingStream = crypto.createDecryptingStream(masterKey, in);
        // Does it contain the expected encryption context?
        if (!"FileStreaming".equals(decryptingStream.getCryptoResult().getEncryptionContext().get("Example"))) {
            throw new IllegalStateException("Bad encryption context");
        }

        // Return the plaintext data.
        out = new FileOutputStream(srcFile + ".decrypted");
        IOUtils.copy(decryptingStream, out);
        decryptingStream.close();
        out.close();
    }

    /**
     * In practice, this key would be saved in a secure location.
     * For this demo, we generate a new random key for each operation.
     */
    private static SecretKey retrieveEncryptionKey() {
        SecureRandom rnd = new SecureRandom();
        byte[] rawKey = new byte[16]; // 128 bits
        rnd.nextBytes(rawKey);
        return new SecretKeySpec(rawKey, "AES");
    }
}
