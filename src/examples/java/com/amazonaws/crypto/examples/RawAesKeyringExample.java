/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
import com.amazonaws.encryptionsdk.AwsCryptoResult;
import com.amazonaws.encryptionsdk.DecryptRequest;
import com.amazonaws.encryptionsdk.EncryptRequest;
import com.amazonaws.encryptionsdk.keyrings.Keyring;
import com.amazonaws.encryptionsdk.keyrings.StandardKeyrings;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

/**
 * <p>
 * Encrypts and then decrypts data using the Raw AES keyring.
 */
public class RawAesKeyringExample {

    private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

    public static void main(final String[] args) {
        encryptAndDecrypt();
    }

    static void encryptAndDecrypt() {
        // 1. Instantiate the SDK
        final AwsCrypto crypto = new AwsCrypto();

        // 2. Get an encryption key. In this example, we generate a random key.
        //    In practice, you would get a key from an existing key store
        final SecretKey cryptoKey = generateEncryptKey();

        // 3. Instantiate a Raw AES keyring with the encryption key
        final Keyring keyring = StandardKeyrings.rawAesBuilder()
                .keyNamespace("ExampleKeyNamespace")
                .keyName("ExampleKeyName")
                .wrappingKey(cryptoKey).build();

        // 4. Create an encryption context
        //
        //    Most encrypted data should have an associated encryption context
        //    to protect integrity. This sample uses placeholder values.
        //
        //    For more information see:
        //    blogs.aws.amazon.com/security/post/Tx2LZ6WBJJANTNW/How-to-Protect-the-Integrity-of-Your-Encrypted-Data-by-Using-AWS-Key-Management
        final Map<String, String> encryptionContext = Collections.singletonMap("ExampleContextKey", "ExampleContextValue");

        // 5. Encrypt the data with the keyring and encryption context
        final AwsCryptoResult<byte[]> encryptResult = crypto.encrypt(EncryptRequest.builder()
                .keyring(keyring)
                .encryptionContext(encryptionContext)
                .plaintext(EXAMPLE_DATA).build());
        final byte[] ciphertext = encryptResult.getResult();

        // 6. Decrypt the data
        final AwsCryptoResult<byte[]> decryptResult = crypto.decrypt(DecryptRequest.builder()
                .keyring(keyring)
                .ciphertext(ciphertext).build());

        // 7. Verify that the encryption context that was used to decrypt the data is the one that you expect.
        //    This helps to ensure that the ciphertext that you decrypted was the one that you intended.
        //
        //    When verifying, test that your expected encryption context is a subset of the actual encryption context,
        //    not an exact match. When appropriate, the Encryption SDK adds the signing key to the encryption context.
        assert decryptResult.getEncryptionContext().get("ExampleContextKey").equals("ExampleContextValue");

        // 8. Verify that the decrypted plaintext matches the original plaintext
        assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);
    }

    /**
     * In practice, this key would be saved in a secure location.
     * For this demo, we generate a new random key for each operation.
     */
    private static SecretKey generateEncryptKey() {
        SecureRandom rnd = new SecureRandom();
        byte[] rawKey = new byte[16]; // 128 bits
        rnd.nextBytes(rawKey);
        return new SecretKeySpec(rawKey, "AES");
    }
}
