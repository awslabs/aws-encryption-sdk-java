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
import com.amazonaws.encryptionsdk.EncryptRequest;
import com.amazonaws.encryptionsdk.keyrings.Keyring;
import com.amazonaws.encryptionsdk.keyrings.RawRsaKeyringBuilder.RsaPaddingScheme;
import com.amazonaws.encryptionsdk.keyrings.StandardKeyrings;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.Collections;
import java.util.Map;

/**
 * Encrypts data using the Raw RSA keyring.
 */
public class RawRsaKeyringEncryptExample {

    static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

    public static byte[] encrypt(PublicKey publicKey) {
        // 1. Instantiate the SDK
        final AwsCrypto crypto = new AwsCrypto();

        // 2. Instantiate a Raw RSA keyring with the public key
        final Keyring keyring = StandardKeyrings.rawRsaBuilder()
                .keyNamespace("ExampleKeyNamespace")
                .keyName("ExampleKeyName")
                .paddingScheme(RsaPaddingScheme.OAEP_SHA512_MGF1)
                .publicKey(publicKey).build();

        // 3. Create an encryption context
        //
        //    Most encrypted data should have an associated encryption context
        //    to protect integrity. This sample uses placeholder values.
        //
        //    For more information see:
        //    blogs.aws.amazon.com/security/post/Tx2LZ6WBJJANTNW/How-to-Protect-the-Integrity-of-Your-Encrypted-Data-by-Using-AWS-Key-Management
        final Map<String, String> encryptionContext = Collections.singletonMap("ExampleContextKey", "ExampleContextValue");

        // 4. Encrypt the data with the keyring and encryption context
        final AwsCryptoResult<byte[]> encryptResult = crypto.encrypt(EncryptRequest.builder()
                .keyring(keyring)
                .encryptionContext(encryptionContext)
                .plaintext(EXAMPLE_DATA).build());

        // 5. Return the encrypted byte array result
        return encryptResult.getResult();
    }
}
