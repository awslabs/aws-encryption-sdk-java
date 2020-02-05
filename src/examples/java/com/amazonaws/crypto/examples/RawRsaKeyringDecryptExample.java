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
import com.amazonaws.encryptionsdk.keyrings.Keyring;
import com.amazonaws.encryptionsdk.keyrings.StandardKeyrings;

import java.security.KeyPair;

/**
 * <p>
 * Decrypts data using the Raw RSA Keyring.
 */
public class RawRsaKeyringDecryptExample {

    public static byte[] decrypt(byte[] ciphertext, KeyPair keyPair) {
        // 1. Instantiate the SDK
        final AwsCrypto crypto = new AwsCrypto();

        // 2. Instantiate a Raw RSA Keyring with the private key
        final Keyring keyring = StandardKeyrings.rawRsa()
                .keyNamespace("ExampleKeyNamespace")
                .keyName("ExampleKeyName")
                .wrappingAlgorithm("RSA/ECB/OAEPWithSHA-512AndMGF1Padding")
                .privateKey(keyPair.getPrivate()).build();

        // 3. Decrypt the ciphertext with the keyring
        final AwsCryptoResult<byte[]> decryptResult = crypto.decrypt(DecryptRequest.builder()
                .keyring(keyring)
                .ciphertext(ciphertext).build());

        // 4. Return the decrypted byte array result
        return decryptResult.getResult();
    }
}
