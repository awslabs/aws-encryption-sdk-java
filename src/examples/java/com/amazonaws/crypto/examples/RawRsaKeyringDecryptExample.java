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
 * Decrypts data using the Raw RSA keyring.
 */
public class RawRsaKeyringDecryptExample {

    public static byte[] decrypt(byte[] ciphertext, KeyPair keyPair) {
        // 1. Instantiate the SDK
        final AwsCrypto crypto = new AwsCrypto();

        // 2. Instantiate a Raw RSA keyring with the private key
        final Keyring keyring = StandardKeyrings.rawRsaBuilder()
                .keyNamespace("ExampleKeyNamespace")
                .keyName("ExampleKeyName")
                .wrappingAlgorithm("RSA/ECB/OAEPWithSHA-512AndMGF1Padding")
                .privateKey(keyPair.getPrivate()).build();

        // 3. Decrypt the ciphertext with the keyring
        final AwsCryptoResult<byte[]> decryptResult = crypto.decrypt(DecryptRequest.builder()
                .keyring(keyring)
                .ciphertext(ciphertext).build());

        // 4. Verify that the encryption context that was used to decrypt the data is the one that you expect.
        //    This helps to ensure that the ciphertext that you decrypted was the one that you intended.
        //
        //    When verifying, test that your expected encryption context is a subset of the actual encryption context,
        //    not an exact match. When appropriate, the Encryption SDK adds the signing key to the encryption context.
        assert decryptResult.getEncryptionContext().get("ExampleContextKey").equals("ExampleContextValue");

        // 5. Return the decrypted byte array result
        return decryptResult.getResult();
    }
}
