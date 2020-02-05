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

import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

class RawRsaKeyringDecryptExampleTest {

    @Test
    void testDecrypt() throws Exception {
        final KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA");
        kg.initialize(4096);
        final KeyPair keyPair = kg.generateKeyPair();

        byte[] ciphertext = RawRsaKeyringEncryptExample.encrypt(keyPair.getPublic());
        byte[] decryptedResult = RawRsaKeyringDecryptExample.decrypt(ciphertext, keyPair);

        assertArrayEquals(RawRsaKeyringEncryptExample.EXAMPLE_DATA, decryptedResult);
    }

}
