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

package com.amazonaws.encryptionsdk;

import com.amazonaws.encryptionsdk.internal.TestKeyring;
import com.amazonaws.encryptionsdk.keyrings.Keyring;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
class DecryptRequestTest {

    @Mock private Keyring keyring;
    @Mock private ParsedCiphertext parsedCiphertext;
    private static final byte[] CIPHERTEXT = new byte[]{1, 2, 3};

    @Test
    void testBothCiphertextAndParsedCiphertext() {

        assertThrows(IllegalArgumentException.class, () -> DecryptRequest.builder()
                .keyring(keyring)
                .ciphertext(CIPHERTEXT)
                .parsedCiphertext(parsedCiphertext)
                .build());
    }

    @Test
    void testNeitherCiphertextOrParsedCiphertext() {

        assertThrows(IllegalArgumentException.class, () -> DecryptRequest.builder()
                .keyring(keyring)
                .build());
    }

    @Test
    void testKeyringUsesDefaultCmm() {

        byte[] ciphertext = AwsCrypto.standard().encrypt(EncryptRequest.builder()
                .keyring(new TestKeyring("keyId"))
                .plaintext(new byte[]{4, 5, 6})
                .build()).getResult();

        final CryptoMaterialsManager cryptoMaterialsManager = DecryptRequest.builder()
                .keyring(keyring)
                .ciphertext(ciphertext).build()
                .cryptoMaterialsManager();

        assertTrue(cryptoMaterialsManager instanceof DefaultCryptoMaterialsManager);
    }
}
