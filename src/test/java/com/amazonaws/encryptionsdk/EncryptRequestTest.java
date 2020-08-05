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

import com.amazonaws.encryptionsdk.keyrings.Keyring;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
class EncryptRequestTest {

    @Mock private Keyring keyring;
    @Mock private CryptoMaterialsManager cmm;
    private static final byte[] PLAINTEXT = new byte[]{1, 2, 3};

    @Test
    void testBothCmmAndKeyring() {

        assertThrows(IllegalArgumentException.class, () -> EncryptRequest.builder()
                .cryptoMaterialsManager(cmm)
                .keyring(keyring)
                .plaintext(PLAINTEXT)
                .build());
    }

    @Test
    void testNeitherCmmOrKeyring() {

        assertThrows(IllegalArgumentException.class, () -> EncryptRequest.builder()
                .plaintext(PLAINTEXT)
                .build());
    }

    @Test
    void testKeyringUsesDefaultCmm() {

        assertTrue(EncryptRequest.builder()
                .keyring(keyring)
                .plaintext(PLAINTEXT).build().cryptoMaterialsManager()
                instanceof DefaultCryptoMaterialsManager);
    }

    @Test
    void testNoEncryptionContext() {

        assertEquals(0, EncryptRequest.builder()
                .plaintext(PLAINTEXT)
                .keyring(keyring).build().encryptionContext().size());
    }

    @Test
    void testNullPlaintext() {
        assertThrows(NullPointerException.class, () -> EncryptRequest.builder()
                .keyring(keyring).build());
    }
}
