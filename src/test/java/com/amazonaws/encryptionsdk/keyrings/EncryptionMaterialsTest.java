/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package com.amazonaws.encryptionsdk.keyrings;

import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.EncryptedDataKey;
import com.amazonaws.encryptionsdk.internal.TrailingSignatureAlgorithm;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.Collections;
import java.util.Map;

import static com.amazonaws.encryptionsdk.internal.RandomBytesGenerator.generate;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(MockitoExtension.class)
class EncryptionMaterialsTest {

    private static final CryptoAlgorithm ALGORITHM = CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384;
    private static final Map<String, String> ENCRYPTION_CONTEXT = Collections.singletonMap("testKey", "testValue");
    private static final KeyringTrace KEYRING_TRACE = new KeyringTrace();
    private static final KeyringTraceEntry KEYRING_TRACE_ENTRY = new KeyringTraceEntry("Namespace", "Name", KeyringTraceFlag.ENCRYPTED_DATA_KEY);
    private static final SecretKey PLAINTEXT_DATA_KEY = new SecretKeySpec(generate(ALGORITHM.getDataKeyLength()), ALGORITHM.getDataKeyAlgo());
    @Mock
    private static EncryptedDataKey ENCRYPTED_DATA_KEY;
    private static PrivateKey SIGNING_KEY;

    @BeforeAll
    static void setup() throws Exception {

        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        final KeyPair keyPair = TrailingSignatureAlgorithm.forCryptoAlgorithm(ALGORITHM).generateKey();
        SIGNING_KEY = keyPair.getPrivate();
    }

    @Test
    void testBuilderNullCryptoAlgorithm() {
        assertThrows(NullPointerException.class, () -> EncryptionMaterials.newBuilder(null).build());
    }

    @Test
    void testBuilder() {
        EncryptionMaterials result = EncryptionMaterials.newBuilder(ALGORITHM)
                .setEncryptionContext(ENCRYPTION_CONTEXT)
                .setKeyringTrace(KEYRING_TRACE)
                .setPlaintextDataKey(PLAINTEXT_DATA_KEY)
                .setEncryptedDataKeys(Collections.singletonList(ENCRYPTED_DATA_KEY))
                .setSigningKey(SIGNING_KEY)
                .build();

        assertEquals(ALGORITHM, result.getAlgorithm());
        assertEquals(ENCRYPTION_CONTEXT, result.getEncryptionContext());
        assertEquals(KEYRING_TRACE, result.getKeyringTrace());
        assertEquals(PLAINTEXT_DATA_KEY, result.getPlaintextDataKey());
        assertEquals(1, result.getEncryptedDataKeys().size());
        assertEquals(ENCRYPTED_DATA_KEY, result.getEncryptedDataKeys().get(0));
        assertEquals(SIGNING_KEY, result.getSigningKey());
    }

    @Test
    void testInvalidPlaintextDataKey() {
        SecretKey wrongLength = new SecretKeySpec(generate(ALGORITHM.getDataKeyLength() + 1), ALGORITHM.getDataKeyAlgo());
        assertThrows(IllegalArgumentException.class, () -> EncryptionMaterials.newBuilder(ALGORITHM)
                .setPlaintextDataKey(wrongLength)
                .setSigningKey(SIGNING_KEY)
                .build());

        SecretKey wrongAlgorithm = new SecretKeySpec(generate(ALGORITHM.getDataKeyLength()), "InvalidAlgorithm");
        assertThrows(IllegalArgumentException.class, () -> EncryptionMaterials.newBuilder(ALGORITHM)
                .setPlaintextDataKey(wrongAlgorithm)
                .setSigningKey(SIGNING_KEY)
                .build());

        EncryptionMaterials materials = EncryptionMaterials.newBuilder(ALGORITHM)
                .setSigningKey(SIGNING_KEY)
                .build();
        assertThrows(IllegalArgumentException.class, () -> materials
                .setPlaintextDataKey(wrongAlgorithm, KEYRING_TRACE_ENTRY));
        assertThrows(IllegalArgumentException.class, () -> materials
                .setPlaintextDataKey(wrongLength, KEYRING_TRACE_ENTRY));
    }

    @Test
    void testInvalidSigningKey() {
        assertThrows(IllegalArgumentException.class, () -> EncryptionMaterials.newBuilder(ALGORITHM)
                .setSigningKey(null)
                .build());
        assertThrows(IllegalArgumentException.class, () -> EncryptionMaterials.newBuilder(CryptoAlgorithm.ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256)
                .setSigningKey(SIGNING_KEY)
                .build());

    }

    @Test
    void testToBuilder() {
        EncryptionMaterials expected = EncryptionMaterials.newBuilder(ALGORITHM)
                .setEncryptionContext(ENCRYPTION_CONTEXT)
                .setKeyringTrace(KEYRING_TRACE)
                .setPlaintextDataKey(PLAINTEXT_DATA_KEY)
                .setEncryptedDataKeys(Collections.singletonList(ENCRYPTED_DATA_KEY))
                .setSigningKey(SIGNING_KEY)
                .build();

        EncryptionMaterials actual = expected.toBuilder().build();

        assertEquals(expected, actual);
        assertNotSame(expected, actual);
    }

    @Test
    void testAddEncryptedDataKey() {
        EncryptionMaterials materials = EncryptionMaterials.newBuilder(ALGORITHM)
                .setSigningKey(SIGNING_KEY)
                .build();

        assertThrows(NullPointerException.class, () -> materials.addEncryptedDataKey(null, KEYRING_TRACE_ENTRY));
        assertThrows(NullPointerException.class, () -> materials.addEncryptedDataKey(ENCRYPTED_DATA_KEY, null));

        materials.addEncryptedDataKey(ENCRYPTED_DATA_KEY, KEYRING_TRACE_ENTRY);
        assertEquals(1, materials.getEncryptedDataKeys().size());
        assertEquals(ENCRYPTED_DATA_KEY, materials.getEncryptedDataKeys().get(0));
        assertEquals(1, materials.getKeyringTrace().getEntries().size());
        assertEquals(KEYRING_TRACE_ENTRY, materials.getKeyringTrace().getEntries().get(0));
    }

    @Test
    void testSetPlaintextDataKey() {
        EncryptionMaterials materials = EncryptionMaterials.newBuilder(ALGORITHM)
                .setSigningKey(SIGNING_KEY)
                .build();

        assertThrows(NullPointerException.class, () -> materials.setPlaintextDataKey(null, KEYRING_TRACE_ENTRY));
        assertThrows(NullPointerException.class, () -> materials.setPlaintextDataKey(PLAINTEXT_DATA_KEY, null));

        materials.setPlaintextDataKey(PLAINTEXT_DATA_KEY, KEYRING_TRACE_ENTRY);
        assertEquals(PLAINTEXT_DATA_KEY, materials.getPlaintextDataKey());
        assertEquals(1, materials.getKeyringTrace().getEntries().size());
        assertEquals(KEYRING_TRACE_ENTRY, materials.getKeyringTrace().getEntries().get(0));

        assertThrows(IllegalStateException.class, () -> materials.setPlaintextDataKey(PLAINTEXT_DATA_KEY, KEYRING_TRACE_ENTRY));
    }

}
