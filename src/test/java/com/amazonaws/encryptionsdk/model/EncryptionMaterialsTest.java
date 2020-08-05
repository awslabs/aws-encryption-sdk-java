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

package com.amazonaws.encryptionsdk.model;

import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.internal.TrailingSignatureAlgorithm;
import com.amazonaws.encryptionsdk.keyrings.KeyringTrace;
import com.amazonaws.encryptionsdk.keyrings.KeyringTraceEntry;
import com.amazonaws.encryptionsdk.keyrings.KeyringTraceFlag;
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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
class EncryptionMaterialsTest {

    private static final CryptoAlgorithm ALGORITHM_SUITE = CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384;
    private static final Map<String, String> ENCRYPTION_CONTEXT = Collections.singletonMap("testKey", "testValue");
    private static final KeyringTraceEntry KEYRING_TRACE_ENTRY = new KeyringTraceEntry("Namespace", "Name", KeyringTraceFlag.ENCRYPTED_DATA_KEY);
    private static final KeyringTrace KEYRING_TRACE = new KeyringTrace(Collections.singletonList(KEYRING_TRACE_ENTRY));
    private static final SecretKey PLAINTEXT_DATA_KEY = new SecretKeySpec(generate(ALGORITHM_SUITE.getDataKeyLength()), ALGORITHM_SUITE.getDataKeyAlgo());
    @Mock
    private static KeyBlob ENCRYPTED_DATA_KEY;
    private static PrivateKey SIGNING_KEY;

    @BeforeAll
    static void setup() throws Exception {

        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        final KeyPair keyPair = TrailingSignatureAlgorithm.forCryptoAlgorithm(ALGORITHM_SUITE).generateKey();
        SIGNING_KEY = keyPair.getPrivate();
    }

    @Test
    void testBuilder() {
        EncryptionMaterials result = EncryptionMaterials.newBuilder()
                .setAlgorithm(ALGORITHM_SUITE)
                .setEncryptionContext(ENCRYPTION_CONTEXT)
                .setKeyringTrace(KEYRING_TRACE)
                .setCleartextDataKey(PLAINTEXT_DATA_KEY)
                .setEncryptedDataKeys(Collections.singletonList(ENCRYPTED_DATA_KEY))
                .setTrailingSignatureKey(SIGNING_KEY)
                .build();

        assertEquals(ALGORITHM_SUITE, result.getAlgorithm());
        assertEquals(ENCRYPTION_CONTEXT, result.getEncryptionContext());
        assertEquals(KEYRING_TRACE, result.getKeyringTrace());
        assertEquals(PLAINTEXT_DATA_KEY, result.getCleartextDataKey());
        assertEquals(1, result.getEncryptedDataKeys().size());
        assertEquals(ENCRYPTED_DATA_KEY, result.getEncryptedDataKeys().get(0));
        assertEquals(SIGNING_KEY, result.getTrailingSignatureKey());
    }

    @Test
    void testInvalidPlaintextDataKey() {
        SecretKey wrongLength = new SecretKeySpec(generate(ALGORITHM_SUITE.getDataKeyLength() + 1), ALGORITHM_SUITE.getDataKeyAlgo());
        SecretKey wrongAlgorithm = new SecretKeySpec(generate(ALGORITHM_SUITE.getDataKeyLength()), "InvalidAlgorithm");

        EncryptionMaterials materials = EncryptionMaterials.newBuilder()
                .setAlgorithm(ALGORITHM_SUITE)
                .setTrailingSignatureKey(SIGNING_KEY)
                .build();
        assertThrows(IllegalArgumentException.class, () -> materials
                .withCleartextDataKey(wrongAlgorithm, KEYRING_TRACE_ENTRY));
        assertThrows(IllegalArgumentException.class, () -> materials
                .withCleartextDataKey(wrongLength, KEYRING_TRACE_ENTRY));
    }

    @Test
    void testToBuilder() {
        EncryptionMaterials expected = EncryptionMaterials.newBuilder()
                .setAlgorithm(ALGORITHM_SUITE)
                .setEncryptionContext(ENCRYPTION_CONTEXT)
                .setKeyringTrace(KEYRING_TRACE)
                .setCleartextDataKey(PLAINTEXT_DATA_KEY)
                .setEncryptedDataKeys(Collections.singletonList(ENCRYPTED_DATA_KEY))
                .setTrailingSignatureKey(SIGNING_KEY)
                .build();

        EncryptionMaterials actual = expected.toBuilder().build();

        assertEquals(expected, actual);
        assertNotSame(expected, actual);
    }

    @Test
    void testWithEncryptedDataKey() {
        EncryptionMaterials materials = EncryptionMaterials.newBuilder()
                .setAlgorithm(ALGORITHM_SUITE)
                .setTrailingSignatureKey(SIGNING_KEY)
                .build();

        assertThrows(NullPointerException.class, () -> materials.withEncryptedDataKey(null, KEYRING_TRACE_ENTRY));
        assertThrows(NullPointerException.class, () -> materials.withEncryptedDataKey(ENCRYPTED_DATA_KEY, null));

        EncryptionMaterials newMaterials = materials.withEncryptedDataKey(ENCRYPTED_DATA_KEY, KEYRING_TRACE_ENTRY);
        assertEquals(1, newMaterials.getEncryptedDataKeys().size());
        assertEquals(ENCRYPTED_DATA_KEY, newMaterials.getEncryptedDataKeys().get(0));
        assertEquals(1, newMaterials.getKeyringTrace().getEntries().size());
        assertEquals(KEYRING_TRACE_ENTRY, newMaterials.getKeyringTrace().getEntries().get(0));
    }

    @Test
    void testWithPlaintextDataKey() {
        EncryptionMaterials materials = EncryptionMaterials.newBuilder()
                .setAlgorithm(ALGORITHM_SUITE)
                .setTrailingSignatureKey(SIGNING_KEY)
                .build();

        assertThrows(NullPointerException.class, () -> materials.withCleartextDataKey(null, KEYRING_TRACE_ENTRY));
        assertThrows(NullPointerException.class, () -> materials.withCleartextDataKey(PLAINTEXT_DATA_KEY, null));

        EncryptionMaterials newMaterials = materials.withCleartextDataKey(PLAINTEXT_DATA_KEY, KEYRING_TRACE_ENTRY);
        assertEquals(PLAINTEXT_DATA_KEY, newMaterials.getCleartextDataKey());
        assertEquals(1, newMaterials.getKeyringTrace().getEntries().size());
        assertEquals(KEYRING_TRACE_ENTRY, newMaterials.getKeyringTrace().getEntries().get(0));

        assertThrows(IllegalStateException.class, () -> newMaterials.withCleartextDataKey(PLAINTEXT_DATA_KEY, KEYRING_TRACE_ENTRY));
    }

    @Test
    void testGetOptionalProperties() {
        EncryptionMaterials materials = EncryptionMaterials.newBuilder()
            .build();

        assertNull(materials.getAlgorithm());
        assertNull(materials.getCleartextDataKey());
        assertFalse(materials.hasCleartextDataKey());
        assertTrue(materials.getEncryptedDataKeys().isEmpty());
        assertNull(materials.getTrailingSignatureKey());
        assertTrue(materials.getKeyringTrace().getEntries().isEmpty());
        assertTrue(materials.getEncryptionContext().isEmpty());
    }

}
