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

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.Collections;
import java.util.Map;

import static com.amazonaws.encryptionsdk.internal.RandomBytesGenerator.generate;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DecryptionMaterialsTest {

    private static final CryptoAlgorithm ALGORITHM_SUITE = CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384;
    private static final Map<String, String> ENCRYPTION_CONTEXT = Collections.singletonMap("testKey", "testValue");
    private static final KeyringTraceEntry KEYRING_TRACE_ENTRY = new KeyringTraceEntry("Namespace", "Name", KeyringTraceFlag.ENCRYPTED_DATA_KEY);
    private static final KeyringTrace KEYRING_TRACE = new KeyringTrace(Collections.singletonList(KEYRING_TRACE_ENTRY));
    private static final SecretKey PLAINTEXT_DATA_KEY = new SecretKeySpec(generate(ALGORITHM_SUITE.getDataKeyLength()), ALGORITHM_SUITE.getDataKeyAlgo());
    private static PublicKey VERIFICATION_KEY;

    @BeforeAll
    static void setup() throws Exception {

        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        final KeyPair keyPair = TrailingSignatureAlgorithm.forCryptoAlgorithm(ALGORITHM_SUITE).generateKey();
        VERIFICATION_KEY = keyPair.getPublic();
    }

    @Test
    void testBuilder() {
        DecryptionMaterials result = DecryptionMaterials.newBuilder()
                .setAlgorithm(ALGORITHM_SUITE)
                .setEncryptionContext(ENCRYPTION_CONTEXT)
                .setKeyringTrace(KEYRING_TRACE)
                .setCleartextDataKey(PLAINTEXT_DATA_KEY)
                .setTrailingSignatureKey(VERIFICATION_KEY)
                .build();

        assertEquals(ALGORITHM_SUITE, result.getAlgorithm());
        assertEquals(ENCRYPTION_CONTEXT, result.getEncryptionContext());
        assertEquals(KEYRING_TRACE, result.getKeyringTrace());
        assertEquals(PLAINTEXT_DATA_KEY, result.getCleartextDataKey());
        assertEquals(VERIFICATION_KEY, result.getTrailingSignatureKey());
    }

    @Test
    void testInvalidPlaintextDataKey() {
        SecretKey wrongLength = new SecretKeySpec(generate(ALGORITHM_SUITE.getDataKeyLength() + 1), ALGORITHM_SUITE.getDataKeyAlgo());
        SecretKey wrongAlgorithm = new SecretKeySpec(generate(ALGORITHM_SUITE.getDataKeyLength()), "InvalidAlgorithm");


        DecryptionMaterials materials = DecryptionMaterials.newBuilder()
                .setAlgorithm(ALGORITHM_SUITE)
                .setTrailingSignatureKey(VERIFICATION_KEY)
                .build();
        assertThrows(IllegalArgumentException.class, () -> materials
                .withCleartextDataKey(wrongAlgorithm, KEYRING_TRACE_ENTRY));
        assertThrows(IllegalArgumentException.class, () -> materials
                .withCleartextDataKey(wrongLength, KEYRING_TRACE_ENTRY));
    }

    @Test
    void testToBuilder() {
        DecryptionMaterials expected = DecryptionMaterials.newBuilder()
                .setAlgorithm(ALGORITHM_SUITE)
                .setEncryptionContext(ENCRYPTION_CONTEXT)
                .setKeyringTrace(KEYRING_TRACE)
                .setCleartextDataKey(PLAINTEXT_DATA_KEY)
                .setTrailingSignatureKey(VERIFICATION_KEY)
                .build();

        DecryptionMaterials actual = expected.toBuilder().build();

        assertEquals(expected, actual);
        assertNotSame(expected, actual);
    }

    @Test
    void testWithPlaintextDataKey() {
        final DecryptionMaterials materials = DecryptionMaterials.newBuilder()
                .setAlgorithm(ALGORITHM_SUITE)
                .setTrailingSignatureKey(VERIFICATION_KEY)
                .build();

        assertThrows(NullPointerException.class, () -> materials.withCleartextDataKey(null, KEYRING_TRACE_ENTRY));
        assertThrows(NullPointerException.class, () -> materials.withCleartextDataKey(PLAINTEXT_DATA_KEY, null));

        final DecryptionMaterials newMaterials = materials.withCleartextDataKey(PLAINTEXT_DATA_KEY, KEYRING_TRACE_ENTRY);
        assertEquals(PLAINTEXT_DATA_KEY, newMaterials.getCleartextDataKey());
        assertEquals(PLAINTEXT_DATA_KEY, newMaterials.getDataKey().getKey());
        assertEquals(1, newMaterials.getKeyringTrace().getEntries().size());
        assertEquals(KEYRING_TRACE_ENTRY, newMaterials.getKeyringTrace().getEntries().get(0));

        assertThrows(IllegalStateException.class, () -> newMaterials.withCleartextDataKey(PLAINTEXT_DATA_KEY, KEYRING_TRACE_ENTRY));
    }

    @Test
    void testGetOptionalProperties() {
        DecryptionMaterials materials = DecryptionMaterials.newBuilder()
            .build();

        assertNull(materials.getAlgorithm());
        assertNull(materials.getCleartextDataKey());
        assertFalse(materials.hasCleartextDataKey());
        assertNull(materials.getTrailingSignatureKey());
        assertTrue(materials.getEncryptionContext().isEmpty());
        assertTrue(materials.getKeyringTrace().getEntries().isEmpty());
    }

}
