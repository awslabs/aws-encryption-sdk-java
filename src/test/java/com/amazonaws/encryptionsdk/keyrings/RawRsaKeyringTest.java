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

import com.amazonaws.encryptionsdk.EncryptedDataKey;
import com.amazonaws.encryptionsdk.model.DecryptionMaterials;
import com.amazonaws.encryptionsdk.model.EncryptionMaterials;
import com.amazonaws.encryptionsdk.model.KeyBlob;
import org.apache.commons.lang3.ArrayUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static com.amazonaws.encryptionsdk.keyrings.RawKeyringTest.ALGORITHM;
import static com.amazonaws.encryptionsdk.keyrings.RawKeyringTest.DATA_KEY;
import static com.amazonaws.encryptionsdk.keyrings.RawKeyringTest.ENCRYPTION_CONTEXT;
import static com.amazonaws.encryptionsdk.keyrings.RawKeyringTest.KEYNAME;
import static com.amazonaws.encryptionsdk.keyrings.RawKeyringTest.KEYNAMESPACE;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RawRsaKeyringTest {

    private static final String TRANSFORMATION = "RSA/ECB/PKCS1Padding";
    private static RawRsaKeyring keyring;

    @BeforeAll
    static void setup() throws Exception {
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        final KeyPair keyPair = keyPairGenerator.generateKeyPair();
        keyring = new RawRsaKeyring(KEYNAMESPACE, KEYNAME, keyPair.getPublic(), keyPair.getPrivate(), TRANSFORMATION);
    }

    @Test
    void testValidToDecrypt() {
        assertTrue(keyring.validToDecrypt(new KeyBlob(
                KEYNAMESPACE, KEYNAME.getBytes(StandardCharsets.UTF_8), new byte[]{})));
        //Provider info has extra data
        assertFalse(keyring.validToDecrypt(new KeyBlob(
                KEYNAMESPACE, ArrayUtils.add(KEYNAME.getBytes(StandardCharsets.UTF_8), (byte)5), new byte[]{})));
        //Bad namespace
        assertFalse(keyring.validToDecrypt(new KeyBlob(
                "WrongNamespace", KEYNAME.getBytes(StandardCharsets.UTF_8), new byte[]{})));
    }

    @Test
    void testEncryptDecryptExistingDataKey() {
        EncryptionMaterials encryptionMaterials = EncryptionMaterials.newBuilder()
                .setAlgorithm(ALGORITHM)
                .setCleartextDataKey(DATA_KEY)
                .setEncryptionContext(ENCRYPTION_CONTEXT)
                .build();

        encryptionMaterials = keyring.onEncrypt(encryptionMaterials);

        assertEquals(1, encryptionMaterials.getEncryptedDataKeys().size());

        final EncryptedDataKey actualEncryptedDataKey = encryptionMaterials.getEncryptedDataKeys().get(0);
        assertEquals(KEYNAMESPACE, actualEncryptedDataKey.getProviderId());
        assertArrayEquals(keyring.keyNameBytes, actualEncryptedDataKey.getProviderInformation());

        assertEquals(1, encryptionMaterials.getKeyringTrace().getEntries().size());
        assertEquals(KEYNAME, encryptionMaterials.getKeyringTrace().getEntries().get(0).getKeyName());
        assertEquals(KEYNAMESPACE, encryptionMaterials.getKeyringTrace().getEntries().get(0).getKeyNamespace());
        assertEquals(1, encryptionMaterials.getKeyringTrace().getEntries().get(0).getFlags().size());
        assertTrue(encryptionMaterials.getKeyringTrace().getEntries().get(0).getFlags().contains(KeyringTraceFlag.ENCRYPTED_DATA_KEY));

        DecryptionMaterials decryptionMaterials = DecryptionMaterials.newBuilder()
                .setAlgorithm(ALGORITHM)
                .setEncryptionContext(ENCRYPTION_CONTEXT)
                .build();

        decryptionMaterials = keyring.onDecrypt(decryptionMaterials, encryptionMaterials.getEncryptedDataKeys());

        assertEquals(DATA_KEY, decryptionMaterials.getCleartextDataKey());
        assertEquals(KEYNAME, decryptionMaterials.getKeyringTrace().getEntries().get(0).getKeyName());
        assertEquals(KEYNAMESPACE, decryptionMaterials.getKeyringTrace().getEntries().get(0).getKeyNamespace());
        assertEquals(1, decryptionMaterials.getKeyringTrace().getEntries().get(0).getFlags().size());
        assertTrue(decryptionMaterials.getKeyringTrace().getEntries().get(0).getFlags().contains(KeyringTraceFlag.DECRYPTED_DATA_KEY));
    }

    @Test
    void testEncryptDecryptGenerateDataKey() {
        EncryptionMaterials encryptionMaterials = EncryptionMaterials.newBuilder()
                .setAlgorithm(ALGORITHM)
                .setEncryptionContext(ENCRYPTION_CONTEXT)
                .build();

        encryptionMaterials = keyring.onEncrypt(encryptionMaterials);

        assertTrue(encryptionMaterials.hasCleartextDataKey());
        assertEquals(encryptionMaterials.getCleartextDataKey().getAlgorithm(), ALGORITHM.getDataKeyAlgo());
        assertEquals(1, encryptionMaterials.getEncryptedDataKeys().size());

        final EncryptedDataKey actualEncryptedDataKey = encryptionMaterials.getEncryptedDataKeys().get(0);
        assertEquals(KEYNAMESPACE, actualEncryptedDataKey.getProviderId());
        assertArrayEquals(keyring.keyNameBytes, actualEncryptedDataKey.getProviderInformation());

        assertEquals(2, encryptionMaterials.getKeyringTrace().getEntries().size());
        assertEquals(1, encryptionMaterials.getKeyringTrace().getEntries().get(0).getFlags().size());
        assertTrue(encryptionMaterials.getKeyringTrace().getEntries().get(0).getFlags().contains(KeyringTraceFlag.GENERATED_DATA_KEY));
        assertEquals(1, encryptionMaterials.getKeyringTrace().getEntries().get(1).getFlags().size());
        assertTrue(encryptionMaterials.getKeyringTrace().getEntries().get(1).getFlags().contains(KeyringTraceFlag.ENCRYPTED_DATA_KEY));

        DecryptionMaterials decryptionMaterials = DecryptionMaterials.newBuilder()
                .setAlgorithm(ALGORITHM)
                .setEncryptionContext(ENCRYPTION_CONTEXT)
                .build();

        decryptionMaterials = keyring.onDecrypt(decryptionMaterials, encryptionMaterials.getEncryptedDataKeys());

        assertEquals(encryptionMaterials.getCleartextDataKey(), decryptionMaterials.getCleartextDataKey());
        assertEquals(KEYNAME, decryptionMaterials.getKeyringTrace().getEntries().get(0).getKeyName());
        assertEquals(KEYNAMESPACE, decryptionMaterials.getKeyringTrace().getEntries().get(0).getKeyNamespace());
        assertEquals(1, decryptionMaterials.getKeyringTrace().getEntries().get(0).getFlags().size());
        assertTrue(decryptionMaterials.getKeyringTrace().getEntries().get(0).getFlags().contains(KeyringTraceFlag.DECRYPTED_DATA_KEY));
    }

}
