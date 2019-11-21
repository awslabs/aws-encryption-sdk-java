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
import com.amazonaws.encryptionsdk.internal.JceKeyCipher;
import com.amazonaws.encryptionsdk.model.KeyBlob;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static com.amazonaws.encryptionsdk.internal.RandomBytesGenerator.generate;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RawKeyringTest {

    static final String KEYNAME = "testKeyname";
    static final String KEYNAMESPACE = "testKeynamespace";
    static final CryptoAlgorithm ALGORITHM = CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;
    static final SecretKey DATA_KEY = new SecretKeySpec(generate(ALGORITHM.getDataKeyLength()), ALGORITHM.getDataKeyAlgo());
    static final Map<String, String> ENCRYPTION_CONTEXT = Collections.singletonMap("myKey", "myValue");
    private static final EncryptedDataKey ENCRYPTED_DATA_KEY = new KeyBlob("keyProviderId", new byte[]{1, 2, 3}, generate(ALGORITHM.getDataKeyLength()));
    private static final EncryptedDataKey INVALID_DATA_KEY = new KeyBlob("invalidProviderId", new byte[]{1, 2, 3}, generate(ALGORITHM.getDataKeyLength()));
    private static final KeyringTraceEntry ENCRYPTED_DATA_KEY_TRACE = new KeyringTraceEntry(KEYNAMESPACE, KEYNAME, KeyringTraceFlag.ENCRYPTED_DATA_KEY);
    private static final KeyringTraceEntry DECRYPTED_DATA_KEY_TRACE = new KeyringTraceEntry(KEYNAMESPACE, KEYNAME, KeyringTraceFlag.DECRYPTED_DATA_KEY);
    private static final KeyringTraceEntry GENERATED_DATA_KEY_TRACE = new KeyringTraceEntry(KEYNAMESPACE, KEYNAME, KeyringTraceFlag.GENERATED_DATA_KEY);
    @Mock(lenient = true) private JceKeyCipher jceKeyCipher;
    private Keyring keyring;

    @BeforeEach
    void setup() throws Exception {
        when(jceKeyCipher.encryptKey(DATA_KEY.getEncoded(), KEYNAME, KEYNAMESPACE, ENCRYPTION_CONTEXT)).thenReturn(ENCRYPTED_DATA_KEY);
        when(jceKeyCipher.decryptKey(ENCRYPTED_DATA_KEY, KEYNAME, ENCRYPTION_CONTEXT)).thenReturn(DATA_KEY.getEncoded());

        keyring = new RawKeyring(KEYNAMESPACE, KEYNAME, jceKeyCipher) {
            @Override
            boolean validToDecrypt(EncryptedDataKey encryptedDataKey) {
                return !encryptedDataKey.getProviderId().equals(INVALID_DATA_KEY.getProviderId());
            }

            @Override
            KeyringTraceEntry traceOnEncrypt() {
                return ENCRYPTED_DATA_KEY_TRACE;
            }

            @Override
            KeyringTraceEntry traceOnDecrypt() {
                return DECRYPTED_DATA_KEY_TRACE;
            }
        };
    }

    @Test
    void testEncryptDecryptExistingDataKey() {
        EncryptionMaterials encryptionMaterials = EncryptionMaterials.newBuilder(ALGORITHM)
                .plaintextDataKey(DATA_KEY)
                .keyringTrace(new KeyringTrace())
                .encryptionContext(ENCRYPTION_CONTEXT)
                .build();

        keyring.onEncrypt(encryptionMaterials);

        assertEquals(1, encryptionMaterials.getEncryptedDataKeys().size());
        assertEncryptedDataKeyEquals(ENCRYPTED_DATA_KEY, encryptionMaterials.getEncryptedDataKeys().get(0));
        assertEquals(1, encryptionMaterials.getKeyringTrace().getEntries().size());
        assertEquals(ENCRYPTED_DATA_KEY_TRACE, encryptionMaterials.getKeyringTrace().getEntries().get(0));

        DecryptionMaterials decryptionMaterials = DecryptionMaterials.newBuilder(ALGORITHM)
                .encryptionContext(ENCRYPTION_CONTEXT)
                .keyringTrace(new KeyringTrace())
                .build();

        keyring.onDecrypt(decryptionMaterials, Collections.singletonList(ENCRYPTED_DATA_KEY));

        assertEquals(DATA_KEY, decryptionMaterials.getPlaintextDataKey());
        assertEquals(DECRYPTED_DATA_KEY_TRACE, decryptionMaterials.getKeyringTrace().getEntries().get(0));
    }

    @Test
    void testEncryptNullDataKey() {
        EncryptionMaterials encryptionMaterials = EncryptionMaterials.newBuilder(ALGORITHM)
                .keyringTrace(new KeyringTrace())
                .encryptionContext(ENCRYPTION_CONTEXT)
                .build();

        ArgumentCaptor<byte[]> dataKeyCaptor = ArgumentCaptor.forClass(byte[].class);
        when(jceKeyCipher.encryptKey(dataKeyCaptor.capture(), eq(KEYNAME), eq(KEYNAMESPACE), eq(ENCRYPTION_CONTEXT))).thenReturn(ENCRYPTED_DATA_KEY);
        keyring.onEncrypt(encryptionMaterials);

        assertEquals(encryptionMaterials.getPlaintextDataKey().getAlgorithm(), ALGORITHM.getDataKeyAlgo());
        assertArrayEquals(encryptionMaterials.getPlaintextDataKey().getEncoded(), dataKeyCaptor.getValue());
        assertEquals(1, encryptionMaterials.getEncryptedDataKeys().size());
        assertNotNull(encryptionMaterials.getPlaintextDataKey());
        assertEncryptedDataKeyEquals(ENCRYPTED_DATA_KEY, encryptionMaterials.getEncryptedDataKeys().get(0));
        assertEquals(2, encryptionMaterials.getKeyringTrace().getEntries().size());
        assertEquals(GENERATED_DATA_KEY_TRACE, encryptionMaterials.getKeyringTrace().getEntries().get(0));
        assertEquals(ENCRYPTED_DATA_KEY_TRACE, encryptionMaterials.getKeyringTrace().getEntries().get(1));
    }

    @Test
    void testDecryptAlreadyDecryptedDataKey() {
        DecryptionMaterials decryptionMaterials = DecryptionMaterials.newBuilder(ALGORITHM)
                .plaintextDataKey(DATA_KEY)
                .encryptionContext(ENCRYPTION_CONTEXT)
                .keyringTrace(new KeyringTrace())
                .build();

        keyring.onDecrypt(decryptionMaterials, Collections.singletonList(ENCRYPTED_DATA_KEY));

        assertEquals(DATA_KEY, decryptionMaterials.getPlaintextDataKey());
        assertEquals(0, decryptionMaterials.getKeyringTrace().getEntries().size());
    }

    @Test
    void testDecryptNoValidDataKey() {
        DecryptionMaterials decryptionMaterials = DecryptionMaterials.newBuilder(ALGORITHM)
                .encryptionContext(ENCRYPTION_CONTEXT)
                .keyringTrace(new KeyringTrace())
                .build();

        keyring.onDecrypt(decryptionMaterials, Collections.singletonList(INVALID_DATA_KEY));

        assertFalse(decryptionMaterials.hasPlaintextDataKey());
        assertEquals(0, decryptionMaterials.getKeyringTrace().getEntries().size());
    }

    @Test
    void testDecryptNoDataKey() {
        DecryptionMaterials decryptionMaterials = DecryptionMaterials.newBuilder(ALGORITHM)
                .encryptionContext(ENCRYPTION_CONTEXT)
                .keyringTrace(new KeyringTrace())
                .build();

        keyring.onDecrypt(decryptionMaterials, Collections.emptyList());

        assertFalse(decryptionMaterials.hasPlaintextDataKey());
        assertEquals(0, decryptionMaterials.getKeyringTrace().getEntries().size());
    }


    @Test
    void testDecryptMultipleKeysOneInvalid() {
        DecryptionMaterials decryptionMaterials = DecryptionMaterials.newBuilder(ALGORITHM)
                .encryptionContext(ENCRYPTION_CONTEXT)
                .keyringTrace(new KeyringTrace())
                .build();

        final List<EncryptedDataKey> edks = new ArrayList<>();
        edks.add(INVALID_DATA_KEY);
        edks.add(ENCRYPTED_DATA_KEY);

        keyring.onDecrypt(decryptionMaterials, edks);

        assertEquals(DATA_KEY, decryptionMaterials.getPlaintextDataKey());
        assertEquals(DECRYPTED_DATA_KEY_TRACE, decryptionMaterials.getKeyringTrace().getEntries().get(0));
    }

    @Test
    void testDecryptMultipleKeysOneException() throws GeneralSecurityException {
        final EncryptedDataKey BAD_DATA_KEY = new KeyBlob("exceptionProvider", new byte[]{1, 2, 3}, new byte[]{4, 5, 6});

        DecryptionMaterials decryptionMaterials = DecryptionMaterials.newBuilder(ALGORITHM)
                .encryptionContext(ENCRYPTION_CONTEXT)
                .keyringTrace(new KeyringTrace())
                .build();

        when(jceKeyCipher.decryptKey(BAD_DATA_KEY, KEYNAME, ENCRYPTION_CONTEXT))
                .thenThrow(new GeneralSecurityException("could not decrypt key"));

        final List<EncryptedDataKey> edks = new ArrayList<>();
        edks.add(BAD_DATA_KEY);
        edks.add(ENCRYPTED_DATA_KEY);

        keyring.onDecrypt(decryptionMaterials, edks);

        assertEquals(DATA_KEY, decryptionMaterials.getPlaintextDataKey());
        assertEquals(DECRYPTED_DATA_KEY_TRACE, decryptionMaterials.getKeyringTrace().getEntries().get(0));
    }

    private void assertEncryptedDataKeyEquals(EncryptedDataKey expected, EncryptedDataKey actual) {
        assertEquals(expected.getProviderId(), actual.getProviderId());
        assertArrayEquals(expected.getProviderInformation(), actual.getProviderInformation());
        assertArrayEquals(expected.getEncryptedDataKey(), actual.getEncryptedDataKey());
    }
}
