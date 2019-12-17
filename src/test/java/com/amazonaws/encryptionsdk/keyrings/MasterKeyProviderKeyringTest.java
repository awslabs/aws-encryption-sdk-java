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
import com.amazonaws.encryptionsdk.DataKey;
import com.amazonaws.encryptionsdk.EncryptedDataKey;
import com.amazonaws.encryptionsdk.MasterKey;
import com.amazonaws.encryptionsdk.MasterKeyProvider;
import com.amazonaws.encryptionsdk.MasterKeyRequest;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.CannotUnwrapDataKeyException;
import com.amazonaws.encryptionsdk.jce.JceMasterKey;
import com.amazonaws.encryptionsdk.kms.KmsMasterKey;
import com.amazonaws.encryptionsdk.kms.KmsMasterKeyProvider;
import com.amazonaws.encryptionsdk.model.KeyBlob;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static com.amazonaws.encryptionsdk.EncryptedDataKey.PROVIDER_ENCODING;
import static com.amazonaws.encryptionsdk.internal.RandomBytesGenerator.generate;
import static com.amazonaws.encryptionsdk.keyrings.KeyringTraceFlag.DECRYPTED_DATA_KEY;
import static com.amazonaws.encryptionsdk.keyrings.KeyringTraceFlag.ENCRYPTED_DATA_KEY;
import static com.amazonaws.encryptionsdk.keyrings.KeyringTraceFlag.GENERATED_DATA_KEY;
import static com.amazonaws.encryptionsdk.keyrings.KeyringTraceFlag.SIGNED_ENCRYPTION_CONTEXT;
import static com.amazonaws.encryptionsdk.keyrings.KeyringTraceFlag.VERIFIED_ENCRYPTION_CONTEXT;
import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class MasterKeyProviderKeyringTest {

    private static final CryptoAlgorithm ALGORITHM_SUITE = CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;
    private static final SecretKey PLAINTEXT_DATA_KEY = new SecretKeySpec(generate(ALGORITHM_SUITE.getDataKeyLength()), ALGORITHM_SUITE.getDataKeyAlgo());
    private static final Map<String, String> ENCRYPTION_CONTEXT = Collections.singletonMap("myKey", "myValue");

    @Test
    void testOnEncryptWithoutPlaintextDataKey() {

        MasterKeyProvider<JceMasterKey> masterKeyProvider = mock(JceMasterKey.class);

        EncryptionMaterials encryptionMaterials = EncryptionMaterials.newBuilder(ALGORITHM_SUITE)
                .encryptionContext(ENCRYPTION_CONTEXT)
                .build();

        Keyring keyring = StandardKeyrings.masterKeyProvider(masterKeyProvider);

        JceMasterKey masterKey1 = mock(JceMasterKey.class);
        JceMasterKey masterKey2 = mock(JceMasterKey.class);

        List<JceMasterKey> masterKeys = new ArrayList<>();
        masterKeys.add(masterKey1);
        masterKeys.add(masterKey2);

        ArgumentCaptor<MasterKeyRequest> masterKeyRequestCaptor = ArgumentCaptor.forClass(MasterKeyRequest.class);
        ArgumentCaptor<DataKey> dataKeyCaptor = ArgumentCaptor.forClass(DataKey.class);

        final String KEY_ID_1 = "KeyId1";
        final String KEY_ID_2 = "KeyId2";
        final String PROVIDER_1 = "Provider1";
        final String PROVIDER_2 = "Provider2";

        DataKey<JceMasterKey> dataKey1 = new DataKey<>(PLAINTEXT_DATA_KEY, generate(100), KEY_ID_1.getBytes(PROVIDER_ENCODING), masterKey1);
        DataKey<JceMasterKey> dataKey2 = new DataKey<>(PLAINTEXT_DATA_KEY, generate(100), KEY_ID_2.getBytes(PROVIDER_ENCODING), masterKey2);

        when(masterKeyProvider.getMasterKeysForEncryption(masterKeyRequestCaptor.capture())).thenReturn(masterKeys);
        when(masterKey1.generateDataKey(ALGORITHM_SUITE, ENCRYPTION_CONTEXT)).thenReturn(dataKey1);
        when(masterKey2.encryptDataKey(eq(ALGORITHM_SUITE), eq(ENCRYPTION_CONTEXT), dataKeyCaptor.capture()))
                .thenReturn(dataKey2);
        when(masterKey1.getProviderId()).thenReturn(PROVIDER_1);
        when(masterKey1.getKeyId()).thenReturn(KEY_ID_1);
        when(masterKey2.getProviderId()).thenReturn(PROVIDER_2);
        when(masterKey2.getKeyId()).thenReturn(KEY_ID_2);
        when(masterKey1.isEncryptionContextSigned()).thenReturn(true);
        when(masterKey2.isEncryptionContextSigned()).thenReturn(false);

        keyring.onEncrypt(encryptionMaterials);

        assertEquals(ENCRYPTION_CONTEXT, masterKeyRequestCaptor.getValue().getEncryptionContext());
        assertEquals(PLAINTEXT_DATA_KEY, dataKeyCaptor.getValue().getKey());
        assertEncryptedDataKeyEquals(dataKey1, encryptionMaterials.getEncryptedDataKeys().get(0));
        assertEncryptedDataKeyEquals(dataKey2, encryptionMaterials.getEncryptedDataKeys().get(1));
        assertEquals(new KeyringTraceEntry(PROVIDER_1, KEY_ID_1, GENERATED_DATA_KEY),
                encryptionMaterials.getKeyringTrace().getEntries().get(0));
        assertEquals(new KeyringTraceEntry(PROVIDER_1, KEY_ID_1, ENCRYPTED_DATA_KEY, SIGNED_ENCRYPTION_CONTEXT),
                encryptionMaterials.getKeyringTrace().getEntries().get(1));
        assertEquals(new KeyringTraceEntry(PROVIDER_2, KEY_ID_2, ENCRYPTED_DATA_KEY),
                encryptionMaterials.getKeyringTrace().getEntries().get(2));
    }

    @Test
    void testOnEncryptWithPlaintextDataKey() {

        MasterKeyProvider<KmsMasterKey> masterKeyProvider = mock(KmsMasterKeyProvider.class);

        EncryptionMaterials encryptionMaterials = EncryptionMaterials.newBuilder(ALGORITHM_SUITE)
                .encryptionContext(ENCRYPTION_CONTEXT)
                .plaintextDataKey(PLAINTEXT_DATA_KEY)
                .build();

        Keyring keyring = StandardKeyrings.masterKeyProvider(masterKeyProvider);

        KmsMasterKey masterKey1 = mock(KmsMasterKey.class);
        KmsMasterKey masterKey2 = mock(KmsMasterKey.class);

        List<KmsMasterKey> masterKeys = new ArrayList<>();
        masterKeys.add(masterKey1);
        masterKeys.add(masterKey2);

        ArgumentCaptor<MasterKeyRequest> masterKeyRequestCaptor = ArgumentCaptor.forClass(MasterKeyRequest.class);
        ArgumentCaptor<DataKey> dataKeyCaptor = ArgumentCaptor.forClass(DataKey.class);

        final String KEY_ID_1 = "KeyId1";
        final String KEY_ID_2 = "KeyId2";
        final String PROVIDER_1 = "Provider1";
        final String PROVIDER_2 = "Provider2";

        DataKey<KmsMasterKey> dataKey1 = new DataKey<>(PLAINTEXT_DATA_KEY, generate(100), KEY_ID_1.getBytes(PROVIDER_ENCODING), masterKey1);
        DataKey<KmsMasterKey> dataKey2 = new DataKey<>(PLAINTEXT_DATA_KEY, generate(100), KEY_ID_2.getBytes(PROVIDER_ENCODING), masterKey2);

        when(masterKeyProvider.getMasterKeysForEncryption(masterKeyRequestCaptor.capture())).thenReturn(masterKeys);
        when(masterKey1.encryptDataKey(eq(ALGORITHM_SUITE), eq(ENCRYPTION_CONTEXT), dataKeyCaptor.capture()))
                .thenReturn(dataKey1);
        when(masterKey2.encryptDataKey(eq(ALGORITHM_SUITE), eq(ENCRYPTION_CONTEXT), dataKeyCaptor.capture()))
                .thenReturn(dataKey2);
        when(masterKey1.getProviderId()).thenReturn(PROVIDER_1);
        when(masterKey1.getKeyId()).thenReturn(KEY_ID_1);
        when(masterKey2.getProviderId()).thenReturn(PROVIDER_2);
        when(masterKey2.getKeyId()).thenReturn(KEY_ID_2);

        keyring.onEncrypt(encryptionMaterials);

        assertEquals(ENCRYPTION_CONTEXT, masterKeyRequestCaptor.getValue().getEncryptionContext());
        assertEquals(PLAINTEXT_DATA_KEY, dataKeyCaptor.getAllValues().get(0).getKey());
        assertEquals(PLAINTEXT_DATA_KEY, dataKeyCaptor.getAllValues().get(1).getKey());
        assertEncryptedDataKeyEquals(dataKey1, encryptionMaterials.getEncryptedDataKeys().get(0));
        assertEncryptedDataKeyEquals(dataKey2, encryptionMaterials.getEncryptedDataKeys().get(1));
        assertEquals(new KeyringTraceEntry(PROVIDER_1, KEY_ID_1, ENCRYPTED_DATA_KEY, SIGNED_ENCRYPTION_CONTEXT),
                encryptionMaterials.getKeyringTrace().getEntries().get(0));
        assertEquals(new KeyringTraceEntry(PROVIDER_2, KEY_ID_2, ENCRYPTED_DATA_KEY, SIGNED_ENCRYPTION_CONTEXT),
                encryptionMaterials.getKeyringTrace().getEntries().get(1));
    }

    @SuppressWarnings("unchecked")
    @Test
    void testOnEncryptWithNonKmsOrJceMasterKeyProvider() {

        MasterKeyProvider masterKeyProvider = mock(MasterKeyProvider.class);

        EncryptionMaterials encryptionMaterials = EncryptionMaterials.newBuilder(ALGORITHM_SUITE)
                .encryptionContext(ENCRYPTION_CONTEXT)
                .plaintextDataKey(PLAINTEXT_DATA_KEY)
                .build();

        Keyring keyring = new MasterKeyProviderKeyring(masterKeyProvider);

        MasterKey masterKey = mock(MasterKey.class);

        final String KEY_ID = "KeyId1";
        final String PROVIDER = "Provider1";

        DataKey dataKey = new DataKey(PLAINTEXT_DATA_KEY, generate(100), KEY_ID.getBytes(PROVIDER_ENCODING), masterKey);

        when(masterKeyProvider.getMasterKeysForEncryption(isA(MasterKeyRequest.class))).thenReturn(singletonList(masterKey));
        when(masterKey.encryptDataKey(eq(ALGORITHM_SUITE), eq(ENCRYPTION_CONTEXT), isA(DataKey.class)))
                .thenReturn(dataKey);
        when(masterKey.getProviderId()).thenReturn(PROVIDER);
        when(masterKey.getKeyId()).thenReturn(KEY_ID);

        keyring.onEncrypt(encryptionMaterials);

        assertEncryptedDataKeyEquals(dataKey, encryptionMaterials.getEncryptedDataKeys().get(0));
        assertEquals(new KeyringTraceEntry(PROVIDER, KEY_ID, ENCRYPTED_DATA_KEY),
                encryptionMaterials.getKeyringTrace().getEntries().get(0));
    }

    @Test
    void testOnEncryptWithNoMasterKeys() {
        MasterKeyProvider<KmsMasterKey> masterKeyProvider = mock(KmsMasterKeyProvider.class);

        EncryptionMaterials encryptionMaterials = EncryptionMaterials.newBuilder(ALGORITHM_SUITE)
                .encryptionContext(ENCRYPTION_CONTEXT)
                .build();

        Keyring keyring = StandardKeyrings.masterKeyProvider(masterKeyProvider);

        when(masterKeyProvider.getMasterKeysForEncryption(isA(MasterKeyRequest.class))).thenReturn(emptyList());

        assertThrows(AwsCryptoException.class, () -> keyring.onEncrypt(encryptionMaterials));
    }

    @Test
    void testOnDecryptWithPlaintextDataKey() {
        MasterKeyProvider<KmsMasterKey> masterKeyProvider = mock(KmsMasterKeyProvider.class);

        DecryptionMaterials decryptionMaterials = DecryptionMaterials.newBuilder(ALGORITHM_SUITE)
                .encryptionContext(ENCRYPTION_CONTEXT)
                .plaintextDataKey(PLAINTEXT_DATA_KEY)
                .build();

        Keyring keyring = StandardKeyrings.masterKeyProvider(masterKeyProvider);
        keyring.onDecrypt(decryptionMaterials, emptyList());

        assertEquals(PLAINTEXT_DATA_KEY, decryptionMaterials.getPlaintextDataKey());
    }

    @Test
    void testOnDecrypt() {
        MasterKeyProvider<KmsMasterKey> masterKeyProvider = mock(KmsMasterKeyProvider.class);
        KmsMasterKey masterKey = mock(KmsMasterKey.class);

        DecryptionMaterials decryptionMaterials = DecryptionMaterials.newBuilder(ALGORITHM_SUITE)
                .encryptionContext(ENCRYPTION_CONTEXT)
                .build();

        final String KEY_ID = "KeyId1";
        final String PROVIDER = "Provider1";

        EncryptedDataKey encryptedDataKey = new KeyBlob(PROVIDER,
                KEY_ID.getBytes(PROVIDER_ENCODING), generate(ALGORITHM_SUITE.getDataKeyLength()));

        when(masterKeyProvider.decryptDataKey(ALGORITHM_SUITE, singletonList(encryptedDataKey), ENCRYPTION_CONTEXT))
                .thenReturn(new DataKey<>(PLAINTEXT_DATA_KEY, encryptedDataKey.getEncryptedDataKey(),
                        encryptedDataKey.getProviderInformation(), masterKey));
        when(masterKey.getProviderId()).thenReturn(PROVIDER);
        when(masterKey.getKeyId()).thenReturn(KEY_ID);

        Keyring keyring = StandardKeyrings.masterKeyProvider(masterKeyProvider);
        keyring.onDecrypt(decryptionMaterials, singletonList(encryptedDataKey));

        assertEquals(PLAINTEXT_DATA_KEY, decryptionMaterials.getPlaintextDataKey());
        assertEquals(new KeyringTraceEntry(PROVIDER, KEY_ID, DECRYPTED_DATA_KEY, VERIFIED_ENCRYPTION_CONTEXT),
                decryptionMaterials.getKeyringTrace().getEntries().get(0));
    }

    @Test
    void testOnDecryptMasterKeyCannotUnwrapDataKeyException() {
        MasterKeyProvider<KmsMasterKey> masterKeyProvider = mock(KmsMasterKeyProvider.class);

        DecryptionMaterials decryptionMaterials = DecryptionMaterials.newBuilder(ALGORITHM_SUITE)
                .encryptionContext(ENCRYPTION_CONTEXT)
                .build();

        EncryptedDataKey encryptedDataKey = mock(EncryptedDataKey.class);

        when(masterKeyProvider.decryptDataKey(ALGORITHM_SUITE, singletonList(encryptedDataKey), ENCRYPTION_CONTEXT))
                .thenThrow(new CannotUnwrapDataKeyException());

        Keyring keyring = StandardKeyrings.masterKeyProvider(masterKeyProvider);
        keyring.onDecrypt(decryptionMaterials, singletonList(encryptedDataKey));

        assertFalse(decryptionMaterials.hasPlaintextDataKey());
    }

    @Test
    void testOnDecryptMasterKeyOtherException() {
        MasterKeyProvider<KmsMasterKey> masterKeyProvider = mock(KmsMasterKeyProvider.class);

        DecryptionMaterials decryptionMaterials = DecryptionMaterials.newBuilder(ALGORITHM_SUITE)
                .encryptionContext(ENCRYPTION_CONTEXT)
                .build();

        EncryptedDataKey encryptedDataKey = mock(EncryptedDataKey.class);

        when(masterKeyProvider.decryptDataKey(ALGORITHM_SUITE, singletonList(encryptedDataKey), ENCRYPTION_CONTEXT))
                .thenThrow(new AwsCryptoException());

        Keyring keyring = StandardKeyrings.masterKeyProvider(masterKeyProvider);
        assertThrows(AwsCryptoException.class, () -> keyring.onDecrypt(decryptionMaterials, singletonList(encryptedDataKey)));
    }

    @Test
    void testOnDecryptNonVerifiedEncryptionContext() {
        MasterKeyProvider<JceMasterKey> masterKeyProvider = mock(JceMasterKey.class);
        JceMasterKey masterKey = mock(JceMasterKey.class);

        DecryptionMaterials decryptionMaterials = DecryptionMaterials.newBuilder(ALGORITHM_SUITE)
                .encryptionContext(ENCRYPTION_CONTEXT)
                .build();

        final String KEY_ID = "KeyId1";
        final String PROVIDER = "Provider1";

        EncryptedDataKey encryptedDataKey = new KeyBlob(PROVIDER,
                KEY_ID.getBytes(PROVIDER_ENCODING), generate(ALGORITHM_SUITE.getDataKeyLength()));

        when(masterKeyProvider.decryptDataKey(ALGORITHM_SUITE, singletonList(encryptedDataKey), ENCRYPTION_CONTEXT))
                .thenReturn(new DataKey<>(PLAINTEXT_DATA_KEY, encryptedDataKey.getEncryptedDataKey(),
                        encryptedDataKey.getProviderInformation(), masterKey));
        when(masterKey.getProviderId()).thenReturn(PROVIDER);
        when(masterKey.getKeyId()).thenReturn(KEY_ID);
        when(masterKey.isEncryptionContextSigned()).thenReturn(false);

        Keyring keyring = StandardKeyrings.masterKeyProvider(masterKeyProvider);
        keyring.onDecrypt(decryptionMaterials, singletonList(encryptedDataKey));

        assertEquals(PLAINTEXT_DATA_KEY, decryptionMaterials.getPlaintextDataKey());
        assertEquals(new KeyringTraceEntry(PROVIDER, KEY_ID, DECRYPTED_DATA_KEY),
                decryptionMaterials.getKeyringTrace().getEntries().get(0));
    }

    private static void assertEncryptedDataKeyEquals(EncryptedDataKey expected, EncryptedDataKey actual) {
        assertEquals(expected.getProviderId(), actual.getProviderId());
        assertArrayEquals(expected.getProviderInformation(), actual.getProviderInformation());
        assertArrayEquals(expected.getEncryptedDataKey(), actual.getEncryptedDataKey());
    }
}
