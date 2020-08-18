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
import com.amazonaws.encryptionsdk.exception.CannotUnwrapDataKeyException;
import com.amazonaws.encryptionsdk.exception.MismatchedDataKeyException;
import com.amazonaws.encryptionsdk.kms.AwsKmsCmkId;
import com.amazonaws.encryptionsdk.kms.DataKeyEncryptionDao;
import com.amazonaws.encryptionsdk.kms.DataKeyEncryptionDao.DecryptDataKeyResult;
import com.amazonaws.encryptionsdk.model.DecryptionMaterials;
import com.amazonaws.encryptionsdk.model.EncryptionMaterials;
import com.amazonaws.encryptionsdk.model.KeyBlob;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static com.amazonaws.encryptionsdk.EncryptedDataKey.PROVIDER_ENCODING;
import static com.amazonaws.encryptionsdk.internal.Constants.AWS_KMS_PROVIDER_ID;
import static com.amazonaws.encryptionsdk.internal.RandomBytesGenerator.generate;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AwsKmsSymmetricKeyringTest {

    private static final CryptoAlgorithm ALGORITHM_SUITE = CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;
    private static final SecretKey PLAINTEXT_DATA_KEY = new SecretKeySpec(generate(ALGORITHM_SUITE.getDataKeyLength()), ALGORITHM_SUITE.getDataKeyAlgo());
    private static final Map<String, String> ENCRYPTION_CONTEXT = Collections.singletonMap("myKey", "myValue");
    private static final String KEY_ARN = "arn:aws:kms:us-east-1:999999999999:key/key1-23bv-sdfs-werw-234323nfdsf";
    private static final String FAILING_KEY_ARN = "arn:aws:kms:us-east-1:999999999999:key/key2-02ds-wvjs-aswe-a4923489273";
    private static final AwsKmsCmkId KEY_NAME = AwsKmsCmkId.fromString(KEY_ARN);
    private static final EncryptedDataKey ENCRYPTED_KEY = new KeyBlob(AWS_KMS_PROVIDER_ID,
        KEY_ARN.getBytes(PROVIDER_ENCODING), generate(ALGORITHM_SUITE.getDataKeyLength()));
    private static final EncryptedDataKey FAILING_ENCRYPTED_KEY = new KeyBlob(AWS_KMS_PROVIDER_ID,
        FAILING_KEY_ARN.getBytes(PROVIDER_ENCODING), generate(ALGORITHM_SUITE.getDataKeyLength()));

    @Mock(lenient = true)
    private DataKeyEncryptionDao dataKeyEncryptionDao;
    private Keyring keyring;

    @BeforeEach
    void setup() {
        when(dataKeyEncryptionDao.encryptDataKey(KEY_NAME, PLAINTEXT_DATA_KEY, ENCRYPTION_CONTEXT)).thenReturn(ENCRYPTED_KEY);
        when(dataKeyEncryptionDao.decryptDataKey(ENCRYPTED_KEY, ALGORITHM_SUITE, ENCRYPTION_CONTEXT))
            .thenReturn(new DecryptDataKeyResult(KEY_ARN, PLAINTEXT_DATA_KEY));

        keyring = new AwsKmsSymmetricKeyring(dataKeyEncryptionDao, KEY_NAME);
    }

    @Test
    void testMalformedArns() {
        DecryptionMaterials decryptionMaterials = DecryptionMaterials.newBuilder()
            .setAlgorithm(ALGORITHM_SUITE)
            .setEncryptionContext(ENCRYPTION_CONTEXT)
            .build();

        List<EncryptedDataKey> encryptedDataKeys = new ArrayList<>();
        encryptedDataKeys.add(new KeyBlob(AWS_KMS_PROVIDER_ID, "arn:badArn".getBytes(PROVIDER_ENCODING), new byte[]{}));
        encryptedDataKeys.add(ENCRYPTED_KEY);

        decryptionMaterials = keyring.onDecrypt(decryptionMaterials, encryptedDataKeys);
        assertEquals(PLAINTEXT_DATA_KEY, decryptionMaterials.getCleartextDataKey());

        decryptionMaterials = DecryptionMaterials.newBuilder()
            .setAlgorithm(ALGORITHM_SUITE)
            .setEncryptionContext(ENCRYPTION_CONTEXT)
            .build();

        // Malformed Arn for a non KMS provider shouldn't fail
        encryptedDataKeys.clear();
        encryptedDataKeys.add(new KeyBlob("OtherProviderId", "arn:badArn".getBytes(PROVIDER_ENCODING), new byte[]{}));
        assertFalse(keyring.onDecrypt(decryptionMaterials, encryptedDataKeys).hasCleartextDataKey());
    }

    @Test
    void testNullDao() {
        assertThrows(
            NullPointerException.class,
            () -> new AwsKmsSymmetricKeyring(null, KEY_NAME),
            "dataKeyEncryptionDao is required");
    }

    @Test
    void testNullKeyName() {
        assertThrows(
            NullPointerException.class,
            () -> new AwsKmsSymmetricKeyring(dataKeyEncryptionDao, null),
            "keyName is required");
    }

    @Test
    void testEncryptDecryptExistingDataKey() {
        EncryptionMaterials encryptionMaterials = EncryptionMaterials.newBuilder()
            .setAlgorithm(ALGORITHM_SUITE)
            .setCleartextDataKey(PLAINTEXT_DATA_KEY)
            .setEncryptionContext(ENCRYPTION_CONTEXT)
            .build();

        encryptionMaterials = keyring.onEncrypt(encryptionMaterials);

        assertEquals(1, encryptionMaterials.getEncryptedDataKeys().size());
        assertEncryptedDataKeyEquals(ENCRYPTED_KEY, encryptionMaterials.getEncryptedDataKeys().get(0));

        DecryptionMaterials decryptionMaterials = DecryptionMaterials.newBuilder()
            .setAlgorithm(ALGORITHM_SUITE)
            .setEncryptionContext(ENCRYPTION_CONTEXT)
            .build();

        List<EncryptedDataKey> encryptedDataKeys = new ArrayList<>();
        encryptedDataKeys.add(ENCRYPTED_KEY);
        decryptionMaterials = keyring.onDecrypt(decryptionMaterials, encryptedDataKeys);

        assertEquals(PLAINTEXT_DATA_KEY, decryptionMaterials.getCleartextDataKey());
    }

    @Test
    void testGenerateEncryptDecryptDataKey() {
        EncryptionMaterials encryptionMaterials = EncryptionMaterials.newBuilder()
            .setAlgorithm(ALGORITHM_SUITE)
            .setEncryptionContext(ENCRYPTION_CONTEXT)
            .build();

        when(dataKeyEncryptionDao.generateDataKey(KEY_NAME, ALGORITHM_SUITE, ENCRYPTION_CONTEXT))
            .thenReturn(new DataKeyEncryptionDao.GenerateDataKeyResult(PLAINTEXT_DATA_KEY, ENCRYPTED_KEY));
        encryptionMaterials = keyring.onEncrypt(encryptionMaterials);

        assertEquals(PLAINTEXT_DATA_KEY, encryptionMaterials.getCleartextDataKey());

        DecryptionMaterials decryptionMaterials = DecryptionMaterials.newBuilder()
            .setAlgorithm(ALGORITHM_SUITE)
            .setEncryptionContext(ENCRYPTION_CONTEXT)
            .build();

        List<EncryptedDataKey> encryptedDataKeys = new ArrayList<>();
        encryptedDataKeys.add(ENCRYPTED_KEY);
        decryptionMaterials = keyring.onDecrypt(decryptionMaterials, encryptedDataKeys);

        assertEquals(PLAINTEXT_DATA_KEY, decryptionMaterials.getCleartextDataKey());
    }

    @Test
    void testDecryptFirstKeyFails() {
        DecryptionMaterials decryptionMaterials = DecryptionMaterials.newBuilder()
            .setAlgorithm(ALGORITHM_SUITE)
            .setEncryptionContext(ENCRYPTION_CONTEXT)
            .build();

        List<EncryptedDataKey> encryptedDataKeys = new ArrayList<>();
        encryptedDataKeys.add(FAILING_ENCRYPTED_KEY);
        encryptedDataKeys.add(ENCRYPTED_KEY);
        decryptionMaterials = keyring.onDecrypt(decryptionMaterials, encryptedDataKeys);

        assertEquals(PLAINTEXT_DATA_KEY, decryptionMaterials.getCleartextDataKey());
    }

    @Test
    void testDecryptIncorrectKeyName() {
        DecryptionMaterials decryptionMaterials = DecryptionMaterials.newBuilder()
            .setAlgorithm(ALGORITHM_SUITE)
            .setEncryptionContext(ENCRYPTION_CONTEXT)
            .build();

        List<EncryptedDataKey> encryptedDataKeys = new ArrayList<>();
        encryptedDataKeys.add(FAILING_ENCRYPTED_KEY);
        decryptionMaterials = keyring.onDecrypt(decryptionMaterials, encryptedDataKeys);

        assertFalse(decryptionMaterials.hasCleartextDataKey());
    }

    @Test
    void testDecryptMismatchedDataKeyException() {
        DecryptionMaterials decryptionMaterials = DecryptionMaterials.newBuilder()
            .setAlgorithm(ALGORITHM_SUITE)
            .setEncryptionContext(ENCRYPTION_CONTEXT)
            .build();

        when(dataKeyEncryptionDao.decryptDataKey(ENCRYPTED_KEY, ALGORITHM_SUITE, ENCRYPTION_CONTEXT)).thenThrow(new MismatchedDataKeyException());

        assertThrows(MismatchedDataKeyException.class, () -> keyring.onDecrypt(decryptionMaterials, Collections.singletonList(ENCRYPTED_KEY)));
    }

    @Test
    void testDecryptWrongProvider() {
        DecryptionMaterials decryptionMaterials = DecryptionMaterials.newBuilder()
            .setAlgorithm(ALGORITHM_SUITE)
            .setEncryptionContext(ENCRYPTION_CONTEXT)
            .build();

        EncryptedDataKey wrongProviderKey = new KeyBlob("OtherProvider", FAILING_KEY_ARN.getBytes(PROVIDER_ENCODING), new byte[]{});

        List<EncryptedDataKey> encryptedDataKeys = new ArrayList<>();
        encryptedDataKeys.add(wrongProviderKey);
        decryptionMaterials = keyring.onDecrypt(decryptionMaterials, encryptedDataKeys);

        assertFalse(decryptionMaterials.hasCleartextDataKey());
    }

    @Test
    void testDecryptAlreadyDecryptedDataKey() {
        DecryptionMaterials decryptionMaterials = DecryptionMaterials.newBuilder()
            .setAlgorithm(ALGORITHM_SUITE)
            .setCleartextDataKey(PLAINTEXT_DATA_KEY)
            .setEncryptionContext(ENCRYPTION_CONTEXT)
            .build();

        decryptionMaterials = keyring.onDecrypt(decryptionMaterials, Collections.singletonList(ENCRYPTED_KEY));

        assertEquals(PLAINTEXT_DATA_KEY, decryptionMaterials.getCleartextDataKey());
    }

    @Test
    void testDecryptCannotUnwrapDataKey() {
        DecryptionMaterials decryptionMaterials = DecryptionMaterials.newBuilder()
            .setAlgorithm(ALGORITHM_SUITE)
            .setEncryptionContext(ENCRYPTION_CONTEXT)
            .build();

        when(dataKeyEncryptionDao.decryptDataKey(ENCRYPTED_KEY, ALGORITHM_SUITE, ENCRYPTION_CONTEXT)).thenThrow(new CannotUnwrapDataKeyException());

        List<EncryptedDataKey> encryptedDataKeys = new ArrayList<>();
        encryptedDataKeys.add(ENCRYPTED_KEY);
        assertThrows(CannotUnwrapDataKeyException.class, () -> keyring.onDecrypt(decryptionMaterials, encryptedDataKeys));

    }

    @Test
    void testDecryptNoDataKey() {
        DecryptionMaterials decryptionMaterials = DecryptionMaterials.newBuilder()
            .setAlgorithm(ALGORITHM_SUITE)
            .setEncryptionContext(ENCRYPTION_CONTEXT)
            .build();

        decryptionMaterials = keyring.onDecrypt(decryptionMaterials, Collections.emptyList());

        assertFalse(decryptionMaterials.hasCleartextDataKey());
    }

    private void assertEncryptedDataKeyEquals(EncryptedDataKey expected, EncryptedDataKey actual) {
        assertEquals(expected.getProviderId(), actual.getProviderId());
        assertArrayEquals(expected.getProviderInformation(), actual.getProviderInformation());
        assertArrayEquals(expected.getEncryptedDataKey(), actual.getEncryptedDataKey());
    }
}
