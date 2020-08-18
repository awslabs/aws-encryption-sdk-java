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
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.CannotUnwrapDataKeyException;
import com.amazonaws.encryptionsdk.exception.MismatchedDataKeyException;
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
class AwsKmsSymmetricRegionDiscoveryKeyringTest {

    private static final CryptoAlgorithm ALGORITHM_SUITE = CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;
    private static final SecretKey PLAINTEXT_DATA_KEY_1 = new SecretKeySpec(generate(ALGORITHM_SUITE.getDataKeyLength()), ALGORITHM_SUITE.getDataKeyAlgo());
    private static final SecretKey PLAINTEXT_DATA_KEY_2 = new SecretKeySpec(generate(ALGORITHM_SUITE.getDataKeyLength()), ALGORITHM_SUITE.getDataKeyAlgo());
    private static final SecretKey PLAINTEXT_DATA_KEY_DIFFERENT_ACCOUNT_ID = new SecretKeySpec(generate(ALGORITHM_SUITE.getDataKeyLength()), ALGORITHM_SUITE.getDataKeyAlgo());
    private static final Map<String, String> ENCRYPTION_CONTEXT = Collections.singletonMap("myKey", "myValue");
    private static final String KEY_NAME_1 = "arn:aws:kms:us-east-1:999999999999:key/key1-23bv-sdfs-werw-234323nfdsf";
    private static final String KEY_NAME_2 = "arn:aws:kms:us-east-1:999999999999:key/key2-02ds-wvjs-aswe-a4923489273";
    private static final String DIFFERENT_REGION_KEY_NAME = "arn:aws:kms:us-west-2:999999999999:key/key2-02ds-wvjs-aswe-a4923489273";
    private static final String DIFFERENT_AWS_ACCOUNT_ID_KEY_NAME = "arn:aws:kms:us-east-1:000000000000:key/key2-02ds-wvjs-aswe-a4923489273";
    private static final String AWS_ACCOUNT_ID = "999999999999";
    private static final String AWS_REGION = "us-east-1";
    private static final EncryptedDataKey ENCRYPTED_KEY_1 = new KeyBlob(AWS_KMS_PROVIDER_ID,
        KEY_NAME_1.getBytes(PROVIDER_ENCODING), generate(ALGORITHM_SUITE.getDataKeyLength()));
    private static final EncryptedDataKey ENCRYPTED_KEY_2 = new KeyBlob(AWS_KMS_PROVIDER_ID,
        KEY_NAME_2.getBytes(PROVIDER_ENCODING), generate(ALGORITHM_SUITE.getDataKeyLength()));
    private static final EncryptedDataKey ENCRYPTED_DIFFERENT_REGION_KEY = new KeyBlob(AWS_KMS_PROVIDER_ID,
        DIFFERENT_REGION_KEY_NAME.getBytes(PROVIDER_ENCODING), generate(ALGORITHM_SUITE.getDataKeyLength()));
    private static final EncryptedDataKey ENCRYPTED_DIFFERENT_AWS_ACCOUNT_ID_KEY = new KeyBlob(AWS_KMS_PROVIDER_ID,
        DIFFERENT_AWS_ACCOUNT_ID_KEY_NAME.getBytes(PROVIDER_ENCODING), generate(ALGORITHM_SUITE.getDataKeyLength()));
    @Mock(lenient = true)
    private DataKeyEncryptionDao dataKeyEncryptionDao;
    private Keyring keyring;

    @BeforeEach
    void setup() {
        when(dataKeyEncryptionDao.decryptDataKey(ENCRYPTED_KEY_1, ALGORITHM_SUITE, ENCRYPTION_CONTEXT))
            .thenReturn(new DecryptDataKeyResult(KEY_NAME_1, PLAINTEXT_DATA_KEY_1));
        when(dataKeyEncryptionDao.decryptDataKey(ENCRYPTED_KEY_2, ALGORITHM_SUITE, ENCRYPTION_CONTEXT))
            .thenReturn(new DecryptDataKeyResult(KEY_NAME_2, PLAINTEXT_DATA_KEY_2));
        when(dataKeyEncryptionDao.decryptDataKey(ENCRYPTED_DIFFERENT_AWS_ACCOUNT_ID_KEY, ALGORITHM_SUITE, ENCRYPTION_CONTEXT))
            .thenReturn(new DecryptDataKeyResult(DIFFERENT_AWS_ACCOUNT_ID_KEY_NAME, PLAINTEXT_DATA_KEY_DIFFERENT_ACCOUNT_ID));
        keyring = new AwsKmsSymmetricRegionDiscoveryKeyring(dataKeyEncryptionDao, AWS_REGION, AWS_ACCOUNT_ID);
    }

    @Test
    void testMalformedArns() {
        DecryptionMaterials decryptionMaterials = DecryptionMaterials.newBuilder()
            .setAlgorithm(ALGORITHM_SUITE)
            .setEncryptionContext(ENCRYPTION_CONTEXT)
            .build();

        List<EncryptedDataKey> encryptedDataKeys = new ArrayList<>();
        encryptedDataKeys.add(new KeyBlob(AWS_KMS_PROVIDER_ID, "arn:badArn".getBytes(PROVIDER_ENCODING), new byte[]{}));
        encryptedDataKeys.add(ENCRYPTED_KEY_1);

        decryptionMaterials = keyring.onDecrypt(decryptionMaterials, encryptedDataKeys);
        assertEquals(PLAINTEXT_DATA_KEY_1, decryptionMaterials.getCleartextDataKey());

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
            () -> new AwsKmsSymmetricRegionDiscoveryKeyring(null, AWS_REGION, null),
            "dataKeyEncryptionDao is required");
    }

    @Test
    void testNullKeyName() {
        assertThrows(
            NullPointerException.class,
            () -> new AwsKmsSymmetricRegionDiscoveryKeyring(dataKeyEncryptionDao, null, null),
            "AWS region is required");
    }

    @Test
    void testEncrypt() {
        EncryptionMaterials encryptionMaterials = EncryptionMaterials.newBuilder()
            .setAlgorithm(ALGORITHM_SUITE)
            .setCleartextDataKey(PLAINTEXT_DATA_KEY_1)
            .setEncryptionContext(ENCRYPTION_CONTEXT)
            .build();

        assertThrows(
            AwsCryptoException.class,
            () -> keyring.onEncrypt(encryptionMaterials),
            "The AWS KMS Region Discovery keyring cannot be used for encryption");
    }

    @Test
    void testDecrypt() {
        DecryptionMaterials decryptionMaterials = DecryptionMaterials.newBuilder()
            .setAlgorithm(ALGORITHM_SUITE)
            .setEncryptionContext(ENCRYPTION_CONTEXT)
            .build();

        List<EncryptedDataKey> encryptedDataKeys = new ArrayList<>();
        encryptedDataKeys.add(ENCRYPTED_KEY_1);
        encryptedDataKeys.add(ENCRYPTED_KEY_2);
        decryptionMaterials = keyring.onDecrypt(decryptionMaterials, encryptedDataKeys);

        assertEquals(PLAINTEXT_DATA_KEY_1, decryptionMaterials.getCleartextDataKey());
    }

    @Test
    void testDecryptFirstKeyFails() {
        DecryptionMaterials decryptionMaterials = DecryptionMaterials.newBuilder()
            .setAlgorithm(ALGORITHM_SUITE)
            .setEncryptionContext(ENCRYPTION_CONTEXT)
            .build();

        when(dataKeyEncryptionDao.decryptDataKey(ENCRYPTED_KEY_1, ALGORITHM_SUITE, ENCRYPTION_CONTEXT)).thenThrow(new CannotUnwrapDataKeyException());

        List<EncryptedDataKey> encryptedDataKeys = new ArrayList<>();
        encryptedDataKeys.add(ENCRYPTED_KEY_1);
        encryptedDataKeys.add(ENCRYPTED_KEY_2);
        decryptionMaterials = keyring.onDecrypt(decryptionMaterials, encryptedDataKeys);

        assertEquals(PLAINTEXT_DATA_KEY_2, decryptionMaterials.getCleartextDataKey());
    }

    @Test
    void testDecryptCannotUnwrap() {
        DecryptionMaterials decryptionMaterials = DecryptionMaterials.newBuilder()
            .setAlgorithm(ALGORITHM_SUITE)
            .setEncryptionContext(ENCRYPTION_CONTEXT)
            .build();

        when(dataKeyEncryptionDao.decryptDataKey(ENCRYPTED_KEY_1, ALGORITHM_SUITE, ENCRYPTION_CONTEXT)).thenThrow(new CannotUnwrapDataKeyException());

        List<EncryptedDataKey> encryptedDataKeys = new ArrayList<>();
        encryptedDataKeys.add(ENCRYPTED_KEY_1);
        decryptionMaterials = keyring.onDecrypt(decryptionMaterials, encryptedDataKeys);

        assertFalse(decryptionMaterials.hasCleartextDataKey());
    }

    @Test
    void testDecryptIncorrectAccountId() {
        DecryptionMaterials decryptionMaterials = DecryptionMaterials.newBuilder()
            .setAlgorithm(ALGORITHM_SUITE)
            .setEncryptionContext(ENCRYPTION_CONTEXT)
            .build();

        List<EncryptedDataKey> encryptedDataKeys = new ArrayList<>();
        encryptedDataKeys.add(ENCRYPTED_DIFFERENT_AWS_ACCOUNT_ID_KEY);
        decryptionMaterials = keyring.onDecrypt(decryptionMaterials, encryptedDataKeys);

        assertFalse(decryptionMaterials.hasCleartextDataKey());
    }

    @Test
    void testDecryptNoAwsAccountIdRequirement() {
        final Keyring noAwsAccountIdCheckDiscoveryKeyring = new AwsKmsSymmetricRegionDiscoveryKeyring(dataKeyEncryptionDao, AWS_REGION, null);
        DecryptionMaterials decryptionMaterials = DecryptionMaterials.newBuilder()
            .setAlgorithm(ALGORITHM_SUITE)
            .setEncryptionContext(ENCRYPTION_CONTEXT)
            .build();

        List<EncryptedDataKey> encryptedDataKeys = new ArrayList<>();
        encryptedDataKeys.add(ENCRYPTED_DIFFERENT_AWS_ACCOUNT_ID_KEY);
        encryptedDataKeys.add(ENCRYPTED_KEY_2);
        decryptionMaterials = noAwsAccountIdCheckDiscoveryKeyring.onDecrypt(decryptionMaterials, encryptedDataKeys);

        assertEquals(PLAINTEXT_DATA_KEY_DIFFERENT_ACCOUNT_ID, decryptionMaterials.getCleartextDataKey());
    }

    @Test
    void testDecryptIncorrectRegion() {
        DecryptionMaterials decryptionMaterials = DecryptionMaterials.newBuilder()
            .setAlgorithm(ALGORITHM_SUITE)
            .setEncryptionContext(ENCRYPTION_CONTEXT)
            .build();

        List<EncryptedDataKey> encryptedDataKeys = new ArrayList<>();
        encryptedDataKeys.add(ENCRYPTED_DIFFERENT_REGION_KEY);
        decryptionMaterials = keyring.onDecrypt(decryptionMaterials, encryptedDataKeys);

        assertFalse(decryptionMaterials.hasCleartextDataKey());
    }

    @Test
    void testDecryptMismatchedDataKeyException() {
        DecryptionMaterials decryptionMaterials = DecryptionMaterials.newBuilder()
            .setAlgorithm(ALGORITHM_SUITE)
            .setEncryptionContext(ENCRYPTION_CONTEXT)
            .build();

        when(dataKeyEncryptionDao.decryptDataKey(ENCRYPTED_KEY_1, ALGORITHM_SUITE, ENCRYPTION_CONTEXT)).thenThrow(new MismatchedDataKeyException());

        assertThrows(MismatchedDataKeyException.class, () -> keyring.onDecrypt(decryptionMaterials, Collections.singletonList(ENCRYPTED_KEY_1)));
    }

    @Test
    void testDecryptWrongProvider() {
        DecryptionMaterials decryptionMaterials = DecryptionMaterials.newBuilder()
            .setAlgorithm(ALGORITHM_SUITE)
            .setEncryptionContext(ENCRYPTION_CONTEXT)
            .build();

        EncryptedDataKey wrongProviderKey = new KeyBlob("OtherProvider", KEY_NAME_1.getBytes(PROVIDER_ENCODING), new byte[]{});

        List<EncryptedDataKey> encryptedDataKeys = new ArrayList<>();
        encryptedDataKeys.add(wrongProviderKey);
        decryptionMaterials = keyring.onDecrypt(decryptionMaterials, encryptedDataKeys);

        assertFalse(decryptionMaterials.hasCleartextDataKey());
    }

    @Test
    void testDecryptNotARN() {
        DecryptionMaterials decryptionMaterials = DecryptionMaterials.newBuilder()
            .setAlgorithm(ALGORITHM_SUITE)
            .setEncryptionContext(ENCRYPTION_CONTEXT)
            .build();

        EncryptedDataKey notArnKey = new KeyBlob(
            AWS_KMS_PROVIDER_ID,
            "notanARN".getBytes(PROVIDER_ENCODING),
            generate(ALGORITHM_SUITE.getDataKeyLength()));

        List<EncryptedDataKey> encryptedDataKeys = new ArrayList<>();
        encryptedDataKeys.add(notArnKey);
        decryptionMaterials = keyring.onDecrypt(decryptionMaterials, encryptedDataKeys);

        assertFalse(decryptionMaterials.hasCleartextDataKey());
    }

    @Test
    void testDecryptAlreadyDecryptedDataKey() {
        DecryptionMaterials decryptionMaterials = DecryptionMaterials.newBuilder()
            .setAlgorithm(ALGORITHM_SUITE)
            .setCleartextDataKey(PLAINTEXT_DATA_KEY_1)
            .setEncryptionContext(ENCRYPTION_CONTEXT)
            .build();

        decryptionMaterials = keyring.onDecrypt(decryptionMaterials, Collections.singletonList(ENCRYPTED_KEY_1));

        assertEquals(PLAINTEXT_DATA_KEY_1, decryptionMaterials.getCleartextDataKey());
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
}
