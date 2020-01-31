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

package com.amazonaws.encryptionsdk.kms;

import com.amazonaws.AmazonWebServiceRequest;
import com.amazonaws.RequestClientOptions;
import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.EncryptedDataKey;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.MismatchedDataKeyException;
import com.amazonaws.encryptionsdk.exception.UnsupportedRegionException;
import com.amazonaws.encryptionsdk.internal.VersionInfo;
import com.amazonaws.encryptionsdk.model.KeyBlob;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.DecryptResult;
import com.amazonaws.services.kms.model.EncryptRequest;
import com.amazonaws.services.kms.model.GenerateDataKeyRequest;
import com.amazonaws.services.kms.model.KMSInvalidStateException;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static com.amazonaws.encryptionsdk.internal.RandomBytesGenerator.generate;
import static com.amazonaws.encryptionsdk.internal.Constants.AWS_KMS_PROVIDER_ID;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AwsKmsDataKeyEncryptionDaoTest {

    private static final CryptoAlgorithm ALGORITHM_SUITE = CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;
    private static final SecretKey DATA_KEY = new SecretKeySpec(generate(ALGORITHM_SUITE.getDataKeyLength()), ALGORITHM_SUITE.getDataKeyAlgo());
    private static final List<String> GRANT_TOKENS = Collections.singletonList("testGrantToken");
    private static final Map<String, String> ENCRYPTION_CONTEXT = Collections.singletonMap("myKey", "myValue");
    private static final EncryptedDataKey ENCRYPTED_DATA_KEY = new KeyBlob(AWS_KMS_PROVIDER_ID,
            "arn:aws:kms:us-east-1:999999999999:key/01234567-89ab-cdef-fedc-ba9876543210".getBytes(EncryptedDataKey.PROVIDER_ENCODING), generate(ALGORITHM_SUITE.getDataKeyLength()));

    @Test
    void testEncryptAndDecrypt() {
        AWSKMS client = spy(new MockKMSClient());
        DataKeyEncryptionDao dao = new AwsKmsDataKeyEncryptionDao(s -> client, GRANT_TOKENS);

        String keyId = client.createKey().getKeyMetadata().getArn();
        EncryptedDataKey encryptedDataKeyResult = dao.encryptDataKey(
                AwsKmsCmkId.fromString(keyId), DATA_KEY, ENCRYPTION_CONTEXT);

        ArgumentCaptor<EncryptRequest> er = ArgumentCaptor.forClass(EncryptRequest.class);
        verify(client, times(1)).encrypt(er.capture());

        EncryptRequest actualRequest = er.getValue();

        assertEquals(keyId, actualRequest.getKeyId());
        assertEquals(GRANT_TOKENS, actualRequest.getGrantTokens());
        assertEquals(ENCRYPTION_CONTEXT, actualRequest.getEncryptionContext());
        assertArrayEquals(DATA_KEY.getEncoded(), actualRequest.getPlaintext().array());
        assertUserAgent(actualRequest);

        assertEquals(AWS_KMS_PROVIDER_ID, encryptedDataKeyResult.getProviderId());
        assertArrayEquals(keyId.getBytes(EncryptedDataKey.PROVIDER_ENCODING), encryptedDataKeyResult.getProviderInformation());
        assertNotNull(encryptedDataKeyResult.getEncryptedDataKey());

        DataKeyEncryptionDao.DecryptDataKeyResult decryptDataKeyResult = dao.decryptDataKey(encryptedDataKeyResult, ALGORITHM_SUITE, ENCRYPTION_CONTEXT);

        ArgumentCaptor<DecryptRequest> decrypt = ArgumentCaptor.forClass(DecryptRequest.class);
        verify(client, times(1)).decrypt(decrypt.capture());

        DecryptRequest actualDecryptRequest = decrypt.getValue();
        assertEquals(GRANT_TOKENS, actualDecryptRequest.getGrantTokens());
        assertEquals(ENCRYPTION_CONTEXT, actualDecryptRequest.getEncryptionContext());
        assertArrayEquals(encryptedDataKeyResult.getEncryptedDataKey(), actualDecryptRequest.getCiphertextBlob().array());
        assertUserAgent(actualDecryptRequest);

        assertEquals(DATA_KEY, decryptDataKeyResult.getPlaintextDataKey());
        assertEquals(keyId, decryptDataKeyResult.getKeyArn());
    }

    @Test
    void testGenerateAndDecrypt() {
        AWSKMS client = spy(new MockKMSClient());
        DataKeyEncryptionDao dao = new AwsKmsDataKeyEncryptionDao(s -> client, GRANT_TOKENS);

        String keyId = client.createKey().getKeyMetadata().getArn();
        DataKeyEncryptionDao.GenerateDataKeyResult generateDataKeyResult = dao.generateDataKey(
                AwsKmsCmkId.fromString(keyId), ALGORITHM_SUITE, ENCRYPTION_CONTEXT);

        ArgumentCaptor<GenerateDataKeyRequest> gr = ArgumentCaptor.forClass(GenerateDataKeyRequest.class);
        verify(client, times(1)).generateDataKey(gr.capture());

        GenerateDataKeyRequest actualRequest = gr.getValue();

        assertEquals(keyId, actualRequest.getKeyId());
        assertEquals(GRANT_TOKENS, actualRequest.getGrantTokens());
        assertEquals(ENCRYPTION_CONTEXT, actualRequest.getEncryptionContext());
        assertEquals(ALGORITHM_SUITE.getDataKeyLength(), actualRequest.getNumberOfBytes());
        assertUserAgent(actualRequest);

        assertNotNull(generateDataKeyResult.getPlaintextDataKey());
        assertEquals(ALGORITHM_SUITE.getDataKeyLength(), generateDataKeyResult.getPlaintextDataKey().getEncoded().length);
        assertEquals(ALGORITHM_SUITE.getDataKeyAlgo(), generateDataKeyResult.getPlaintextDataKey().getAlgorithm());
        assertNotNull(generateDataKeyResult.getEncryptedDataKey());

        DataKeyEncryptionDao.DecryptDataKeyResult decryptDataKeyResult = dao.decryptDataKey(generateDataKeyResult.getEncryptedDataKey(), ALGORITHM_SUITE, ENCRYPTION_CONTEXT);

        ArgumentCaptor<DecryptRequest> decrypt = ArgumentCaptor.forClass(DecryptRequest.class);
        verify(client, times(1)).decrypt(decrypt.capture());

        DecryptRequest actualDecryptRequest = decrypt.getValue();
        assertEquals(GRANT_TOKENS, actualDecryptRequest.getGrantTokens());
        assertEquals(ENCRYPTION_CONTEXT, actualDecryptRequest.getEncryptionContext());
        assertArrayEquals(generateDataKeyResult.getEncryptedDataKey().getEncryptedDataKey(), actualDecryptRequest.getCiphertextBlob().array());
        assertUserAgent(actualDecryptRequest);

        assertEquals(generateDataKeyResult.getPlaintextDataKey(), decryptDataKeyResult.getPlaintextDataKey());
        assertEquals(keyId, decryptDataKeyResult.getKeyArn());
    }

    @Test
    void testEncryptWithRawKeyId() {
        AWSKMS client = spy(new MockKMSClient());
        DataKeyEncryptionDao dao = new AwsKmsDataKeyEncryptionDao(s -> client, GRANT_TOKENS);

        String keyId = client.createKey().getKeyMetadata().getArn();
        String rawKeyId = keyId.split("/")[1];
        EncryptedDataKey encryptedDataKeyResult = dao.encryptDataKey(
                AwsKmsCmkId.fromString(rawKeyId), DATA_KEY, ENCRYPTION_CONTEXT);

        ArgumentCaptor<EncryptRequest> er = ArgumentCaptor.forClass(EncryptRequest.class);
        verify(client, times(1)).encrypt(er.capture());

        EncryptRequest actualRequest = er.getValue();

        assertEquals(rawKeyId, actualRequest.getKeyId());
        assertEquals(GRANT_TOKENS, actualRequest.getGrantTokens());
        assertEquals(ENCRYPTION_CONTEXT, actualRequest.getEncryptionContext());
        assertArrayEquals(DATA_KEY.getEncoded(), actualRequest.getPlaintext().array());
        assertUserAgent(actualRequest);

        assertEquals(AWS_KMS_PROVIDER_ID, encryptedDataKeyResult.getProviderId());
        assertArrayEquals(keyId.getBytes(EncryptedDataKey.PROVIDER_ENCODING), encryptedDataKeyResult.getProviderInformation());
        assertNotNull(encryptedDataKeyResult.getEncryptedDataKey());
    }

    @Test
    void testEncryptWrongKeyFormat() {
        SecretKey key = mock(SecretKey.class);
        when(key.getFormat()).thenReturn("BadFormat");

        AWSKMS client = spy(new MockKMSClient());
        DataKeyEncryptionDao dao = new AwsKmsDataKeyEncryptionDao(s -> client, GRANT_TOKENS);

        String keyId = client.createKey().getKeyMetadata().getArn();

        assertThrows(IllegalArgumentException.class, () -> dao.encryptDataKey(
                AwsKmsCmkId.fromString(keyId), key, ENCRYPTION_CONTEXT));
    }

    @Test
    void testKmsFailure() {
        AWSKMS client = spy(new MockKMSClient());
        DataKeyEncryptionDao dao = new AwsKmsDataKeyEncryptionDao(s -> client, GRANT_TOKENS);

        String keyId = client.createKey().getKeyMetadata().getArn();
        doThrow(new KMSInvalidStateException("fail")).when(client).generateDataKey(isA(GenerateDataKeyRequest.class));
        doThrow(new KMSInvalidStateException("fail")).when(client).encrypt(isA(EncryptRequest.class));
        doThrow(new KMSInvalidStateException("fail")).when(client).decrypt(isA(DecryptRequest.class));

        assertThrows(AwsCryptoException.class, () -> dao.generateDataKey(
                AwsKmsCmkId.fromString(keyId), ALGORITHM_SUITE, ENCRYPTION_CONTEXT));
        assertThrows(AwsCryptoException.class, () -> dao.encryptDataKey(
                AwsKmsCmkId.fromString(keyId), DATA_KEY, ENCRYPTION_CONTEXT));
        assertThrows(AwsCryptoException.class, () -> dao.decryptDataKey(ENCRYPTED_DATA_KEY, ALGORITHM_SUITE, ENCRYPTION_CONTEXT));
    }

    @Test
    void testUnsupportedRegionException() {
        AWSKMS client = spy(new MockKMSClient());
        DataKeyEncryptionDao dao = new AwsKmsDataKeyEncryptionDao(s -> client, GRANT_TOKENS);

        String keyId = client.createKey().getKeyMetadata().getArn();
        doThrow(new UnsupportedRegionException("fail")).when(client).generateDataKey(isA(GenerateDataKeyRequest.class));
        doThrow(new UnsupportedRegionException("fail")).when(client).encrypt(isA(EncryptRequest.class));
        doThrow(new UnsupportedRegionException("fail")).when(client).decrypt(isA(DecryptRequest.class));

        assertThrows(AwsCryptoException.class, () -> dao.generateDataKey(
                AwsKmsCmkId.fromString(keyId), ALGORITHM_SUITE, ENCRYPTION_CONTEXT));
        assertThrows(AwsCryptoException.class, () -> dao.encryptDataKey(
                AwsKmsCmkId.fromString(keyId), DATA_KEY, ENCRYPTION_CONTEXT));
        assertThrows(AwsCryptoException.class, () -> dao.decryptDataKey(ENCRYPTED_DATA_KEY, ALGORITHM_SUITE, ENCRYPTION_CONTEXT));
    }

    @Test
    void testDecryptBadKmsKeyId() {
        AWSKMS client = spy(new MockKMSClient());
        DataKeyEncryptionDao dao = new AwsKmsDataKeyEncryptionDao(s -> client, GRANT_TOKENS);

        DecryptResult badResult = new DecryptResult();
        badResult.setKeyId("badKeyId");

        doReturn(badResult).when(client).decrypt(isA(DecryptRequest.class));

        assertThrows(MismatchedDataKeyException.class, () -> dao.decryptDataKey(ENCRYPTED_DATA_KEY, ALGORITHM_SUITE, ENCRYPTION_CONTEXT));
    }

    @Test
    void testDecryptBadKmsKeyLength() {
        AWSKMS client = spy(new MockKMSClient());
        DataKeyEncryptionDao dao = new AwsKmsDataKeyEncryptionDao(s -> client, GRANT_TOKENS);

        DecryptResult badResult = new DecryptResult();
        badResult.setKeyId(new String(ENCRYPTED_DATA_KEY.getProviderInformation(), EncryptedDataKey.PROVIDER_ENCODING));
        badResult.setPlaintext(ByteBuffer.allocate(ALGORITHM_SUITE.getDataKeyLength() + 1));

        doReturn(badResult).when(client).decrypt(isA(DecryptRequest.class));

        assertThrows(IllegalStateException.class, () -> dao.decryptDataKey(ENCRYPTED_DATA_KEY, ALGORITHM_SUITE, ENCRYPTION_CONTEXT));
    }

    private void assertUserAgent(AmazonWebServiceRequest request) {
        assertTrue(request.getRequestClientOptions().getClientMarker(RequestClientOptions.Marker.USER_AGENT)
                .contains(VersionInfo.USER_AGENT));
    }

}
