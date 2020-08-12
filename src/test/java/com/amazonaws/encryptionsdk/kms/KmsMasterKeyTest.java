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

import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.DataKey;
import com.amazonaws.encryptionsdk.EncryptedDataKey;
import com.amazonaws.encryptionsdk.exception.MismatchedDataKeyException;
import com.amazonaws.encryptionsdk.model.KeyBlob;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.DecryptResult;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import static com.amazonaws.encryptionsdk.EncryptedDataKey.PROVIDER_ENCODING;
import static com.amazonaws.encryptionsdk.internal.Constants.AWS_KMS_PROVIDER_ID;
import static com.amazonaws.encryptionsdk.internal.RandomBytesGenerator.generate;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class KmsMasterKeyTest {

    private static final CryptoAlgorithm ALGORITHM_SUITE = CryptoAlgorithm.ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384;
    private static final Map<String, String> ENCRYPTION_CONTEXT = Collections.singletonMap("test", "value");
    private static final String CMK_ARN = "arn:aws:kms:us-east-1:999999999999:key/01234567-89ab-cdef-fedc-ba9876543210";
    @Mock Supplier<AWSKMS> supplier;
    @Mock AWSKMS awsKmsClient;

    /**
     * Test that when decryption of an encrypted data key throws a MismatchedDataKeyException, this
     * key is skipped and another key in the list of keys is decrypted.
     */
    @Test
    void testMismatchedDataKeyException() {
        EncryptedDataKey encryptedDataKey1 = new KeyBlob(AWS_KMS_PROVIDER_ID, "KeyId1".getBytes(PROVIDER_ENCODING), generate(64));
        EncryptedDataKey encryptedDataKey2 = new KeyBlob(AWS_KMS_PROVIDER_ID, "KeyId2".getBytes(PROVIDER_ENCODING), generate(64));
        byte[] generated = generate(ALGORITHM_SUITE.getDataKeyLength());
        SecretKey secretKey = new SecretKeySpec(generated, ALGORITHM_SUITE.getDataKeyAlgo());
        when(supplier.get()).thenReturn(awsKmsClient);

        when(awsKmsClient.decrypt(any(DecryptRequest.class)))
            // Fail the first call
            .thenThrow(new MismatchedDataKeyException())
            // Return the decrypted result for the second EncryptedDataKey on the second decrypt call
            .thenReturn(new DecryptResult()
                .withKeyId("KeyId2")
                .withEncryptionAlgorithm(secretKey.getAlgorithm())
                .withPlaintext(ByteBuffer.wrap(generated)));

        KmsMasterKey kmsMasterKey = KmsMasterKey.getInstance(supplier, CMK_ARN, null);

        List<EncryptedDataKey> encryptedDataKeys = new ArrayList<>();
        encryptedDataKeys.add(encryptedDataKey1);
        encryptedDataKeys.add(encryptedDataKey2);

        DataKey<KmsMasterKey> result = kmsMasterKey.decryptDataKey(ALGORITHM_SUITE, encryptedDataKeys, ENCRYPTION_CONTEXT);

        assertEquals(secretKey, result.getKey());
    }
}
