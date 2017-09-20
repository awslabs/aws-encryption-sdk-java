/*
 * Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package com.amazonaws.encryptionsdk.internal;

import static com.amazonaws.encryptionsdk.TestUtils.assertThrows;
import static java.util.Collections.emptyList;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.junit.Test;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.DefaultCryptoMaterialsManager;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.model.EncryptionMaterials;
import com.amazonaws.encryptionsdk.model.EncryptionMaterialsRequest;

public class EncryptionHandlerTest {
    private final CryptoAlgorithm cryptoAlgorithm_ = CryptoAlgorithm.ALG_AES_192_GCM_IV12_TAG16_NO_KDF;
    private final int frameSize_ = AwsCrypto.getDefaultFrameSize();
    private final Map<String, String> encryptionContext_ = Collections.<String, String> emptyMap();
    private StaticMasterKey masterKeyProvider = new StaticMasterKey("mock");
    private final List<StaticMasterKey> cmks_ = Collections.singletonList(masterKeyProvider);
    private EncryptionMaterialsRequest testRequest
            = EncryptionMaterialsRequest.newBuilder()
                                        .setContext(encryptionContext_)
                                        .setRequestedAlgorithm(cryptoAlgorithm_)
                                        .build();

    private EncryptionMaterials testResult = new DefaultCryptoMaterialsManager(masterKeyProvider)
                                                 .getMaterialsForEncrypt(testRequest);

    @Test
    public void badArguments() {
        assertThrows(
                () -> new EncryptionHandler(frameSize_, testResult.toBuilder().setAlgorithm(null).build())
        );

        assertThrows(
                () -> new EncryptionHandler(frameSize_, testResult.toBuilder().setEncryptionContext(null).build())
        );

        assertThrows(
                () -> new EncryptionHandler(frameSize_, testResult.toBuilder().setEncryptedDataKeys(null).build())
        );

        assertThrows(
                () -> new EncryptionHandler(frameSize_, testResult.toBuilder().setEncryptedDataKeys(emptyList()).build())
        );

        assertThrows(
                () -> new EncryptionHandler(frameSize_, testResult.toBuilder().setCleartextDataKey(null).build())
        );

        assertThrows(
                () -> new EncryptionHandler(frameSize_, testResult.toBuilder().setMasterKeys(null).build())
        );

        assertThrows(
                () -> new EncryptionHandler(-1, testResult)
        );
    }

    @Test(expected = AwsCryptoException.class)
    public void invalidLenProcessBytes() {
        final EncryptionHandler encryptionHandler = new EncryptionHandler(frameSize_, testResult);

        final byte[] in = new byte[1];
        final byte[] out = new byte[1];
        encryptionHandler.processBytes(in, 0, -1, out, 0);
    }

    @Test(expected = AwsCryptoException.class)
    public void invalidOffsetProcessBytes() {
        final EncryptionHandler encryptionHandler = new EncryptionHandler(frameSize_, testResult);

        final byte[] in = new byte[1];
        final byte[] out = new byte[1];
        encryptionHandler.processBytes(in, -1, in.length, out, 0);
    }

    @Test
    public void whenEncrypting_headerIVIsZero() throws Exception {
        final EncryptionHandler encryptionHandler = new EncryptionHandler(frameSize_, testResult);

        assertArrayEquals(
                new byte[encryptionHandler.getHeaders().getCryptoAlgoId().getNonceLen()],
                encryptionHandler.getHeaders().getHeaderNonce()
        );
    }
}
