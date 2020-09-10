// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk.internal;

import static com.amazonaws.encryptionsdk.TestUtils.assertThrows;
import static java.util.Collections.emptyList;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import com.amazonaws.encryptionsdk.TestUtils;
import com.amazonaws.encryptionsdk.CommitmentPolicy;
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
    private final CommitmentPolicy commitmentPolicy = TestUtils.DEFAULT_TEST_COMMITMENT_POLICY;
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

    @Test(expected = AwsCryptoException.class)
    public void whenEncryptingV2Algorithm_fails() throws Exception {
        final EncryptionMaterials resultWithV2Alg = testResult.toBuilder().setAlgorithm(TestUtils.KEY_COMMIT_CRYPTO_ALG).build();
        final EncryptionHandler encryptionHandler = new EncryptionHandler(frameSize_, resultWithV2Alg);
    }
}
