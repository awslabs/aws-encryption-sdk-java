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

package com.amazonaws.encryptionsdk;

import com.amazonaws.encryptionsdk.internal.StaticMasterKey;
import com.amazonaws.encryptionsdk.internal.VersionInfo;
import com.amazonaws.encryptionsdk.model.CiphertextHeaders;
import org.junit.Before;
import org.junit.Test;

import com.amazonaws.encryptionsdk.exception.BadCiphertextException;

import java.util.HashMap;
import java.util.Map;
import java.util.Arrays;

import static org.junit.Assert.*;
import static org.mockito.Mockito.spy;

public class ParsedCiphertextTest extends CiphertextHeaders {
    private StaticMasterKey masterKeyProvider;
    private AwsCrypto encryptionClient_;

    @Before
    public void init() {
        masterKeyProvider = spy(new StaticMasterKey("testmaterial"));

        encryptionClient_ = new AwsCrypto();
        encryptionClient_.setEncryptionAlgorithm(CryptoAlgorithm.ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256);
    }

    @Test()
    public void goodParsedCiphertext() {
        final int byteSize = 0;
        final int frameSize = 0;
        final byte[] plaintextBytes = new byte[byteSize];

        final Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC1", "ParsedCiphertext test with %d" + byteSize);

        encryptionClient_.setEncryptionFrameSize(frameSize);

        final byte[] cipherText = encryptionClient_.encryptData(
                masterKeyProvider,
                plaintextBytes,
                encryptionContext).getResult();
        final ParsedCiphertext pCt = new ParsedCiphertext(cipherText);

        assertNotNull(pCt.getCiphertext());
        assertTrue(pCt.getOffset() > 0);
    }

    @Test(expected = BadCiphertextException.class)
    public void incompleteZeroByteCiphertext() {
        final byte[] cipherText = {};
        ParsedCiphertext pCt = new ParsedCiphertext(cipherText);
    }

    @Test(expected = BadCiphertextException.class)
    public void incompleteSingleByteCiphertext() {
        final byte[] cipherText = {VersionInfo.CURRENT_CIPHERTEXT_VERSION};
        ParsedCiphertext pCt = new ParsedCiphertext(cipherText);
    }

    @Test(expected = BadCiphertextException.class)
    public void incompleteCiphertext() {
        final int byteSize = 0;
        final int frameSize = 0;
        final byte[] plaintextBytes = new byte[byteSize];

        final Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC1", "ParsedCiphertext test with %d" + byteSize);

        encryptionClient_.setEncryptionFrameSize(frameSize);

        final byte[] cipherText = encryptionClient_.encryptData(
                masterKeyProvider,
                plaintextBytes,
                encryptionContext).getResult();
        ParsedCiphertext pCt = new ParsedCiphertext(cipherText);

        byte[] incompleteCiphertext = Arrays.copyOf(pCt.getCiphertext(), pCt.getOffset() - 1);
        ParsedCiphertext badPCt = new ParsedCiphertext(incompleteCiphertext);
    }
}
