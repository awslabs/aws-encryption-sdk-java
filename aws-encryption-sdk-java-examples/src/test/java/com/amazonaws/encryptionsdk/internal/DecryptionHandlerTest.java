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

import java.util.Collections;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.DefaultCryptoMaterialsManager;
import com.amazonaws.encryptionsdk.MasterKey;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.BadCiphertextException;
import com.amazonaws.encryptionsdk.model.CiphertextType;
import com.amazonaws.encryptionsdk.model.EncryptionMaterialsRequest;
import com.amazonaws.encryptionsdk.model.EncryptionMaterials;

public class DecryptionHandlerTest {
    private StaticMasterKey masterKeyProvider_;

    @Before
    public void init() {
        masterKeyProvider_ = new StaticMasterKey("testmaterial");
    }

    @Test(expected = NullPointerException.class)
    public void nullMasterKey() {
        DecryptionHandler.create((MasterKey)null);
    }

    @Test(expected = AwsCryptoException.class)
    public void invalidLenProcessBytes() {
        final DecryptionHandler<StaticMasterKey> decryptionHandler = DecryptionHandler.create(masterKeyProvider_);
        final byte[] in = new byte[1];
        final byte[] out = new byte[1];
        decryptionHandler.processBytes(in, 0, -1, out, 0);
    }

    @Test(expected = AwsCryptoException.class)
    public void maxLenProcessBytes() {
        final DecryptionHandler<StaticMasterKey> decryptionHandler = DecryptionHandler.create(masterKeyProvider_);
        // Create input of size 3 bytes: 1 byte containing version, 1 byte
        // containing type, and 1 byte containing half of the algoId short
        // primitive. Only 1 byte of the algoId is provided because this
        // forces the decryption handler to buffer that 1 byte while waiting for
        // the other byte. We do this so we can specify an input of max
        // value and the total bytes to parse will become max value + 1.
        final byte[] in = new byte[3];
        final byte[] out = new byte[3];
        in[1] = CiphertextType.CUSTOMER_AUTHENTICATED_ENCRYPTED_DATA.getValue();

        decryptionHandler.processBytes(in, 0, in.length, out, 0);
        decryptionHandler.processBytes(in, 0, Integer.MAX_VALUE, out, 0);
    }

    @Test(expected = BadCiphertextException.class)
    public void headerIntegrityFailure() {
        byte[] ciphertext = getTestHeaders();

        // tamper the fifth byte in the header which corresponds to the first
        // byte of the message identifier. We do this because tampering the
        // first four bytes will be detected as invalid values during parsing.
        ciphertext[5] += 1;

        // attempt to decrypt with the tampered header.
        final DecryptionHandler<StaticMasterKey> decryptionHandler = DecryptionHandler.create(masterKeyProvider_);
        final int plaintextLen = decryptionHandler.estimateOutputSize(ciphertext.length);
        final byte[] plaintext = new byte[plaintextLen];
        decryptionHandler.processBytes(ciphertext, 0, ciphertext.length, plaintext, 0);
    }

    @Test(expected = BadCiphertextException.class)
    public void invalidVersion() {
        byte[] ciphertext = getTestHeaders();

        // set byte containing version to invalid value.
        ciphertext[0] += VersionInfo.CURRENT_CIPHERTEXT_VERSION + 1;

        // attempt to decrypt with the tampered header.
        final DecryptionHandler<StaticMasterKey> decryptionHandler = DecryptionHandler.create(masterKeyProvider_);
        final int plaintextLen = decryptionHandler.estimateOutputSize(ciphertext.length);
        final byte[] plaintext = new byte[plaintextLen];
        decryptionHandler.processBytes(ciphertext, 0, ciphertext.length, plaintext, 0);
    }

    @Test(expected = AwsCryptoException.class)
    public void invalidCMK() {
        final byte[] ciphertext = getTestHeaders();
        
        masterKeyProvider_.setKeyId(masterKeyProvider_.getKeyId() + "nonsense");

        // attempt to decrypt with the tampered header.
        final DecryptionHandler<StaticMasterKey> decryptionHandler = DecryptionHandler.create(masterKeyProvider_);
        final int plaintextLen = decryptionHandler.estimateOutputSize(ciphertext.length);
        final byte[] plaintext = new byte[plaintextLen];
        decryptionHandler.processBytes(ciphertext, 0, ciphertext.length, plaintext, 0);
    }

    private byte[] getTestHeaders() {
        final CryptoAlgorithm cryptoAlgorithm_ = AwsCrypto.getDefaultCryptoAlgorithm();
        final int frameSize_ = AwsCrypto.getDefaultFrameSize();
        final Map<String, String> encryptionContext = Collections.<String, String> emptyMap();

        final EncryptionMaterialsRequest encryptionMaterialsRequest = EncryptionMaterialsRequest.newBuilder()
                                                                                                .setContext(encryptionContext)
                                                                                                .setRequestedAlgorithm(cryptoAlgorithm_)
                                                                                                .build();

        final EncryptionMaterials encryptionMaterials = new DefaultCryptoMaterialsManager(masterKeyProvider_)
                .getMaterialsForEncrypt(encryptionMaterialsRequest);

        final EncryptionHandler encryptionHandler = new EncryptionHandler(frameSize_, encryptionMaterials);

        // create the ciphertext headers by calling encryption handler.
        final byte[] in = new byte[0];
        final int ciphertextLen = encryptionHandler.estimateOutputSize(in.length);
        final byte[] ciphertext = new byte[ciphertextLen];
        encryptionHandler.processBytes(in, 0, in.length, ciphertext, 0);
        return ciphertext;
    }

    @Test(expected = AwsCryptoException.class)
    public void invalidOffsetProcessBytes() {
        final DecryptionHandler<StaticMasterKey> decryptionHandler = DecryptionHandler.create(masterKeyProvider_);
        final byte[] in = new byte[1];
        final byte[] out = new byte[1];
        decryptionHandler.processBytes(in, -1, in.length, out, 0);
    }
}