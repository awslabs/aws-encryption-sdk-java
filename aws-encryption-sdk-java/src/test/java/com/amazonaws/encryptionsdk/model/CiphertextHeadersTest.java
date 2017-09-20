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

package com.amazonaws.encryptionsdk.model;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.spec.SecretKeySpec;

import org.junit.Test;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.BadCiphertextException;
import com.amazonaws.encryptionsdk.internal.Constants;
import com.amazonaws.encryptionsdk.internal.EncryptionContextSerializer;
import com.amazonaws.encryptionsdk.internal.RandomBytesGenerator;
import com.amazonaws.encryptionsdk.internal.VersionInfo;

public class CiphertextHeadersTest {
    final CryptoAlgorithm cryptoAlgo_ = AwsCrypto.getDefaultCryptoAlgorithm();
    final String keyProviderId_ = "None";
    final byte[] keyProviderInfo_ = "TestKeyID".getBytes();
    final String keyId_ = "testKeyId";
    final byte version_ = VersionInfo.CURRENT_CIPHERTEXT_VERSION;
    final CiphertextType type_ = CiphertextType.CUSTOMER_AUTHENTICATED_ENCRYPTED_DATA;
    final int nonceLen_ = cryptoAlgo_.getNonceLen();
    final int tagLenBytes_ = cryptoAlgo_.getTagLen();
    final int tagLenBits_ = tagLenBytes_ * 8;
    final ContentType contentType_ = ContentType.FRAME;
    final int frameSize_ = AwsCrypto.getDefaultFrameSize();

    byte[] messageId_ = RandomBytesGenerator.generate(Constants.MESSAGE_ID_LEN);

    byte[] testPlaintextKey_ = RandomBytesGenerator.generate(cryptoAlgo_.getKeyLength());
    SecretKeySpec testKey_ = new SecretKeySpec(testPlaintextKey_, cryptoAlgo_.getKeyAlgo());
    byte[] encryptedKey_ = RandomBytesGenerator.generate(cryptoAlgo_.getKeyLength());

    final KeyBlob keyBlob_ = new KeyBlob(keyProviderId_, keyProviderInfo_, encryptedKey_);

    byte[] headerNonce_ = RandomBytesGenerator.generate(nonceLen_);
    byte[] headerTag_ = RandomBytesGenerator.generate(tagLenBytes_);

    @Test
    public void serializeDeserialize() {
        Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC", "CiphertextHeader Test");

        final CiphertextHeaders ciphertextHeaders = createCiphertextHeaders(encryptionContext);

        final byte[] headerBytes = ciphertextHeaders.toByteArray();
        final CiphertextHeaders reconstructedHeaders = new CiphertextHeaders();
        reconstructedHeaders.deserialize(headerBytes, 0);
        final byte[] reconstructedHeaderBytes = reconstructedHeaders.toByteArray();

        assertArrayEquals(headerBytes, reconstructedHeaderBytes);
    }

    @Test
    public void serializeDeserializeStreaming() {
        Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC", "CiphertextHeader Streaming Test");

        final CiphertextHeaders ciphertextHeaders = createCiphertextHeaders(encryptionContext);

        final byte[] headerBytes = ciphertextHeaders.toByteArray();
        final CiphertextHeaders reconstructedHeaders = new CiphertextHeaders();

        int totalParsedBytes = 0;
        int bytesToParseLen = 1;
        int bytesParsed;

        while (reconstructedHeaders.isComplete() == false) {
            final byte[] bytesToParse = new byte[bytesToParseLen];
            System.arraycopy(headerBytes, totalParsedBytes, bytesToParse, 0, bytesToParse.length);

            bytesParsed = reconstructedHeaders.deserialize(bytesToParse, 0);
            if (bytesParsed == 0) {
                bytesToParseLen++;
            } else {
                totalParsedBytes += bytesParsed;
                bytesToParseLen = 1;
            }
        }

        final byte[] reconstructedHeaderBytes = reconstructedHeaders.toByteArray();

        assertArrayEquals(headerBytes, reconstructedHeaderBytes);
    }

    @Test
    public void deserializeNull() {
        final CiphertextHeaders ciphertextHeaders = new CiphertextHeaders();
        final int deserializedBytes = ciphertextHeaders.deserialize(null, 0);

        assertEquals(0, deserializedBytes);
    }

    @Test(expected = AwsCryptoException.class)
    public void overlyLargeEncryptionContext() {
        final int size = Constants.UNSIGNED_SHORT_MAX_VAL + 1;
        final byte[] encContextBytes = RandomBytesGenerator.generate(size);

        createCiphertextHeaders(encContextBytes);
    }

    @Test(expected = AwsCryptoException.class)
    public void serializeWithNullHeaderNonce() {
        final CiphertextHeaders ciphertextHeaders = new CiphertextHeaders(
                version_,
                type_,
                cryptoAlgo_,
                new byte[0],
                Collections.singletonList(keyBlob_),
                contentType_,
                frameSize_);
        ciphertextHeaders.setHeaderTag(headerTag_);

        ciphertextHeaders.toByteArray();
    }

    @Test(expected = AwsCryptoException.class)
    public void serializeWithNullHeaderTag() {
        final CiphertextHeaders ciphertextHeaders = new CiphertextHeaders(
                version_,
                type_,
                cryptoAlgo_,
                new byte[0],
                Collections.singletonList(keyBlob_),
                contentType_,
                frameSize_);
        ciphertextHeaders.setHeaderNonce(headerNonce_);

        ciphertextHeaders.toByteArray();
    }

    /*
     * @Test
     * public void byteFormatCheck() {
     * testPlaintextKey_ = ByteFormatCheckValues.getPlaintextKey();
     * testKey_ = new SecretKeySpec(testPlaintextKey_,
     * cryptoAlgo_.getKeySpec());
     * encryptedKey_ = ByteFormatCheckValues.getEncryptedKey();
     * dataKey_ = new AWSKMSDataKey(testKey_, encryptedKey_);
     * headerNonce_ = ByteFormatCheckValues.getNonce();
     * headerTag_ = ByteFormatCheckValues.getTag();
     * 
     * Map<String, String> encryptionContext = new HashMap<String, String>(1);
     * encryptionContext.put("ENC", "CiphertextHeader format check test");
     * 
     * final CiphertextHeaders ciphertextHeaders =
     * createCiphertextHeaders(encryptionContext);
     * //NOTE: this test will fail because of the line below.
     * //That is, the message id is randomly generated in the ciphertext
     * headers.
     * messageId_ = ciphertextHeaders.getMessageId();
     * final byte[] ciphertextHeaderHash =
     * TestIOUtils.getSha256Hash(ciphertextHeaders.toByteArray());
     * 
     * assertArrayEquals(ByteFormatCheckValues.getCiphertextHeaderHash(),
     * ciphertextHeaderHash);
     * }
     */

    private CiphertextHeaders createCiphertextHeaders(final byte[] encryptionContextBytes) {
        final CiphertextHeaders ciphertextHeaders = new CiphertextHeaders(
                version_,
                type_,
                cryptoAlgo_,
                encryptionContextBytes,
                Collections.singletonList(keyBlob_),
                contentType_,
                frameSize_);

        ciphertextHeaders.setHeaderNonce(headerNonce_);
        ciphertextHeaders.setHeaderTag(headerTag_);

        return ciphertextHeaders;
    }

    private CiphertextHeaders createCiphertextHeaders(final Map<String, String> encryptionContext) {
        byte[] encryptionContextBytes = null;
        if (encryptionContext != null) {
            encryptionContextBytes = EncryptionContextSerializer.serialize(encryptionContext);
        }

        return createCiphertextHeaders(encryptionContextBytes);
    }

    @Test
    public void checkEncContextLen() {
        final Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC", "CiphertextHeader Streaming Test");
        final byte[] encryptionContextBytes = EncryptionContextSerializer.serialize(encryptionContext);
        final int encryptionContextLen = encryptionContextBytes.length;

        final CiphertextHeaders ciphertextHeaders = createCiphertextHeaders(encryptionContext);
        final byte[] headerBytes = ciphertextHeaders.toByteArray();

        final CiphertextHeaders reconstructedHeaders = new CiphertextHeaders();
        reconstructedHeaders.deserialize(headerBytes, 0);

        assertEquals(encryptionContextLen, reconstructedHeaders.getEncryptionContextLen());
    }

    @Test
    public void checkKeyBlobCount() {
        final Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC", "CiphertextHeader Streaming Test");

        final CiphertextHeaders ciphertextHeaders = createCiphertextHeaders(encryptionContext);
        final byte[] headerBytes = ciphertextHeaders.toByteArray();

        final CiphertextHeaders reconstructedHeaders = new CiphertextHeaders();
        reconstructedHeaders.deserialize(headerBytes, 0);

        assertEquals(1, reconstructedHeaders.getEncryptedKeyBlobCount());
    }

    @Test
    public void checkNullMessageId() {
        final CiphertextHeaders ciphertextHeaders = new CiphertextHeaders();

        assertEquals(null, ciphertextHeaders.getMessageId());
    }

    @Test
    public void checkNullHeaderNonce() {
        final CiphertextHeaders ciphertextHeaders = new CiphertextHeaders();

        assertEquals(null, ciphertextHeaders.getHeaderNonce());
    }

    @Test
    public void checkNullHeaderTag() {
        final CiphertextHeaders ciphertextHeaders = new CiphertextHeaders();

        assertEquals(null, ciphertextHeaders.getHeaderTag());
    }

    private void readUptoVersion(final ByteBuffer headerBuff) {
        headerBuff.get();
    }

    private void readUptoType(final ByteBuffer headerBuff) {
        readUptoVersion(headerBuff);

        headerBuff.get();
    }

    private void readUptoAlgoId(final ByteBuffer headerBuff) {
        readUptoType(headerBuff);

        headerBuff.getShort();
    }

    private void readUptoEncContext(final ByteBuffer headerBuff) {
        readUptoAlgoId(headerBuff);

        // pull out messageId to get to enc context len.
        final byte[] msgId = new byte[Constants.MESSAGE_ID_LEN];
        headerBuff.get(msgId);

        // pull out enc context to get to key count.
        final int encContextLen = headerBuff.getShort();
        final byte[] encContext = new byte[encContextLen];
        headerBuff.get(encContext);
    }

    private void readUptoKeyBlob(final ByteBuffer headerBuff) {
        readUptoEncContext(headerBuff);

        headerBuff.getShort(); // get key count
        final short keyProviderIdLen = headerBuff.getShort();
        final byte[] keyProviderId = new byte[keyProviderIdLen];
        headerBuff.get(keyProviderId);
        final short keyProviderInfoLen = headerBuff.getShort();
        final byte[] keyProviderInfo = new byte[keyProviderInfoLen];
        headerBuff.get(keyProviderInfo);
        final short keyLen = headerBuff.getShort();
        final byte[] key = new byte[keyLen];
        headerBuff.get(key);
    }

    private void readUptoContentType(final ByteBuffer headerBuff) {
        readUptoKeyBlob(headerBuff);
        headerBuff.get();
    }

    private void readUptoReservedField(final ByteBuffer headerBuff) {
        readUptoContentType(headerBuff);
        headerBuff.getInt();
    }

    private void readUptoNonceLen(final ByteBuffer headerBuff) {
        readUptoReservedField(headerBuff);
        headerBuff.get();
    }

    @Test(expected = BadCiphertextException.class)
    public void invalidType() {
        final Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC", "CiphertextHeader Streaming Test");

        final CiphertextHeaders ciphertextHeaders = createCiphertextHeaders(encryptionContext);
        final byte[] headerBytes = ciphertextHeaders.toByteArray();
        final ByteBuffer headerBuff = ByteBuffer.wrap(headerBytes);

        readUptoVersion(headerBuff);

        // set type to invalid value of 0.
        headerBuff.put((byte) 0);

        final CiphertextHeaders reconstructedHeaders = new CiphertextHeaders();
        reconstructedHeaders.deserialize(headerBuff.array(), 0);
    }

    @Test(expected = BadCiphertextException.class)
    public void invalidAlgoId() {
        final Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC", "CiphertextHeader Streaming Test");

        final CiphertextHeaders ciphertextHeaders = createCiphertextHeaders(encryptionContext);
        final byte[] headerBytes = ciphertextHeaders.toByteArray();
        final ByteBuffer headerBuff = ByteBuffer.wrap(headerBytes);

        readUptoType(headerBuff);

        // set algoId to invalid value of 0.
        headerBuff.putShort((short) 0);

        final CiphertextHeaders reconstructedHeaders = new CiphertextHeaders();
        reconstructedHeaders.deserialize(headerBuff.array(), 0);
    }

    @Test(expected = BadCiphertextException.class)
    public void invalidContentType() {
        final Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC", "CiphertextHeader Streaming Test");

        final CiphertextHeaders ciphertextHeaders = createCiphertextHeaders(encryptionContext);
        final byte[] headerBytes = ciphertextHeaders.toByteArray();
        final ByteBuffer headerBuff = ByteBuffer.wrap(headerBytes);

        readUptoKeyBlob(headerBuff);

        // set content type to an invalid value
        headerBuff.put((byte) 10);

        final CiphertextHeaders reconstructedHeaders = new CiphertextHeaders();
        reconstructedHeaders.deserialize(headerBuff.array(), 0);
    }

    @Test(expected = BadCiphertextException.class)
    public void invalidReservedFieldLen() {
        final Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC", "CiphertextHeader Streaming Test");

        final CiphertextHeaders ciphertextHeaders = createCiphertextHeaders(encryptionContext);
        final byte[] headerBytes = ciphertextHeaders.toByteArray();
        final ByteBuffer headerBuff = ByteBuffer.wrap(headerBytes);

        readUptoContentType(headerBuff);

        // set reserved field to an invalid value
        headerBuff.putInt(-1);

        final CiphertextHeaders reconstructedHeaders = new CiphertextHeaders();
        reconstructedHeaders.deserialize(headerBuff.array(), 0);
    }

    @Test(expected = BadCiphertextException.class)
    public void invalidNonceLen() {
        final Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC", "CiphertextHeader Streaming Test");

        final CiphertextHeaders ciphertextHeaders = createCiphertextHeaders(encryptionContext);
        final byte[] headerBytes = ciphertextHeaders.toByteArray();
        final ByteBuffer headerBuff = ByteBuffer.wrap(headerBytes);

        readUptoReservedField(headerBuff);

        // set nonce len to an invalid value
        headerBuff.put((byte) -1);

        final CiphertextHeaders reconstructedHeaders = new CiphertextHeaders();
        reconstructedHeaders.deserialize(headerBuff.array(), 0);
    }

    @Test(expected = BadCiphertextException.class)
    public void invalidFrameLength() {
        final Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC", "CiphertextHeader Streaming Test");

        final CiphertextHeaders ciphertextHeaders = createCiphertextHeaders(encryptionContext);
        final byte[] headerBytes = ciphertextHeaders.toByteArray();
        final ByteBuffer headerBuff = ByteBuffer.wrap(headerBytes);

        readUptoNonceLen(headerBuff);

        // set content type to an invalid value
        headerBuff.putInt(-1);

        final CiphertextHeaders reconstructedHeaders = new CiphertextHeaders();
        reconstructedHeaders.deserialize(headerBuff.array(), 0);
    }
}
