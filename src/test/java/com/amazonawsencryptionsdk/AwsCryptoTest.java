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

package com.amazonawsencryptionsdk;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.ParsedCiphertext;
import com.amazonaws.encryptionsdk.exception.BadCiphertextException;
import com.amazonaws.encryptionsdk.internal.MockKmsProvider;
import com.amazonaws.encryptionsdk.internal.TestIOUtils;
import com.amazonaws.encryptionsdk.kms.KmsMasterKey;
import com.amazonaws.encryptionsdk.kms.KmsMasterKeyProvider;
import com.amazonaws.encryptionsdk.model.CiphertextType;
import com.amazonaws.services.kms.MockKMSClient;
import com.amazonaws.util.Base64;

public class AwsCryptoTest {
    private MockKMSClient mockKMSClient;
    private String cmkId;
    private KmsMasterKey customerMasterKey;
    private KmsMasterKeyProvider customerMasterKeyProvider;
    private AwsCrypto encryptionClient_;

    @Before
    public void init() {
        mockKMSClient = new MockKMSClient();
        cmkId = mockKMSClient.createKey().getKeyMetadata().getKeyId();
        customerMasterKeyProvider = new MockKmsProvider(mockKMSClient);
        customerMasterKey = customerMasterKeyProvider.getMasterKey(cmkId);

        encryptionClient_ = new AwsCrypto();
    }

    private void doEncryptDecrypt(final CryptoAlgorithm cryptoAlg, final int byteSize, final int frameSize) {
        final byte[] plaintextBytes = new byte[byteSize];

        final Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC1", "Encrypt-decrypt test with %d" + byteSize);

        encryptionClient_.setEncryptionAlgorithm(cryptoAlg);
        encryptionClient_.setEncryptionFrameSize(frameSize);

        final byte[] cipherText = encryptionClient_.encryptData(
                customerMasterKey,
                plaintextBytes,
                encryptionContext).getResult();
        final byte[] decryptedText = encryptionClient_.decryptData(
                customerMasterKeyProvider,
                cipherText
                ).getResult();

        assertArrayEquals("Bad encrypt/decrypt for " + cryptoAlg, plaintextBytes, decryptedText);
    }

    private void doTamperedEncryptDecrypt(final CryptoAlgorithm cryptoAlg, final int byteSize, final int frameSize) {
        final byte[] plaintextBytes = new byte[byteSize];

        final Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC1", "Encrypt-decrypt test with %d" + byteSize);

        encryptionClient_.setEncryptionAlgorithm(cryptoAlg);
        encryptionClient_.setEncryptionFrameSize(frameSize);

        final byte[] cipherText = encryptionClient_.encryptData(
                customerMasterKey,
                plaintextBytes,
                encryptionContext).getResult();
        cipherText[cipherText.length - 2] ^= (byte) 0xff;
        try {
            encryptionClient_.decryptData(
                    customerMasterKeyProvider,
                    cipherText
                    ).getResult();
            Assert.fail("Expected BadCiphertextException");
        } catch (final BadCiphertextException ex) {
            // Expected exception
        }
    }

    private void doEncryptDecryptWithParsedCiphertext(final int byteSize, final int frameSize) {
        final byte[] plaintextBytes = new byte[byteSize];

        final Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC1", "Encrypt-decrypt test with %d" + byteSize);

        encryptionClient_.setEncryptionFrameSize(frameSize);

        final byte[] cipherText = encryptionClient_.encryptData(
                customerMasterKey,
                plaintextBytes,
                encryptionContext).getResult();
        ParsedCiphertext pCt = new ParsedCiphertext(cipherText);
        assertEquals(encryptionClient_.getEncryptionAlgorithm(), pCt.getCryptoAlgoId());
        assertEquals(CiphertextType.CUSTOMER_AUTHENTICATED_ENCRYPTED_DATA, pCt.getType());
        assertEquals(1, pCt.getEncryptedKeyBlobCount());
        assertEquals(pCt.getEncryptedKeyBlobCount(), pCt.getEncryptedKeyBlobs().size());
        assertEquals(customerMasterKey.getProviderId(), pCt.getEncryptedKeyBlobs().get(0).getProviderId());
        for (Map.Entry<String, String> e : encryptionContext.entrySet()) {
            assertEquals(e.getValue(), pCt.getEncryptionContextMap().get(e.getKey()));
        }

        final byte[] decryptedText = encryptionClient_.decryptData(
                customerMasterKeyProvider,
                pCt
                ).getResult();

        assertArrayEquals(plaintextBytes, decryptedText);
    }

    @Test
    public void encryptDecrypt() {
        for (final CryptoAlgorithm cryptoAlg : EnumSet.allOf(CryptoAlgorithm.class)) {
            final int blockSize = cryptoAlg.getBlockSize();
            final int[] frameSizeToTest = { 0, blockSize, blockSize * 2, blockSize * 10,
                    AwsCrypto.getDefaultFrameSize() };

            for (int i = 0; i < frameSizeToTest.length; i++) {
                final int frameSize = frameSizeToTest[i];
                int[] bytesToTest = { 0, 1, frameSize - 1, frameSize, frameSize + 1, (int) (frameSize * 1.5),
                        frameSize * 2, 1000000 };

                for (int j = 0; j < bytesToTest.length; j++) {
                    final int byteSize = bytesToTest[j];
                    if (byteSize >= 0) {
                        doEncryptDecrypt(cryptoAlg, byteSize, frameSize);
                    }
                }
            }
        }
    }

    @Test
    public void encryptDecryptPointCompressionDisabled() {
        encryptionClient_.setPointCompressionEnabled(false);

        for (final CryptoAlgorithm cryptoAlg : EnumSet.allOf(CryptoAlgorithm.class)) {

            if (cryptoAlg.getTrailingSignatureAlgo() == null) {
                continue;
            }

            final int blockSize = cryptoAlg.getBlockSize();
            final int[] frameSizeToTest = {0, blockSize, blockSize * 2, blockSize * 10,
                    AwsCrypto.getDefaultFrameSize()};

            for (int i = 0; i < frameSizeToTest.length; i++) {
                final int frameSize = frameSizeToTest[i];
                int[] bytesToTest = { 0, 1, frameSize - 1, frameSize, frameSize + 1, (int) (frameSize * 1.5),
                        frameSize * 2, 1000000 };

                for (int j = 0; j < bytesToTest.length; j++) {
                    final int byteSize = bytesToTest[j];
                    if (byteSize >= 0) {
                        doEncryptDecrypt(cryptoAlg, byteSize, frameSize);
                    }
                }
            }
        }
    }

    @Test
    public void encryptDecryptWithBadSignature() {
        for (final CryptoAlgorithm cryptoAlg : EnumSet.allOf(CryptoAlgorithm.class)) {
            if (cryptoAlg.getTrailingSignatureAlgo() == null) {
                continue;
            }
            final int blockSize = cryptoAlg.getBlockSize();
            final int[] frameSizeToTest = { 0, blockSize, blockSize * 2, blockSize * 10,
                    AwsCrypto.getDefaultFrameSize() };

            for (int i = 0; i < frameSizeToTest.length; i++) {
                final int frameSize = frameSizeToTest[i];
                int[] bytesToTest = { 0, 1, frameSize - 1, frameSize, frameSize + 1, (int) (frameSize * 1.5),
                        frameSize * 2, 1000000 };

                for (int j = 0; j < bytesToTest.length; j++) {
                    final int byteSize = bytesToTest[j];
                    if (byteSize >= 0) {
                        doTamperedEncryptDecrypt(cryptoAlg, byteSize, frameSize);
                    }
                }
            }
        }
    }

    @Test
    public void encryptDecryptWithParsedCiphertext() {
        for (final CryptoAlgorithm cryptoAlg : EnumSet.allOf(CryptoAlgorithm.class)) {
            final int blockSize = cryptoAlg.getBlockSize();
            final int[] frameSizeToTest = { 0, blockSize, blockSize * 2, blockSize * 10,
                    AwsCrypto.getDefaultFrameSize() };

            for (int i = 0; i < frameSizeToTest.length; i++) {
                final int frameSize = frameSizeToTest[i];
                int[] bytesToTest = { 0, 1, frameSize - 1, frameSize, frameSize + 1, (int) (frameSize * 1.5),
                        frameSize * 2, 1000000 };

                for (int j = 0; j < bytesToTest.length; j++) {
                    final int byteSize = bytesToTest[j];
                    if (byteSize >= 0) {
                        doEncryptDecryptWithParsedCiphertext(byteSize, frameSize);
                    }
                }
            }
        }
    }

    private void doEstimateCiphertextSize(final CryptoAlgorithm cryptoAlg, final int inLen, final int frameSize) {
        final byte[] plaintext = TestIOUtils.generateRandomPlaintext(inLen);

        final Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC1", "Ciphertext size estimation test with " + inLen);

        encryptionClient_.setEncryptionAlgorithm(cryptoAlg);
        encryptionClient_.setEncryptionFrameSize(frameSize);

        final long estimatedCiphertextSize = encryptionClient_.estimateCiphertextSize(
                customerMasterKey,
                inLen,
                encryptionContext);
        final byte[] cipherText = encryptionClient_.encryptData(customerMasterKey, plaintext,
                encryptionContext).getResult();

        // The estimate should be close (within 16 bytes) and never less than reality
        final String errMsg = "Bad estimation for " + cryptoAlg + " expected: <" + estimatedCiphertextSize
                + "> but was: <" + cipherText.length + ">";
        assertTrue(errMsg, estimatedCiphertextSize - cipherText.length >= 0);
        assertTrue(errMsg, estimatedCiphertextSize - cipherText.length <= 16);
    }

    @Test
    public void estimateCiphertextSize() {
        for (final CryptoAlgorithm cryptoAlg : EnumSet.allOf(CryptoAlgorithm.class)) {
            final int blockSize = cryptoAlg.getBlockSize();
            final int[] frameSizeToTest = { 0, blockSize, blockSize * 2, blockSize * 10,
                    AwsCrypto.getDefaultFrameSize() };

            for (int i = 0; i < frameSizeToTest.length; i++) {
                final int frameSize = frameSizeToTest[i];
                int[] bytesToTest = { 0, 1, frameSize - 1, frameSize, frameSize + 1, (int) (frameSize * 1.5),
                        frameSize * 2, 1000000 };

                for (int j = 0; j < bytesToTest.length; j++) {
                    final int byteSize = bytesToTest[j];
                    if (byteSize >= 0) {
                        doEstimateCiphertextSize(cryptoAlg, byteSize, frameSize);
                    }
                }
            }
        }
    }

    @Test
    public void estimateCiphertextSizeWithoutEncContext() {
        final int inLen = 1000000;
        final byte[] plaintext = TestIOUtils.generateRandomPlaintext(inLen);

        encryptionClient_.setEncryptionFrameSize(AwsCrypto.getDefaultFrameSize());

        final long estimatedCiphertextSize = encryptionClient_.estimateCiphertextSize(customerMasterKey, inLen);
        final byte[] cipherText = encryptionClient_.encryptData(customerMasterKey, plaintext).getResult();

        final String errMsg = "Bad estimation expected: <" + estimatedCiphertextSize
                + "> but was: <" + cipherText.length + ">";
        assertTrue(errMsg, estimatedCiphertextSize - cipherText.length >= 0);
        assertTrue(errMsg, estimatedCiphertextSize - cipherText.length <= 16);
    }

    @Test
    public void encryptDecryptWithoutEncContext() {
        final int ptSize = 1000000; // 1MB
        final byte[] plaintextBytes = TestIOUtils.generateRandomPlaintext(ptSize);

        final byte[] cipherText = encryptionClient_.encryptData(customerMasterKey, plaintextBytes).getResult();
        final byte[] decryptedText = encryptionClient_.decryptData(
                customerMasterKeyProvider,
                cipherText).getResult();

        assertArrayEquals(plaintextBytes, decryptedText);
    }

    @Test
    public void encryptDecryptString() {
        final int ptSize = 1000000; // 1MB
        final String plaintextString = TestIOUtils.generateRandomString(ptSize);

        final Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC1", "Test Encryption Context");

        final String ciphertext = encryptionClient_.encryptString(
                customerMasterKey,
                plaintextString,
                encryptionContext).getResult();
        final String decryptedText = encryptionClient_.decryptString(
                customerMasterKeyProvider,
                ciphertext).getResult();

        assertEquals(plaintextString, decryptedText);
    }

    @Test
    public void encryptDecryptStringWithoutEncContext() {
        final int ptSize = 1000000; // 1MB
        final String plaintextString = TestIOUtils.generateRandomString(ptSize);

        final String cipherText = encryptionClient_.encryptString(customerMasterKey, plaintextString).getResult();
        final String decryptedText = encryptionClient_.decryptString(
                customerMasterKeyProvider,
                cipherText).getResult();

        assertEquals(plaintextString, decryptedText);
    }

    @Test
    public void encryptBytesDecryptString() {
        final int ptSize = 1000000; // 1MB
        final String plaintext = TestIOUtils.generateRandomString(ptSize);

        final Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC1", "Test Encryption Context");

        final byte[] cipherText = encryptionClient_.encryptData(
                customerMasterKey,
                plaintext.getBytes(StandardCharsets.UTF_8),
                encryptionContext).getResult();
        final String decryptedText = encryptionClient_.decryptString(
                customerMasterKeyProvider,
                Base64.encodeAsString(cipherText)).getResult();

        assertEquals(plaintext, decryptedText);
    }

    @Test
    public void encryptStringDecryptBytes() {
        final int ptSize = 1000000; // 1MB
        final byte[] plaintextBytes = TestIOUtils.generateRandomPlaintext(ptSize);
        final String plaintextString = new String(plaintextBytes, StandardCharsets.UTF_8);

        final Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC1", "Test Encryption Context");

        final String ciphertext = encryptionClient_.encryptString(
                customerMasterKey,
                plaintextString,
                encryptionContext).getResult();
        final byte[] decryptedText = encryptionClient_.decryptData(
                customerMasterKeyProvider,
                Base64.decode(ciphertext)).getResult();

        assertArrayEquals(plaintextString.getBytes(StandardCharsets.UTF_8), decryptedText);
    }

    @Test
    public void emptyEncryptionContext() {
        final int ptSize = 1000000; // 1MB
        final byte[] plaintextBytes = TestIOUtils.generateRandomPlaintext(ptSize);

        final Map<String, String> encryptionContext = new HashMap<String, String>(0);

        final byte[] cipherText = encryptionClient_.encryptData(
                customerMasterKey,
                plaintextBytes,
                encryptionContext).getResult();
        final byte[] decryptedText = encryptionClient_.decryptData(
                customerMasterKeyProvider,
                cipherText).getResult();

        assertArrayEquals(plaintextBytes, decryptedText);
    }

    @Test(expected = NullPointerException.class)
    public void nullEncryptionContextEncrypt() {
        final int ptSize = 1000000; // 1MB
        final byte[] plaintext = TestIOUtils.generateRandomPlaintext(ptSize);

        final Map<String, String> encryptionContext = null;
        encryptionClient_.encryptData(customerMasterKey, plaintext, encryptionContext);
    }

    @Test(expected = NullPointerException.class)
    public void nullPlaintextEncrypt() {
        final Map<String, String> encryptionContext = new HashMap<String, String>(0);
        encryptionClient_.encryptData(customerMasterKey, null, encryptionContext);
    }

    @Test(expected = NullPointerException.class)
    public void nullMasterKeyEncrypt() {
        final int ptSize = 1000000; // 1MB
        final byte[] plaintext = TestIOUtils.generateRandomPlaintext(ptSize);

        final Map<String, String> encryptionContext = new HashMap<String, String>(0);
        encryptionClient_.encryptData(null, plaintext, encryptionContext);
    }

    @Test(expected = NullPointerException.class)
    public void nullEncryptionContextEncryptString() {
        final int ptSize = 1000000; // 1MB
        final byte[] plaintextBytes = TestIOUtils.generateRandomPlaintext(ptSize);
        final String plaintextString = new String(plaintextBytes, StandardCharsets.UTF_8);

        encryptionClient_.encryptString(customerMasterKey, plaintextString, null);
    }

    @Test(expected = NullPointerException.class)
    public void nullPlaintextEncryptString() {
        final Map<String, String> encryptionContext = new HashMap<String, String>(0);
        encryptionClient_.encryptString(customerMasterKey, null, encryptionContext);
    }

    @Test(expected = NullPointerException.class)
    public void nullMasterKeyEncryptString() {
        final int ptSize = 1000000; // 1MB
        final byte[] plaintextBytes = TestIOUtils.generateRandomPlaintext(ptSize);
        final String plaintextString = new String(plaintextBytes, StandardCharsets.UTF_8);

        final Map<String, String> encryptionContext = new HashMap<String, String>(0);
        encryptionClient_.encryptString(null, plaintextString, encryptionContext);
    }

    @Test(expected = NullPointerException.class)
    public void nullMasterKeyDecrypt() {
        final int ctSize = 1000000; // 1MB
        final byte[] ciphertext = TestIOUtils.generateRandomPlaintext(ctSize);

        encryptionClient_.decryptData(null, ciphertext);
    }

    @Test(expected = NullPointerException.class)
    public void nullMasterKeyDecryptString() {
        final int ctSize = 1000000; // 1MB
        final byte[] ciphertextBytes = TestIOUtils.generateRandomPlaintext(ctSize);
        final String ciphertextString = new String(ciphertextBytes, StandardCharsets.UTF_8);

        encryptionClient_.decryptString(null, ciphertextString);
    }

    @Test(expected = NullPointerException.class)
    public void nullCiphertextDecrypt() {
        encryptionClient_.decryptData(customerMasterKeyProvider, (byte[]) null);
    }

    @Test(expected = NullPointerException.class)
    public void nullParsedCiphertextDecrypt() {
        encryptionClient_.decryptData(customerMasterKeyProvider, (ParsedCiphertext) null);
    }

    @Test(expected = NullPointerException.class)
    public void nullCiphertextDecryptString() {
        encryptionClient_.decryptString(customerMasterKeyProvider, (String) null);
    }

    @Test(expected = NullPointerException.class)
    public void nullEncContextEncryptingInputStream() {
        final byte[] inputBytes = new byte[1];
        final InputStream inStream = new ByteArrayInputStream(inputBytes);
        encryptionClient_.createEncryptingStream(customerMasterKey, inStream, null);
    }

    @Test(expected = NullPointerException.class)
    public void nullCMKEncryptingInputStream() {
        final byte[] inputBytes = new byte[1];
        final InputStream inStream = new ByteArrayInputStream(inputBytes);
        final Map<String, String> encryptionContext = new HashMap<String, String>(0);
        encryptionClient_.createEncryptingStream(null, inStream, encryptionContext);
    }

    @Test(expected = NullPointerException.class)
    public void nullCMKDecryptingInputStream() {
        final byte[] inputBytes = new byte[1];
        final InputStream inStream = new ByteArrayInputStream(inputBytes);
        encryptionClient_.createDecryptingStream(null, inStream);
    }

    @Test(expected = NullPointerException.class)
    public void nullCMKEncryptingOutputStream() {
        final OutputStream outStream = new ByteArrayOutputStream();
        final Map<String, String> encryptionContext = new HashMap<String, String>(0);
        encryptionClient_.createEncryptingStream(null, outStream, encryptionContext);
    }

    @Test(expected = NullPointerException.class)
    public void nullEncContextEncryptingOutputStream() {
        final OutputStream outStream = new ByteArrayOutputStream();
        encryptionClient_.createEncryptingStream(customerMasterKey, outStream, null);
    }

    @Test(expected = NullPointerException.class)
    public void nullCMKDecryptingOutputStream() {
        final OutputStream outStream = new ByteArrayOutputStream();
        encryptionClient_.createDecryptingStream(null, outStream);
    }

    @Test(expected = NullPointerException.class)
    public void nullEncryptingInputStream() {
        final Map<String, String> encryptionContext = new HashMap<String, String>(0);
        encryptionClient_.createEncryptingStream(customerMasterKey, (InputStream) null, encryptionContext);
    }

    @Test(expected = NullPointerException.class)
    public void nullDecryptingInputStream() {
        encryptionClient_.createDecryptingStream(customerMasterKeyProvider, (InputStream) null);
    }

    @Test(expected = NullPointerException.class)
    public void nullEncryptingOutputStream() {
        final Map<String, String> encryptionContext = new HashMap<String, String>(0);
        encryptionClient_.createEncryptingStream(customerMasterKey, (OutputStream) null, encryptionContext);
    }

    @Test(expected = NullPointerException.class)
    public void nullDecryptingOutputStream() {
        encryptionClient_.createDecryptingStream(customerMasterKeyProvider, (OutputStream) null);
    }

    @Test(expected = NullPointerException.class)
    public void nullMasterKeyCiphertextEstimate() {
        final int ptSize = 1000000; // 1MB

        final Map<String, String> encryptionContext = new HashMap<String, String>(0);
        encryptionClient_.estimateCiphertextSize(null, ptSize, encryptionContext);
    }

    @Test(expected = NullPointerException.class)
    public void nullEncContextCiphertextEstimate() {
        final int ptSize = 1000000; // 1MB

        encryptionClient_.estimateCiphertextSize(customerMasterKey, ptSize, null);
    }

    @Test
    public void setValidFrameSize() throws IOException {
        final int setFrameSize = AwsCrypto.getDefaultCryptoAlgorithm().getBlockSize() * 2;
        encryptionClient_.setEncryptionFrameSize(setFrameSize);

        final int getFrameSize = encryptionClient_.getEncryptionFrameSize();

        assertEquals(setFrameSize, getFrameSize);
    }

    @Test(expected = IllegalArgumentException.class)
    public void setInValidFrameSize() throws IOException {
        final int frameSize = AwsCrypto.getDefaultCryptoAlgorithm().getBlockSize() - 1;
        encryptionClient_.setEncryptionFrameSize(frameSize);
    }

    @Test(expected = IllegalArgumentException.class)
    public void setNegativeFrameSize() throws IOException {
        encryptionClient_.setEncryptionFrameSize(-1);
    }

    @Test
    public void setCryptoAlgorithm() throws IOException {
        final CryptoAlgorithm setCryptoAlgorithm = CryptoAlgorithm.ALG_AES_192_GCM_IV12_TAG16_NO_KDF;
        encryptionClient_.setEncryptionAlgorithm(setCryptoAlgorithm);

        final CryptoAlgorithm getCryptoAlgorithm = encryptionClient_.getEncryptionAlgorithm();

        assertEquals(setCryptoAlgorithm, getCryptoAlgorithm);
    }

}
