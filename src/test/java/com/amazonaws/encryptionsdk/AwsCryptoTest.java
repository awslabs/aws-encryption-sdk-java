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

package com.amazonaws.encryptionsdk;

import static com.amazonaws.encryptionsdk.FastTestsOnlySuite.isFastTestSuiteActive;
import static com.amazonaws.encryptionsdk.TestUtils.assertThrows;
import static java.util.Collections.singletonMap;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.amazonaws.encryptionsdk.caching.CachingCryptoMaterialsManager;
import com.amazonaws.encryptionsdk.caching.LocalCryptoMaterialsCache;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.BadCiphertextException;
import com.amazonaws.encryptionsdk.internal.StaticMasterKey;
import com.amazonaws.encryptionsdk.internal.TestIOUtils;
import com.amazonaws.encryptionsdk.internal.Utils;
import com.amazonaws.encryptionsdk.model.CiphertextType;
import com.amazonaws.encryptionsdk.model.DecryptionMaterials;
import com.amazonaws.encryptionsdk.model.DecryptionMaterialsRequest;
import com.amazonaws.encryptionsdk.model.EncryptionMaterials;
import com.amazonaws.encryptionsdk.model.EncryptionMaterialsRequest;

public class AwsCryptoTest {
    private StaticMasterKey masterKeyProvider;
    private AwsCrypto encryptionClient_;

    @Before
    public void init() {
        masterKeyProvider = spy(new StaticMasterKey("testmaterial"));

        encryptionClient_ = new AwsCrypto();
        encryptionClient_.setEncryptionAlgorithm(CryptoAlgorithm.ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256);
    }

    private void doEncryptDecrypt(final CryptoAlgorithm cryptoAlg, final int byteSize, final int frameSize) {
        final byte[] plaintextBytes = new byte[byteSize];

        final Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC1", "Encrypt-decrypt test with %d" + byteSize);

        encryptionClient_.setEncryptionAlgorithm(cryptoAlg);
        encryptionClient_.setEncryptionFrameSize(frameSize);

        final byte[] cipherText = encryptionClient_.encryptData(
                masterKeyProvider,
                plaintextBytes,
                encryptionContext).getResult();
        final byte[] decryptedText = encryptionClient_.decryptData(
                masterKeyProvider,
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
                masterKeyProvider,
                plaintextBytes,
                encryptionContext).getResult();
        cipherText[cipherText.length - 2] ^= (byte) 0xff;
        try {
            encryptionClient_.decryptData(
                    masterKeyProvider,
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
                masterKeyProvider,
                plaintextBytes,
                encryptionContext).getResult();
        ParsedCiphertext pCt = new ParsedCiphertext(cipherText);
        assertEquals(encryptionClient_.getEncryptionAlgorithm(), pCt.getCryptoAlgoId());
        assertEquals(CiphertextType.CUSTOMER_AUTHENTICATED_ENCRYPTED_DATA, pCt.getType());
        assertEquals(1, pCt.getEncryptedKeyBlobCount());
        assertEquals(pCt.getEncryptedKeyBlobCount(), pCt.getEncryptedKeyBlobs().size());
        assertEquals(masterKeyProvider.getProviderId(), pCt.getEncryptedKeyBlobs().get(0).getProviderId());
        for (Map.Entry<String, String> e : encryptionContext.entrySet()) {
            assertEquals(e.getValue(), pCt.getEncryptionContextMap().get(e.getKey()));
        }

        final byte[] decryptedText = encryptionClient_.decryptData(
                masterKeyProvider,
                pCt
                ).getResult();

        assertArrayEquals(plaintextBytes, decryptedText);
    }

    @Test
    public void encryptDecrypt() {
        for (final CryptoAlgorithm cryptoAlg : EnumSet.allOf(CryptoAlgorithm.class)) {
            final int[] frameSizeToTest = TestUtils.getFrameSizesToTest(cryptoAlg);

            for (int i = 0; i < frameSizeToTest.length; i++) {
                final int frameSize = frameSizeToTest[i];
                int[] bytesToTest = { 0, 1, frameSize - 1, frameSize, frameSize + 1, (int) (frameSize * 1.5),
                        frameSize * 2, 1000000 };

                for (int j = 0; j < bytesToTest.length; j++) {
                    final int byteSize = bytesToTest[j];

                    if (byteSize > 500_000 && isFastTestSuiteActive()) {
                        continue;
                    }

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
            final int[] frameSizeToTest = TestUtils.getFrameSizesToTest(cryptoAlg);

            for (int i = 0; i < frameSizeToTest.length; i++) {
                final int frameSize = frameSizeToTest[i];
                int[] bytesToTest = { 0, 1, frameSize - 1, frameSize, frameSize + 1, (int) (frameSize * 1.5),
                        frameSize * 2, 1000000 };

                for (int j = 0; j < bytesToTest.length; j++) {
                    final int byteSize = bytesToTest[j];

                    if (byteSize > 500_000 && isFastTestSuiteActive()) {
                        continue;
                    }

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
            final int[] frameSizeToTest = TestUtils.getFrameSizesToTest(cryptoAlg);

            for (int i = 0; i < frameSizeToTest.length; i++) {
                final int frameSize = frameSizeToTest[i];
                int[] bytesToTest = { 0, 1, frameSize - 1, frameSize, frameSize + 1, (int) (frameSize * 1.5),
                        frameSize * 2, 1000000 };

                for (int j = 0; j < bytesToTest.length; j++) {
                    final int byteSize = bytesToTest[j];

                    if (byteSize > 500_000 && isFastTestSuiteActive()) {
                        continue;
                    }

                    if (byteSize >= 0) {
                        doEncryptDecryptWithParsedCiphertext(byteSize, frameSize);
                    }
                }
            }
        }
    }

    @Test
    public void encryptDecryptWithCustomManager() throws Exception {
        boolean[] didDecrypt = new boolean[] { false };

        CryptoMaterialsManager manager = new CryptoMaterialsManager() {
            @Override public EncryptionMaterials getMaterialsForEncrypt(
                    EncryptionMaterialsRequest request
            ) {
                request = request.toBuilder().setContext(singletonMap("foo", "bar")).build();

                EncryptionMaterials encryptionMaterials
                        = new DefaultCryptoMaterialsManager(masterKeyProvider).getMaterialsForEncrypt(request);

                return encryptionMaterials;
            }

            @Override public DecryptionMaterials decryptMaterials(
                    DecryptionMaterialsRequest request
            ) {
                didDecrypt[0] = true;
                return new DefaultCryptoMaterialsManager(masterKeyProvider).decryptMaterials(request);
            }
        };

        byte[] plaintext = new byte[100];
        CryptoResult<byte[], ?> ciphertext = encryptionClient_.encryptData(manager, plaintext);
        assertEquals("bar", ciphertext.getEncryptionContext().get("foo"));

        // TODO decrypt
        assertFalse(didDecrypt[0]);
        CryptoResult<byte[], ?> plaintextResult = encryptionClient_.decryptData(manager, ciphertext.getResult());
        assertArrayEquals(plaintext, plaintextResult.getResult());
        assertTrue(didDecrypt[0]);
    }

    @Test
    public void whenCustomCMMIgnoresAlgorithm_throws() throws Exception {
        boolean[] didDecrypt = new boolean[] { false };

        CryptoMaterialsManager manager = new CryptoMaterialsManager() {
            @Override public EncryptionMaterials getMaterialsForEncrypt(
                    EncryptionMaterialsRequest request
            ) {
                request = request.toBuilder().setRequestedAlgorithm(null).build();

                EncryptionMaterials encryptionMaterials
                        = new DefaultCryptoMaterialsManager(masterKeyProvider).getMaterialsForEncrypt(request);

                return encryptionMaterials;
            }

            @Override public DecryptionMaterials decryptMaterials(
                    DecryptionMaterialsRequest request
            ) {
                didDecrypt[0] = true;
                return new DefaultCryptoMaterialsManager(masterKeyProvider).decryptMaterials(request);
            }
        };

        encryptionClient_.setEncryptionAlgorithm(CryptoAlgorithm.ALG_AES_128_GCM_IV12_TAG16_NO_KDF);

        byte[] plaintext = new byte[100];
        assertThrows(AwsCryptoException.class,
                     () -> encryptionClient_.encryptData(manager, plaintext));
        assertThrows(AwsCryptoException.class,
                     () -> encryptionClient_.estimateCiphertextSize(manager, 12345));
        assertThrows(AwsCryptoException.class,
                     () -> encryptionClient_.createEncryptingStream(manager, new ByteArrayOutputStream()).write(0));
        assertThrows(AwsCryptoException.class,
                     () -> encryptionClient_.createEncryptingStream(manager, new ByteArrayInputStream(new byte[1024*1024])).read());

    }

    @Test
    public void whenDecrypting_invokesMKPOnce() throws Exception {
        byte[] data = encryptionClient_.encryptData(masterKeyProvider, new byte[1]).getResult();

        reset(masterKeyProvider);

        encryptionClient_.decryptData(masterKeyProvider, data);

        verify(masterKeyProvider, times(1)).decryptDataKey(any(), any(), any());
    }

    private void doEstimateCiphertextSize(final CryptoAlgorithm cryptoAlg, final int inLen, final int frameSize) {
        final byte[] plaintext = TestIOUtils.generateRandomPlaintext(inLen);

        final Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC1", "Ciphertext size estimation test with " + inLen);

        encryptionClient_.setEncryptionAlgorithm(cryptoAlg);
        encryptionClient_.setEncryptionFrameSize(frameSize);

        final long estimatedCiphertextSize = encryptionClient_.estimateCiphertextSize(
                masterKeyProvider,
                inLen,
                encryptionContext);
        final byte[] cipherText = encryptionClient_.encryptData(masterKeyProvider, plaintext,
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
            final int[] frameSizeToTest = TestUtils.getFrameSizesToTest(cryptoAlg);

            for (int i = 0; i < frameSizeToTest.length; i++) {
                final int frameSize = frameSizeToTest[i];
                int[] bytesToTest = { 0, 1, frameSize - 1, frameSize, frameSize + 1, (int) (frameSize * 1.5),
                        frameSize * 2, 1000000 };

                for (int j = 0; j < bytesToTest.length; j++) {
                    final int byteSize = bytesToTest[j];

                    if (byteSize > 500_000 && isFastTestSuiteActive()) {
                        continue;
                    }

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

        final long estimatedCiphertextSize = encryptionClient_.estimateCiphertextSize(masterKeyProvider, inLen);
        final byte[] cipherText = encryptionClient_.encryptData(masterKeyProvider, plaintext).getResult();

        final String errMsg = "Bad estimation expected: <" + estimatedCiphertextSize
                + "> but was: <" + cipherText.length + ">";
        assertTrue(errMsg, estimatedCiphertextSize - cipherText.length >= 0);
        assertTrue(errMsg, estimatedCiphertextSize - cipherText.length <= 16);
    }

    @Test
    public void estimateCiphertextSize_usesCachedKeys() throws Exception {
        // Make sure estimateCiphertextSize works with cached CMMs
        CryptoMaterialsManager cmm = spy(new DefaultCryptoMaterialsManager(masterKeyProvider));

        CachingCryptoMaterialsManager cache = CachingCryptoMaterialsManager.newBuilder()
                .withBackingMaterialsManager(cmm)
                .withMaxAge(Long.MAX_VALUE, TimeUnit.SECONDS)
                .withCache(new LocalCryptoMaterialsCache(1))
                .withMessageUseLimit(9999)
                .withByteUseLimit(501)
                .build();

        // These estimates should be cached, and should not consume any bytes from the byte use limit.
        encryptionClient_.estimateCiphertextSize(cache, 500, new HashMap<>());
        encryptionClient_.estimateCiphertextSize(cache, 500, new HashMap<>());

        encryptionClient_.encryptData(cache, new byte[500]);

        verify(cmm, times(1)).getMaterialsForEncrypt(any());
    }

    @Test
    public void encryptDecryptWithoutEncContext() {
        final int ptSize = 1000000; // 1MB
        final byte[] plaintextBytes = TestIOUtils.generateRandomPlaintext(ptSize);

        final byte[] cipherText = encryptionClient_.encryptData(masterKeyProvider, plaintextBytes).getResult();
        final byte[] decryptedText = encryptionClient_.decryptData(
                masterKeyProvider,
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
                masterKeyProvider,
                plaintextString,
                encryptionContext).getResult();
        final String decryptedText = encryptionClient_.decryptString(
                masterKeyProvider,
                ciphertext).getResult();

        assertEquals(plaintextString, decryptedText);
    }

    @Test
    public void encryptDecryptStringWithoutEncContext() {
        final int ptSize = 1000000; // 1MB
        final String plaintextString = TestIOUtils.generateRandomString(ptSize);

        final String cipherText = encryptionClient_.encryptString(masterKeyProvider, plaintextString).getResult();
        final String decryptedText = encryptionClient_.decryptString(
                masterKeyProvider,
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
                masterKeyProvider,
                plaintext.getBytes(StandardCharsets.UTF_8),
                encryptionContext).getResult();
        final String decryptedText = encryptionClient_.decryptString(
                masterKeyProvider,
                Utils.encodeBase64String(cipherText)).getResult();

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
                masterKeyProvider,
                plaintextString,
                encryptionContext).getResult();
        final byte[] decryptedText = encryptionClient_.decryptData(
                masterKeyProvider,
                Utils.decodeBase64String(ciphertext)).getResult();

        assertArrayEquals(plaintextString.getBytes(StandardCharsets.UTF_8), decryptedText);
    }

    @Test
    public void emptyEncryptionContext() {
        final int ptSize = 1000000; // 1MB
        final byte[] plaintextBytes = TestIOUtils.generateRandomPlaintext(ptSize);

        final Map<String, String> encryptionContext = new HashMap<String, String>(0);

        final byte[] cipherText = encryptionClient_.encryptData(
                masterKeyProvider,
                plaintextBytes,
                encryptionContext).getResult();
        final byte[] decryptedText = encryptionClient_.decryptData(
                masterKeyProvider,
                cipherText).getResult();

        assertArrayEquals(plaintextBytes, decryptedText);
    }

    // Test that all the parameters that aren't allowed to be null (i.e. all of them) result in immediate NPEs if
    // invoked with null args
    @Test
    public void assertNullChecks() throws Exception {
        byte[] buf = new byte[1];
        HashMap<String, String> context = new HashMap<>();
        MasterKeyProvider provider = masterKeyProvider;
        CryptoMaterialsManager cmm = new DefaultCryptoMaterialsManager(masterKeyProvider);
        InputStream is = new ByteArrayInputStream(new byte[0]);
        OutputStream os = new ByteArrayOutputStream();

        byte[] ciphertext = encryptionClient_.encryptData(cmm, buf).getResult();
        String stringCiphertext = encryptionClient_.encryptString(cmm, "hello, world").getResult();

        TestUtils.assertNullChecks(encryptionClient_, "estimateCiphertextSize",
                                   MasterKeyProvider.class, provider,
                                   Integer.TYPE, 42,
                                   Map.class, context
        );
        TestUtils.assertNullChecks(encryptionClient_, "estimateCiphertextSize",
                                   CryptoMaterialsManager.class, cmm,
                                   Integer.TYPE, 42,
                                   Map.class, context
        );
        TestUtils.assertNullChecks(encryptionClient_, "estimateCiphertextSize",
                                   MasterKeyProvider.class, provider,
                                   Integer.TYPE, 42
        );
        TestUtils.assertNullChecks(encryptionClient_, "estimateCiphertextSize",
                                   CryptoMaterialsManager.class, cmm,
                                   Integer.TYPE, 42
        );

        TestUtils.assertNullChecks(encryptionClient_, "encryptData",
                                   MasterKeyProvider.class, provider,
                                   byte[].class, buf,
                                   Map.class, context
        );
        TestUtils.assertNullChecks(encryptionClient_, "encryptData",
                                   CryptoMaterialsManager.class, cmm,
                                   byte[].class, buf,
                                   Map.class, context
        );
        TestUtils.assertNullChecks(encryptionClient_, "encryptData",
                                   MasterKeyProvider.class, provider,
                                   byte[].class, buf
        );
        TestUtils.assertNullChecks(encryptionClient_, "encryptData",
                                   CryptoMaterialsManager.class, cmm,
                                   byte[].class, buf
        );
        TestUtils.assertNullChecks(encryptionClient_, "encryptString",
                                   MasterKeyProvider.class, provider,
                                   String.class, "",
                                   Map.class, context
        );
        TestUtils.assertNullChecks(encryptionClient_, "encryptString",
                                   CryptoMaterialsManager.class, cmm,
                                   String.class, "",
                                   Map.class, context
        );
        TestUtils.assertNullChecks(encryptionClient_, "encryptString",
                                   MasterKeyProvider.class, provider,
                                   String.class, ""
        );
        TestUtils.assertNullChecks(encryptionClient_, "encryptString",
                                   CryptoMaterialsManager.class, cmm,
                                   String.class, ""
        );

        TestUtils.assertNullChecks(encryptionClient_, "decryptData",
                                   MasterKeyProvider.class, provider,
                                   byte[].class, ciphertext
        );
        TestUtils.assertNullChecks(encryptionClient_, "decryptData",
                                   CryptoMaterialsManager.class, cmm,
                                   byte[].class, ciphertext
        );
        TestUtils.assertNullChecks(encryptionClient_, "decryptData",
                                   MasterKeyProvider.class, provider,
                                   ParsedCiphertext.class, new ParsedCiphertext(ciphertext)
        );
        TestUtils.assertNullChecks(encryptionClient_, "decryptData",
                                   CryptoMaterialsManager.class, cmm,
                                   ParsedCiphertext.class, new ParsedCiphertext(ciphertext)
        );
        TestUtils.assertNullChecks(encryptionClient_, "decryptString",
                                   MasterKeyProvider.class, provider,
                                   String.class, stringCiphertext
        );
        TestUtils.assertNullChecks(encryptionClient_, "decryptString",
                                   CryptoMaterialsManager.class, cmm,
                                   String.class, stringCiphertext
        );

        TestUtils.assertNullChecks(encryptionClient_, "createEncryptingStream",
                                   MasterKeyProvider.class, provider,
                                   OutputStream.class, os,
                                   Map.class, context
                                   );
        TestUtils.assertNullChecks(encryptionClient_, "createEncryptingStream",
                                   CryptoMaterialsManager.class, cmm,
                                   OutputStream.class, os,
                                   Map.class, context
        );

        TestUtils.assertNullChecks(encryptionClient_, "createEncryptingStream",
                                   MasterKeyProvider.class, provider,
                                   OutputStream.class, os
        );
        TestUtils.assertNullChecks(encryptionClient_, "createEncryptingStream",
                                   CryptoMaterialsManager.class, cmm,
                                   OutputStream.class, os
        );

        TestUtils.assertNullChecks(encryptionClient_, "createEncryptingStream",
                                   MasterKeyProvider.class, provider,
                                   InputStream.class, is,
                                   Map.class, context
        );
        TestUtils.assertNullChecks(encryptionClient_, "createEncryptingStream",
                                   CryptoMaterialsManager.class, cmm,
                                   InputStream.class, is,
                                   Map.class, context
        );

        TestUtils.assertNullChecks(encryptionClient_, "createEncryptingStream",
                                   MasterKeyProvider.class, provider,
                                   InputStream.class, is
        );
        TestUtils.assertNullChecks(encryptionClient_, "createEncryptingStream",
                                   CryptoMaterialsManager.class, cmm,
                                   InputStream.class, is
        );

        TestUtils.assertNullChecks(encryptionClient_, "createDecryptingStream",
                                   MasterKeyProvider.class, provider,
                                   OutputStream.class, os
        );
        TestUtils.assertNullChecks(encryptionClient_, "createDecryptingStream",
                                   CryptoMaterialsManager.class, cmm,
                                   OutputStream.class, os
        );

        TestUtils.assertNullChecks(encryptionClient_, "createDecryptingStream",
                                   MasterKeyProvider.class, provider,
                                   InputStream.class, is
        );
        TestUtils.assertNullChecks(encryptionClient_, "createDecryptingStream",
                                   CryptoMaterialsManager.class, cmm,
                                   InputStream.class, is
        );
    }

    @Test
    public void setValidFrameSize() throws IOException {
        final int setFrameSize = AwsCrypto.getDefaultCryptoAlgorithm().getBlockSize() * 2;
        encryptionClient_.setEncryptionFrameSize(setFrameSize);

        final int getFrameSize = encryptionClient_.getEncryptionFrameSize();

        assertEquals(setFrameSize, getFrameSize);
    }


    public void unalignedFrameSizesAreAccepted() throws IOException {
        final int frameSize = AwsCrypto.getDefaultCryptoAlgorithm().getBlockSize() - 1;
        encryptionClient_.setEncryptionFrameSize(frameSize);

        assertEquals(frameSize, encryptionClient_.getEncryptionFrameSize());
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
