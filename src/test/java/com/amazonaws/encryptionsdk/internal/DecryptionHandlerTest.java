// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk.internal;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import com.amazonaws.encryptionsdk.jce.JceMasterKey;
import com.amazonaws.encryptionsdk.ParsedCiphertext;
import com.amazonaws.encryptionsdk.model.CiphertextHeaders;
import org.junit.Before;
import org.junit.Test;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.DefaultCryptoMaterialsManager;
import com.amazonaws.encryptionsdk.MasterKey;
import com.amazonaws.encryptionsdk.TestUtils;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.BadCiphertextException;
import com.amazonaws.encryptionsdk.CommitmentPolicy;
import com.amazonaws.encryptionsdk.model.CiphertextType;
import com.amazonaws.encryptionsdk.model.EncryptionMaterialsRequest;
import com.amazonaws.encryptionsdk.model.EncryptionMaterials;

import static com.amazonaws.encryptionsdk.TestUtils.assertThrows;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class DecryptionHandlerTest {
    private StaticMasterKey masterKeyProvider_;
    private final CommitmentPolicy commitmentPolicy = TestUtils.DEFAULT_TEST_COMMITMENT_POLICY;
    private final CommitmentPolicy requireReadPolicy = CommitmentPolicy.RequireEncryptRequireDecrypt;
    private final List<CommitmentPolicy> allowReadPolicies = Arrays.asList(CommitmentPolicy.RequireEncryptAllowDecrypt,
            CommitmentPolicy.ForbidEncryptAllowDecrypt);

    @Before
    public void init() {
        masterKeyProvider_ = new StaticMasterKey("testmaterial");
    }

    @Test(expected = NullPointerException.class)
    public void nullMasterKey() {
        DecryptionHandler.create((MasterKey)null, commitmentPolicy);
    }

    @Test
    public void nullCommitment() {
        final byte[] ciphertext = getTestHeaders(CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384, CommitmentPolicy.ForbidEncryptAllowDecrypt);

        assertThrows(NullPointerException.class, () -> DecryptionHandler.create(masterKeyProvider_, new ParsedCiphertext(ciphertext), null));
        assertThrows(NullPointerException.class, () -> DecryptionHandler.create(masterKeyProvider_, null));
    }


    @Test(expected = AwsCryptoException.class)
    public void invalidLenProcessBytes() {
        final DecryptionHandler<StaticMasterKey> decryptionHandler = DecryptionHandler.create(masterKeyProvider_, commitmentPolicy);
        final byte[] in = new byte[1];
        final byte[] out = new byte[1];
        decryptionHandler.processBytes(in, 0, -1, out, 0);
    }

    @Test(expected = AwsCryptoException.class)
    public void maxLenProcessBytes() {
        final DecryptionHandler<StaticMasterKey> decryptionHandler = DecryptionHandler.create(masterKeyProvider_, commitmentPolicy);
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
        final DecryptionHandler<StaticMasterKey> decryptionHandler = DecryptionHandler.create(masterKeyProvider_, commitmentPolicy);
        final int plaintextLen = decryptionHandler.estimateOutputSize(ciphertext.length);
        final byte[] plaintext = new byte[plaintextLen];
        decryptionHandler.processBytes(ciphertext, 0, ciphertext.length, plaintext, 0);
    }

    @Test(expected = BadCiphertextException.class)
    public void invalidVersion() {
        byte[] ciphertext = getTestHeaders();

        // set byte containing version to invalid value.
        ciphertext[0] = 0; // NOTE: This will need to be updated should 0 ever be a valid version

        // attempt to decrypt with the tampered header.
        final DecryptionHandler<StaticMasterKey> decryptionHandler = DecryptionHandler.create(masterKeyProvider_, commitmentPolicy);
        final int plaintextLen = decryptionHandler.estimateOutputSize(ciphertext.length);
        final byte[] plaintext = new byte[plaintextLen];
        decryptionHandler.processBytes(ciphertext, 0, ciphertext.length, plaintext, 0);
    }

    @Test(expected = AwsCryptoException.class)
    public void invalidCMK() {
        final byte[] ciphertext = getTestHeaders();

        masterKeyProvider_.setKeyId(masterKeyProvider_.getKeyId() + "nonsense");

        // attempt to decrypt with the tampered header.
        final DecryptionHandler<StaticMasterKey> decryptionHandler = DecryptionHandler.create(masterKeyProvider_, commitmentPolicy);
        final int plaintextLen = decryptionHandler.estimateOutputSize(ciphertext.length);
        final byte[] plaintext = new byte[plaintextLen];
        decryptionHandler.processBytes(ciphertext, 0, ciphertext.length, plaintext, 0);
    }

    @Test
    public void validAlgForCommitmentPolicyCreate() {
        // ensure we can decrypt non-committing algs with the policies that allow it
        final CryptoAlgorithm nonCommittingAlg = CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;
        for (CommitmentPolicy policy : allowReadPolicies) {
            final byte[] ciphertext = getTestHeaders(nonCommittingAlg, CommitmentPolicy.ForbidEncryptAllowDecrypt);
            final DecryptionHandler<StaticMasterKey> decryptionHandler = DecryptionHandler.create(masterKeyProvider_, policy);
            // expected plaintext is zero length
            final byte[] plaintext = new byte[0];
            ProcessingSummary processingSummary = decryptionHandler.processBytes(ciphertext, 0, ciphertext.length, plaintext, 0);
            assertEquals(ciphertext.length, processingSummary.getBytesProcessed());
            assertArrayEquals(new byte[0], plaintext);
        }

        // ensure we can decrypt committing algs with all policies
        final CryptoAlgorithm committingAlg = CryptoAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY;
        for (CommitmentPolicy policy : CommitmentPolicy.values()) {
            final byte[] ciphertext = getTestHeaders(committingAlg, CommitmentPolicy.RequireEncryptRequireDecrypt);
            final DecryptionHandler<StaticMasterKey> decryptionHandler = DecryptionHandler.create(masterKeyProvider_, policy);
            // expected plaintext is zero length
            final byte[] plaintext = new byte[0];
            ProcessingSummary processingSummary = decryptionHandler.processBytes(ciphertext, 0, ciphertext.length, plaintext, 0);
            assertEquals(ciphertext.length, processingSummary.getBytesProcessed());
            assertArrayEquals(new byte[0], plaintext);
        }
    }

    @Test
    public void invalidAlgForCommitmentPolicyCreateWithoutHeaders() {
        final CryptoAlgorithm nonCommittingAlg = CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384;
        final byte[] ciphertext = getTestHeaders(nonCommittingAlg, CommitmentPolicy.ForbidEncryptAllowDecrypt);

        final DecryptionHandler<StaticMasterKey> decryptionHandler = DecryptionHandler.create(masterKeyProvider_, requireReadPolicy);
        final int plaintextLen = decryptionHandler.estimateOutputSize(ciphertext.length);
        final byte[] plaintext = new byte[plaintextLen];

        assertThrows(AwsCryptoException.class, () -> decryptionHandler.processBytes(ciphertext, 0, ciphertext.length, plaintext, 0));
    }

    @Test
    public void invalidAlgForCommitmentPolicyCreateWithHeaders() {
        final CryptoAlgorithm nonCommittingAlg = CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384;
        final byte[] ciphertext = getTestHeaders(nonCommittingAlg, CommitmentPolicy.ForbidEncryptAllowDecrypt);

        assertThrows(AwsCryptoException.class,
                () -> DecryptionHandler.create(masterKeyProvider_, new ParsedCiphertext(ciphertext), requireReadPolicy));
    }

    private byte[] getTestHeaders() {
        return getTestHeaders(TestUtils.DEFAULT_TEST_CRYPTO_ALG, TestUtils.DEFAULT_TEST_COMMITMENT_POLICY);
    }

    private byte[] getTestHeaders(CryptoAlgorithm cryptoAlgorithm, CommitmentPolicy policy) {
        final int frameSize_ = AwsCrypto.getDefaultFrameSize();
        final Map<String, String> encryptionContext = Collections.<String, String> emptyMap();

        final EncryptionMaterialsRequest encryptionMaterialsRequest = EncryptionMaterialsRequest.newBuilder()
                                                                                                .setContext(encryptionContext)
                                                                                                .setRequestedAlgorithm(cryptoAlgorithm)
                                                                                                .setCommitmentPolicy(policy)
                                                                                                .build();

        final EncryptionMaterials encryptionMaterials = new DefaultCryptoMaterialsManager(masterKeyProvider_)
                .getMaterialsForEncrypt(encryptionMaterialsRequest);

        final EncryptionHandler encryptionHandler = new EncryptionHandler(frameSize_, encryptionMaterials, policy);

        // create the ciphertext headers by calling encryption handler.
        final byte[] in = new byte[0];
        final int ciphertextLen = encryptionHandler.estimateOutputSize(in.length);
        final byte[] ciphertext = new byte[ciphertextLen];
        encryptionHandler.processBytes(in, 0, in.length, ciphertext, 0);
        return ciphertext;
    }

    @Test(expected = AwsCryptoException.class)
    public void invalidOffsetProcessBytes() {
        final DecryptionHandler<StaticMasterKey> decryptionHandler = DecryptionHandler.create(masterKeyProvider_, commitmentPolicy);
        final byte[] in = new byte[1];
        final byte[] out = new byte[1];
        decryptionHandler.processBytes(in, -1, in.length, out, 0);
    }

    @Test(expected = BadCiphertextException.class)
    public void incompleteCiphertext() {
        byte[] ciphertext = getTestHeaders();

        CiphertextHeaders h = new CiphertextHeaders();
        h.deserialize(ciphertext, 0);

        final DecryptionHandler<StaticMasterKey> decryptionHandler = DecryptionHandler.create(masterKeyProvider_, commitmentPolicy);
        final byte[] out = new byte[1];

        decryptionHandler.processBytes(ciphertext, 0, ciphertext.length - 1, out, 0);
        decryptionHandler.doFinal(out, 0);
    }

    @Test
    public void incompleteCiphertextV2() {
        byte[] ciphertext = Utils.decodeBase64String(TestUtils.messageWithCommitKeyBase64);
        final DecryptionHandler<JceMasterKey> decryptionHandler = DecryptionHandler.create(
                TestUtils.messageWithCommitKeyMasterKey,
                CommitmentPolicy.RequireEncryptRequireDecrypt);
        final byte[] out = new byte[1];

        decryptionHandler.processBytes(ciphertext, 0, ciphertext.length - 1, out, 0);
        assertThrows(BadCiphertextException.class, "Unable to process entire ciphertext.",
                () -> decryptionHandler.doFinal(out, 0));
    }

    @Test
    public void headerV2HeaderIntegrityFailure() {
        byte[] ciphertext = Utils.decodeBase64String(TestUtils.messageWithCommitKeyBase64);

        // Tamper the bytes that corresponds to the frame length.
        // This is the only reasonable way to tamper with this handcrafted message's
        // header which can still be successfully parsed.
        ciphertext[134] += 1;

        // attempt to decrypt with the tampered header.
        final DecryptionHandler<JceMasterKey> decryptionHandler = DecryptionHandler.create(
                TestUtils.messageWithCommitKeyMasterKey,
                CommitmentPolicy.RequireEncryptRequireDecrypt);
        final int plaintextLen = decryptionHandler.estimateOutputSize(ciphertext.length);
        final byte[] plaintext = new byte[plaintextLen];
        assertThrows(BadCiphertextException.class, "Header integrity check failed", () ->
                decryptionHandler.processBytes(ciphertext, 0, ciphertext.length, plaintext, 0));
    }

    @Test
    public void headerV2BodyIntegrityFailure() {
        byte[] ciphertext = Utils.decodeBase64String(TestUtils.messageWithCommitKeyBase64);

        // Tamper the bytes that corresponds to the body auth
        ciphertext[ciphertext.length - 1] += 1;

        // attempt to decrypt with the tampered header.
        final DecryptionHandler<JceMasterKey> decryptionHandler = DecryptionHandler.create(
                TestUtils.messageWithCommitKeyMasterKey,
                CommitmentPolicy.RequireEncryptRequireDecrypt);
        final int plaintextLen = decryptionHandler.estimateOutputSize(ciphertext.length);
        final byte[] plaintext = new byte[plaintextLen];
        assertThrows(BadCiphertextException.class, "Tag mismatch", () ->
                decryptionHandler.processBytes(ciphertext, 0, ciphertext.length, plaintext, 0));
    }
}
