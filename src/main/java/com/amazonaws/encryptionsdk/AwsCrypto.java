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

import static com.amazonaws.encryptionsdk.internal.Utils.assertNonNull;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import com.amazonaws.encryptionsdk.exception.BadCiphertextException;
import com.amazonaws.encryptionsdk.internal.DecryptionHandler;
import com.amazonaws.encryptionsdk.internal.EncryptionHandler;
import com.amazonaws.encryptionsdk.internal.MessageCryptoHandler;
import com.amazonaws.encryptionsdk.internal.ProcessingSummary;
import com.amazonaws.encryptionsdk.internal.Utils;
import com.amazonaws.util.Base64;

/**
 * Provides the primary entry-point to the AWS Encryption SDK. All encryption and decryption
 * operations should start here. Most people will want to use either
 * {@link #encryptData(MasterKeyProvider, byte[], Map)} and
 * {@link #decryptData(MasterKeyProvider, byte[])} to encrypt/decrypt things.
 * 
 * <P>
 * The core concepts (and classes) in this SDK are:
 * <ul>
 * <li>{@link AwsCrypto}
 * <li>{@link DataKey}
 * <li>{@link MasterKey}
 * <li>{@link MasterKeyProvider}
 * </ul>
 *
 * <p>
 * {@link AwsCrypto} provides the primary way to encrypt/decrypt data. It can operate on
 * byte-arrays, streams, or {@link java.lang.String Strings}. This data is encrypted using the
 * specifed {@link CryptoAlgorithm} and a {@link DataKey} which is unique to each encrypted message.
 * This {@code DataKey} is then encrypted using one (or more) {@link MasterKey MasterKeys}. The
 * process is reversed on decryption with the code selecting a copy of the {@code DataKey} protected
 * by a usable {@code MasterKey}, decrypting the {@code DataKey}, and then decrypted the message.
 *
 * <p>
 * The main way to get a {@code MasterKey} is through the use of a {@link MasterKeyProvider}. This
 * provides a common interface for the AwsEncryptionSdk to find and retrieve {@code MasterKeys}.
 * (Some {@code MasterKeys} can also be constructed directly.)
 *
 * <p>
 * {@code AwsCrypto} uses the {@code MasterKeyProvider} to determine which {@code MasterKeys} should
 * be used to encrypt the {@code DataKeys} by calling
 * {@link MasterKeyProvider#getMasterKeysForEncryption(MasterKeyRequest)} . When more than one
 * {@code MasterKey} is returned, the first {@code MasterKeys} is used to create the
 * {@code DataKeys} by calling {@link MasterKey#generateDataKey(CryptoAlgorithm,java.util.Map)} .
 * All of the other {@code MasterKeys} are then used to re-encrypt that {@code DataKey} with
 * {@link MasterKey#encryptDataKey(CryptoAlgorithm,java.util.Map,DataKey)} . This list of
 * {@link EncryptedDataKey EncryptedDataKeys} (the same {@code DataKey} possibly encrypted multiple
 * times) is stored in the {@link com.amazonaws.encryptionsdk.model.CiphertextHeaders}.
 *
 * <p>
 * {@code AwsCrypto} also uses the {@code MasterKeyProvider} to decrypt one of the
 * {@link EncryptedDataKey EncryptedDataKeys} from the header to retrieve the actual {@code DataKey}
 * necessary to decrypt the message.
 *
 * <p>
 * Any place a {@code MasterKeyProvider} is used, a {@link MasterKey} can be used instead. The
 * {@code MasterKey} will behave as a {@code MasterKeyProvider} which is only capable of providing
 * itself. This is often useful when only one {@code MasterKey} is being used.
 *
 * <p>
 * Note regarding the use of generics: This library makes heavy use of generics to provide type
 * safety to advanced developers. The great majority of users should be able to just use the
 * provided type parameters or the {@code ?} wildcard.
 */
public class AwsCrypto {
    private static final Map<String, String> EMPTY_MAP = Collections.emptyMap();

    private boolean pointCompressionEnabled_ = true;

    /**
     * Returns the {@link CryptoAlgorithm} to be used for encryption when none is explicitly
     * selected. Currently it is {@link CryptoAlgorithm#ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384}.
     */
    public static CryptoAlgorithm getDefaultCryptoAlgorithm() {
        return CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384;
    }

    /**
     * Returns the frame size to use for encryption when none is explicitly selected. Currently it
     * is 4096.
     */
    public static int getDefaultFrameSize() {
        return 4096;
    }

    private CryptoAlgorithm encryptionAlgorithm_ = getDefaultCryptoAlgorithm();
    private int encryptionFrameSize_ = getDefaultFrameSize();

    /**
     * Sets the {@link CryptoAlgorithm} to use when <em>encrypting</em> data. This has no impact on
     * decryption.
     */
    public void setEncryptionAlgorithm(final CryptoAlgorithm alg) {
        encryptionAlgorithm_ = alg;
    }

    public CryptoAlgorithm getEncryptionAlgorithm() {
        return encryptionAlgorithm_;
    }

    /**
     * Sets the framing size to use when <em>encrypting</em> data. This has no impact on decryption.
     * {@code frameSize} must be a non-negative multiple of the underlying algorithm's blocksize. If
     * {@code franeSize} is 0, then framing is disabled and the entire plaintext will be encrypted
     * in a single block.
     */
    public void setEncryptionFrameSize(final int frameSize) {
        if (frameSize < 0 || (frameSize % encryptionAlgorithm_.getBlockSize()) != 0) {
            throw new IllegalArgumentException("frameSize must be a non-negative multiple of the block size");
        }
        encryptionFrameSize_ = frameSize;
    }

    public int getEncryptionFrameSize() {
        return encryptionFrameSize_;
    }

    /**
     * Sets whether or not point compression should be used during encryption. Point compression is enabled by
     * default. This has no impact on decryption.
     */
    public void setPointCompressionEnabled(final boolean pointCompressionEnabled) {
        this.pointCompressionEnabled_ = pointCompressionEnabled;
    }

    public boolean getPointCompressionEnabled() {
        return pointCompressionEnabled_;
    }

    /**
     * Returns the best estimate for the output length of encrypting a plaintext with the provided
     * {@code plaintextSize} and {@code encryptionContext}. The actual ciphertext may be shorter.
     */
    public <K extends MasterKey<K>> long estimateCiphertextSize(final MasterKeyProvider<K> provider,
            final int plaintextSize, final Map<String, String> encryptionContext) {
        final MasterKeyRequest keyRequest = MasterKeyRequest.newBuilder()
                .setEncryptionContext(encryptionContext)
                .setStreaming(true) // Since we don't have the actual data yet
                .build();
        final List<K> mks = assertNonNull(provider, "provider").getMasterKeysForEncryption(keyRequest);

        final MessageCryptoHandler<K> cryptoHandler = new EncryptionHandler<>(
                mks,
                encryptionContext,
                getEncryptionAlgorithm(),
                getEncryptionFrameSize(),
                getPointCompressionEnabled());

        return cryptoHandler.estimateOutputSize(plaintextSize);
    }

    /**
     * Returns the equivalent to calling
     * {@link #estimateCiphertextSize(MasterKeyProvider, int, Map)} with an empty
     * {@code encryptionContext}.
     */
    public <K extends MasterKey<K>> long estimateCiphertextSize(final MasterKeyProvider<K> provider,
            final int plaintextSize) {
        return estimateCiphertextSize(provider, plaintextSize, EMPTY_MAP);
    }

    /**
     * Returns an encrypted form of {@code plaintext} that has been protected with {@link DataKey
     * DataKeys} that are in turn protected by {@link MasterKey MasterKeys} provided by
     * {@code provider}. This method may add new values to the provided {@code encryptionContext}.
     */
    public <K extends MasterKey<K>> CryptoResult<byte[], K> encryptData(final MasterKeyProvider<K> provider,
            final byte[] plaintext, final Map<String, String> encryptionContext) {
        final MasterKeyRequest keyRequest = MasterKeyRequest.newBuilder()
                .setEncryptionContext(encryptionContext)
                .setPlaintext(plaintext)
                .build();
        final List<K> mks = assertNonNull(provider, "provider").getMasterKeysForEncryption(keyRequest);
        final MessageCryptoHandler<K> cryptoHandler = new EncryptionHandler<>(
                mks,
                encryptionContext,
                getEncryptionAlgorithm(),
                getEncryptionFrameSize(),
                getPointCompressionEnabled());
        final int outSizeEstimate = cryptoHandler.estimateOutputSize(plaintext.length);
        final byte[] out = new byte[outSizeEstimate];
        int outLen = cryptoHandler.processBytes(plaintext, 0, plaintext.length, out, 0).getBytesWritten();
        outLen += cryptoHandler.doFinal(out, outLen);

        final byte[] outBytes = Utils.truncate(out, outLen);
        return new CryptoResult<byte[], K>(outBytes, cryptoHandler.getMasterKeys(), cryptoHandler.getHeaders());
    }

    /**
     * Returns the equivalent to calling {@link #encryptData(MasterKeyProvider, byte[], Map)} with
     * an empty {@code encryptionContext}.
     */
    public <K extends MasterKey<K>> CryptoResult<byte[], K> encryptData(final MasterKeyProvider<K> provider,
            final byte[] plaintext) {
        return encryptData(provider, plaintext, EMPTY_MAP);
    }

    /**
     * Calls {@link #encryptData(MasterKeyProvider, byte[], Map)} on the UTF-8 encoded bytes of
     * {@code plaintext} and base64 encodes the result.
     */
    public <K extends MasterKey<K>> CryptoResult<String, K> encryptString(final MasterKeyProvider<K> provider,
            final String plaintext,
            final Map<String, String> encryptionContext) {
        final CryptoResult<byte[], K> ctBytes = encryptData(
                provider, plaintext.getBytes(StandardCharsets.UTF_8), encryptionContext);
        return new CryptoResult<String, K>(Base64.encodeAsString(ctBytes.getResult()),
                ctBytes.getMasterKeys(), ctBytes.getHeaders());
    }

    /**
     * Returns the equivalent to calling {@link #encryptString(MasterKeyProvider, String, Map)} with
     * an empty {@code encryptionContext}.
     */
    public <K extends MasterKey<K>> CryptoResult<String, K> encryptString(final MasterKeyProvider<K> provider,
            final String plaintext) {
        return encryptString(provider, plaintext, EMPTY_MAP);
    }

    /**
     * Decrypts the provided {@code ciphertext} by requesting that the {@code provider} unwrap the
     * first usable {@link DataKey} in the ciphertext and then decrypts the ciphertext using that
     * {@code DataKey}.
     */
    public <K extends MasterKey<K>> CryptoResult<byte[], K> decryptData(final MasterKeyProvider<K> provider,
            final byte[] ciphertext) {
        return decryptData(Utils.assertNonNull(provider, "provider"), new
                ParsedCiphertext(ciphertext));
    }

    /**
     * @see #decryptData(MasterKeyProvider, byte[])
     */
    public <K extends MasterKey<K>> CryptoResult<byte[], K> decryptData(
            final MasterKeyProvider<K> provider, final ParsedCiphertext ciphertext) {
        final MessageCryptoHandler<K> cryptoHandler = new DecryptionHandler<>(provider, ciphertext);

        final byte[] ciphertextBytes = ciphertext.getCiphertext();
        final int contentLen = ciphertextBytes.length - ciphertext.getOffset();
        final int outSizeEstimate = cryptoHandler.estimateOutputSize(contentLen);
        final byte[] out = new byte[outSizeEstimate];
        final ProcessingSummary processed = cryptoHandler.processBytes(ciphertextBytes, ciphertext.getOffset(),
                contentLen, out,
                0);
        if (processed.getBytesProcessed() != contentLen) {
            throw new BadCiphertextException("Unable to process entire ciphertext. May have trailing data.");
        }
        int outLen = processed.getBytesWritten();
        outLen += cryptoHandler.doFinal(out, outLen);

        final byte[] outBytes = Utils.truncate(out, outLen);
        return new CryptoResult<byte[], K>(outBytes, cryptoHandler.getMasterKeys(), cryptoHandler.getHeaders());
    }

    /**
     * Base64 decodes the {@code ciphertext} prior to decryption and then treats the results as a
     * UTF-8 encoded string.
     *
     * @see #decryptData(MasterKeyProvider, byte[])
     */
    public <K extends MasterKey<K>> CryptoResult<String, K> decryptString(final MasterKeyProvider<K> provider,
            final String ciphertext) {
        Utils.assertNonNull(provider, "provider");
        final byte[] ciphertextBytes;
        try {
            ciphertextBytes = Base64.decode(Utils.assertNonNull(ciphertext, "ciphertext"));
        } catch (final IllegalArgumentException ex) {
            throw new BadCiphertextException("Invalid base 64", ex);
        }
        final CryptoResult<byte[], K> ptBytes = decryptData(provider, ciphertextBytes);
        return new CryptoResult<String, K>(
                new String(ptBytes.getResult(), StandardCharsets.UTF_8),
                ptBytes.getMasterKeys(), ptBytes.getHeaders());
    }

    /**
     * Returns a {@link CryptoOutputStream} which encrypts the data prior to passing it onto the
     * underlying {@link OutputStream}.
     * 
     * @see #encryptData(MasterKeyProvider, byte[], Map)
     * @see javax.crypto.CipherOutputStream
     */
    public <K extends MasterKey<K>> CryptoOutputStream<K> createEncryptingStream(
            final MasterKeyProvider<K> provider,
            final OutputStream os,
            final Map<String, String> encryptionContext) {
        final MasterKeyRequest keyRequest = MasterKeyRequest.newBuilder()
                .setEncryptionContext(encryptionContext)
                .setStreaming(true)
                .build();
        final List<K> mks = assertNonNull(provider, "provider").getMasterKeysForEncryption(keyRequest);

        final MessageCryptoHandler<K> cryptoHandler = new EncryptionHandler<>(
                mks,
                encryptionContext,
                getEncryptionAlgorithm(),
                getEncryptionFrameSize(),
                getPointCompressionEnabled());
        return new CryptoOutputStream<K>(os, cryptoHandler);
    }

    /**
     * Returns the equivalent to calling
     * {@link #createEncryptingStream(MasterKeyProvider, OutputStream, Map)} with an empty
     * {@code encryptionContext}.
     */
    public <K extends MasterKey<K>> CryptoOutputStream<K> createEncryptingStream(
            final MasterKeyProvider<K> provider,
            final OutputStream os) {
        return createEncryptingStream(provider, os, EMPTY_MAP);
    }

    /**
     * Returns a {@link CryptoInputStream} which encrypts the data after reading it from the
     * underlying {@link InputStream}.
     *
     * @see #encryptData(MasterKeyProvider, byte[], Map)
     * @see javax.crypto.CipherInputStream
     */
    public <K extends MasterKey<K>> CryptoInputStream<K> createEncryptingStream(
            final MasterKeyProvider<K> provider,
            final InputStream is,
            final Map<String, String> encryptionContext) {
        final MasterKeyRequest keyRequest = MasterKeyRequest.newBuilder()
                .setEncryptionContext(encryptionContext)
                .setStreaming(true)
                .build();
        final List<K> mks = assertNonNull(provider, "provider").getMasterKeysForEncryption(keyRequest);

        final MessageCryptoHandler<K> cryptoHandler = new EncryptionHandler<>(
                mks,
                encryptionContext,
                getEncryptionAlgorithm(),
                getEncryptionFrameSize(),
                getPointCompressionEnabled());
        return new CryptoInputStream<K>(is, cryptoHandler);
    }

    /**
     * Returns the equivalent to calling
     * {@link #createEncryptingStream(MasterKeyProvider, InputStream, Map)} with an empty
     * {@code encryptionContext}.
     */
    public <K extends MasterKey<K>> CryptoInputStream<K> createEncryptingStream(
            final MasterKeyProvider<K> provider,
            final InputStream is) {
        return createEncryptingStream(provider, is, EMPTY_MAP);
    }

    /**
     * Returns a {@link CryptoOutputStream} which decrypts the data prior to passing it onto the
     * underlying {@link OutputStream}.
     * 
     * @see #encryptData(MasterKeyProvider, byte[], Map)
     * @see javax.crypto.CipherOutputStream
     */
    public <K extends MasterKey<K>> CryptoOutputStream<K> createDecryptingStream(
            final MasterKeyProvider<K> provider, final OutputStream os) {
        final MessageCryptoHandler<K> cryptoHandler = new DecryptionHandler<>(provider);
        return new CryptoOutputStream<K>(os, cryptoHandler);
    }

    /**
     * Returns a {@link CryptoInputStream} which decrypts the data after reading it from the
     * underlying {@link InputStream}.
     *
     * @see #encryptData(MasterKeyProvider, byte[], Map)
     * @see javax.crypto.CipherInputStream
     */
    public <K extends MasterKey<K>> CryptoInputStream<K> createDecryptingStream(
            final MasterKeyProvider<K> provider, final InputStream is) {
        final MessageCryptoHandler<K> cryptoHandler = new DecryptionHandler<>(provider);
        return new CryptoInputStream<K>(is, cryptoHandler);
    }
}
