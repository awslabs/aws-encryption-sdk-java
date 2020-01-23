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

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Map;

import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.BadCiphertextException;
import com.amazonaws.encryptionsdk.internal.DecryptionHandler;
import com.amazonaws.encryptionsdk.internal.EncryptionHandler;
import com.amazonaws.encryptionsdk.internal.LazyMessageCryptoHandler;
import com.amazonaws.encryptionsdk.internal.MessageCryptoHandler;
import com.amazonaws.encryptionsdk.internal.ProcessingSummary;
import com.amazonaws.encryptionsdk.internal.Utils;
import com.amazonaws.encryptionsdk.keyrings.Keyring;
import com.amazonaws.encryptionsdk.model.EncryptionMaterials;
import com.amazonaws.encryptionsdk.model.EncryptionMaterialsRequest;

import static java.util.Objects.requireNonNull;
import static org.apache.commons.lang3.Validate.isTrue;

/**
 * Provides the primary entry-point to the AWS Encryption SDK. All encryption and decryption
 * operations should start here. Most people will want to use either
 * {@link #encryptData(AwsCryptoConfig, byte[])} and
 * {@link #decryptData(AwsCryptoConfig, byte[])} to encrypt/decrypt things.
 * 
 * <P>
 * The core concepts (and classes) in this SDK are:
 * <ul>
 * <li>{@link AwsCrypto}
 * <li>{@link AwsCryptoConfig}
 * <li>{@link Keyring}
 * <li>{@link EncryptedDataKey}
 * <li>{@link MasterKey}
 * <li>{@link MasterKeyProvider}
 * </ul>
 *
 * <p>
 * {@link AwsCrypto} provides the primary way to encrypt/decrypt data. It can operate on
 * byte-arrays, streams, or {@link java.lang.String Strings}. This data is encrypted using the
 * specified {@link CryptoAlgorithm} and a {@code plaintextDataKey} which is unique to each encrypted message.
 * This {@code plaintextDataKey} is then encrypted using one (or more) {@link MasterKey MasterKeys} or a {@link Keyring}.
 * The process is reversed on decryption with the code selecting a copy of the {@code EncryptedDataKey} protected
 * by a usable {@code MasterKey} or {@code Keyring}, decrypting the {@code EncryptedDataKey}, and
 * then decrypting the message.
 *
 * <p>
 * Note:
 * {@link MasterKey}s and {@link MasterKeyProvider}s have been deprecated in favor of {@link Keyring}s. Keyrings
 * provide a simplified architecture over {@link MasterKey}s and {@link MasterKeyProvider}s; The keyring combines the
 * similar responsibilities of {@link MasterKey}s and {@link MasterKeyProvider}s into one concept, as well as removes
 * all key management logic from {@link CryptoMaterialsManager}s.
 *
 * Due to this simplified architecture, {@link MasterKey}s and {@link MasterKeyProvider}s  are deprecated and will be
 * removed in the future, and new implementations should use {@link Keyring}s. The below discussion on
 * {@link MasterKeyProvider}s is provided for informational purposes as you transition to {@link Keyring}s.
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
@SuppressWarnings("WeakerAccess") // this is a public API
public class AwsCrypto {
    private static final Map<String, String> EMPTY_MAP = Collections.emptyMap();

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

    // These are volatile because we allow unsynchronized writes via our setters, and without setting volatile we could
    // see strange results - e.g. copying these to a local might give different values on subsequent reads from the
    // local. By setting them volatile we ensure that proper memory barriers are applied to ensure things behave in a
    // sensible manner.
    private volatile CryptoAlgorithm encryptionAlgorithm_ = null;
    private volatile int encryptionFrameSize_ = getDefaultFrameSize();

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
     * If {@code frameSize} is 0, then framing is disabled and the entire plaintext will be encrypted
     * in a single block.
     *
     * Note that during encryption arrays of this size will be allocated. Using extremely large frame sizes may pose
     * compatibility issues when the decryptor is running on 32-bit systems. Additionally, Java VM limits may set a
     * platform-specific upper bound to frame sizes.
     */
    public void setEncryptionFrameSize(final int frameSize) {
        if (frameSize < 0) {
            throw new IllegalArgumentException("frameSize must be non-negative");
        }

        encryptionFrameSize_ = frameSize;
    }

    public int getEncryptionFrameSize() {
        return encryptionFrameSize_;
    }

    /**
     * Returns the best estimate for the output length of encrypting a plaintext with the provided
     * {@code plaintextSize} and {@code encryptionContext}. The actual ciphertext may be shorter.
     *
     * This method is equivalent to calling {@link #estimateCiphertextSize(CryptoMaterialsManager, int, Map)} with a
     * {@link DefaultCryptoMaterialsManager} based on the given provider.
     *
     * @deprecated {@link MasterKeyProvider}s have been deprecated in favor of {@link Keyring}s.
     *              Replaced by {@link #estimateCiphertextSize(AwsCryptoConfig, int)}
     */
    @Deprecated
    public <K extends MasterKey<K>> long estimateCiphertextSize(
            final MasterKeyProvider<K> provider,
            final int plaintextSize,
            final Map<String, String> encryptionContext
    ) {
        return estimateCiphertextSize(new DefaultCryptoMaterialsManager(provider), plaintextSize, encryptionContext);
    }

    /**
     * Returns the best estimate for the output length of encrypting a plaintext with the provided
     * {@code plaintextSize} and {@code encryptionContext}. The actual ciphertext may be shorter.
     *
     * @deprecated Replaced by {@link #estimateCiphertextSize(AwsCryptoConfig, int)}
     */
    @Deprecated
    public long estimateCiphertextSize(
            CryptoMaterialsManager materialsManager,
            final int plaintextSize,
            final Map<String, String> encryptionContext
    ) {
        return estimateCiphertextSize(AwsCryptoConfig.builder()
                .cryptoMaterialsManager(materialsManager)
                .encryptionContext(encryptionContext)
                .build(), plaintextSize);
    }

    /**
     * Returns the equivalent to calling
     * {@link #estimateCiphertextSize(MasterKeyProvider, int, Map)} with an empty
     * {@code encryptionContext}.
     *
     * @deprecated {@link MasterKeyProvider}s have been deprecated in favor of {@link Keyring}s.
     *              Replaced by {@link #estimateCiphertextSize(AwsCryptoConfig, int)}
     */
    @Deprecated
    public <K extends MasterKey<K>> long estimateCiphertextSize(
            final MasterKeyProvider<K> provider,
            final int plaintextSize
    ) {
        return estimateCiphertextSize(provider, plaintextSize, EMPTY_MAP);
    }

    /**
     * Returns the equivalent to calling
     * {@link #estimateCiphertextSize(CryptoMaterialsManager, int, Map)} with an empty
     * {@code encryptionContext}.
     *
     * @deprecated Replaced by {@link #estimateCiphertextSize(AwsCryptoConfig, int)}
     */
    @Deprecated
    public long estimateCiphertextSize(
            final CryptoMaterialsManager materialsManager,
            final int plaintextSize
    ) {
        return estimateCiphertextSize(materialsManager, plaintextSize, EMPTY_MAP);
    }

    /**
     * Returns the best estimate for the output length of encrypting a plaintext with the provided
     * {@code plaintextSize} and {@code config}. The actual ciphertext may be shorter.
     *
     * @param config The AwsCryptoConfig containing either a {@link CryptoMaterialsManager} or a {@link Keyring} and
     *               optionally an EncryptionContext
     * @param plaintextSize The size of the plaintext in bytes
     * @return The estimated output length in bytes
     */
    public long estimateCiphertextSize(AwsCryptoConfig config, int plaintextSize) {
        requireNonNull(config, "config is required");

        final EncryptionMaterialsRequest encryptionMaterialsRequest = EncryptionMaterialsRequest.newBuilder()
                .setContext(config.getEncryptionContext())
                .setRequestedAlgorithm(getEncryptionAlgorithm())
                // We're not actually encrypting any data, so don't consume any bytes from the cache's limits. We do need to
                // pass /something/ though, or the cache will be bypassed (as it'll assume this is a streaming encrypt of
                // unknown size).
                .setPlaintextSize(0)
                .build();

        final MessageCryptoHandler cryptoHandler = new EncryptionHandler(
                getEncryptionFrameSize(),
                checkAlgorithm(config.getCryptoMaterialsManager().getMaterialsForEncrypt(encryptionMaterialsRequest))
        );

        return cryptoHandler.estimateOutputSize(plaintextSize);
    }

    /**
     * Returns an encrypted form of {@code plaintext} that has been protected with {@link DataKey}s
     * that are in turn protected by {@link MasterKey MasterKeys} provided by
     * {@code provider}.
     *
     * This method is equivalent to calling {@link #encryptData(CryptoMaterialsManager, byte[], Map)} using a
     * {@link DefaultCryptoMaterialsManager} based on the given provider.
     *
     * @deprecated {@link MasterKeyProvider}s have been deprecated in favor of {@link Keyring}s.
     *              Replaced by {@link #encryptData(AwsCryptoConfig, byte[])}
     */
    @Deprecated
    public <K extends MasterKey<K>> CryptoResult<byte[], K> encryptData(
            final MasterKeyProvider<K> provider,
            final byte[] plaintext,
            final Map<String, String> encryptionContext
    ) {
        //noinspection unchecked
        return (CryptoResult<byte[], K>)
                encryptData(new DefaultCryptoMaterialsManager(provider), plaintext, encryptionContext);
    }

    /**
     * Returns an encrypted form of {@code plaintext} that has been protected with {@link DataKey
     * DataKeys} that are in turn protected by the given CryptoMaterialsProvider.
     *
     * @deprecated Replaced by {@link #encryptData(AwsCryptoConfig, byte[])}
     */
    @Deprecated
    public CryptoResult<byte[], ?> encryptData(
            CryptoMaterialsManager materialsManager,
            final byte[] plaintext,
            final Map<String, String> encryptionContext
    ) {
        return encryptData(AwsCryptoConfig.builder()
                .cryptoMaterialsManager(materialsManager)
                .encryptionContext(encryptionContext).build(), plaintext).toCryptoResult();
    }

    /**
     * Returns the equivalent to calling {@link #encryptData(MasterKeyProvider, byte[], Map)} with
     * an empty {@code encryptionContext}.
     *
     * @deprecated {@link MasterKeyProvider}s have been deprecated in favor of {@link Keyring}s.
     *              Replaced by {@link #encryptData(AwsCryptoConfig, byte[])}
     */
    @Deprecated
    public <K extends MasterKey<K>> CryptoResult<byte[], K> encryptData(final MasterKeyProvider<K> provider,
            final byte[] plaintext) {
        return encryptData(provider, plaintext, EMPTY_MAP);
    }

    /**
     * Returns the equivalent to calling {@link #encryptData(CryptoMaterialsManager, byte[], Map)} with
     * an empty {@code encryptionContext}.
     *
     * @deprecated Replaced by {@link #encryptData(AwsCryptoConfig, byte[])}
     */
    @Deprecated
    public CryptoResult<byte[], ?> encryptData(
            final CryptoMaterialsManager materialsManager,
            final byte[] plaintext
    ) {
        return encryptData(materialsManager, plaintext, EMPTY_MAP);
    }

    /**
     * Returns an encrypted form of {@code plaintext} that has been protected with either the {@link CryptoMaterialsManager}
     * or the {@link Keyring} specified in the {@link AwsCryptoConfig}.
     *
     * @param config The AwsCryptoConfig containing either a {@link CryptoMaterialsManager} or a {@link Keyring} and
     *               optionally an EncryptionContext
     * @param plaintext The plaintext to encrypt
     * @return An {@link AwsCryptoResult} containing the encrypted data
     */
    public AwsCryptoResult<byte[]> encryptData(final AwsCryptoConfig config,
                                               final byte[] plaintext) {
        requireNonNull(config, "config is required");
        requireNonNull(config, "plaintext is required");

        final EncryptionMaterialsRequest request = EncryptionMaterialsRequest.newBuilder()
                .setContext(config.getEncryptionContext())
                .setRequestedAlgorithm(getEncryptionAlgorithm())
                .setPlaintext(plaintext)
                .build();

        final EncryptionMaterials encryptionMaterials =
                checkAlgorithm(config.getCryptoMaterialsManager().getMaterialsForEncrypt(request));

        final MessageCryptoHandler cryptoHandler = new EncryptionHandler(
                getEncryptionFrameSize(), encryptionMaterials);

        final int outSizeEstimate = cryptoHandler.estimateOutputSize(plaintext.length);
        final byte[] out = new byte[outSizeEstimate];
        int outLen = cryptoHandler.processBytes(plaintext, 0, plaintext.length, out, 0).getBytesWritten();
        outLen += cryptoHandler.doFinal(out, outLen);

        final byte[] outBytes = Utils.truncate(out, outLen);

        return new AwsCryptoResult<>(outBytes, encryptionMaterials.getKeyringTrace(),
                cryptoHandler.getMasterKeys(), cryptoHandler.getHeaders());
    }

    /**
     * Calls {@link #encryptData(MasterKeyProvider, byte[], Map)} on the UTF-8 encoded bytes of
     * {@code plaintext} and base64 encodes the result.
     * @deprecated Use the {@link #encryptData(MasterKeyProvider, byte[], Map)} and
     * {@link #decryptData(MasterKeyProvider, byte[])} APIs instead. {@code encryptString} and {@code decryptString}
     * work as expected if you use them together. However, to work with other language implementations of the AWS 
     * Encryption SDK, you need to base64-decode the output of {@code encryptString} and base64-encode the input to
     * {@code decryptString}. These deprecated APIs will be removed in the future.
     */
    @Deprecated
    public <K extends MasterKey<K>> CryptoResult<String, K> encryptString(
            final MasterKeyProvider<K> provider,
            final String plaintext,
            final Map<String, String> encryptionContext
    ) {
        //noinspection unchecked
        return (CryptoResult<String, K>)
                encryptString(new DefaultCryptoMaterialsManager(provider), plaintext, encryptionContext);
    }

    /**
     * Calls {@link #encryptData(CryptoMaterialsManager, byte[], Map)} on the UTF-8 encoded bytes of
     * {@code plaintext} and base64 encodes the result.
     * @deprecated Use the {@link #encryptData(CryptoMaterialsManager, byte[], Map)} and
     * {@link #decryptData(CryptoMaterialsManager, byte[])} APIs instead. {@code encryptString} and {@code decryptString}
     * work as expected if you use them together. However, to work with other language implementations of the AWS 
     * Encryption SDK, you need to base64-decode the output of {@code encryptString} and base64-encode the input to
     * {@code decryptString}. These deprecated APIs will be removed in the future.
     */
    @Deprecated
    public CryptoResult<String, ?> encryptString(
            CryptoMaterialsManager materialsManager,
            final String plaintext,
            final Map<String, String> encryptionContext
    ) {
        final CryptoResult<byte[], ?> ctBytes = encryptData(
                materialsManager,
                plaintext.getBytes(StandardCharsets.UTF_8),
                encryptionContext
        );
        return new CryptoResult<>(Utils.encodeBase64String(ctBytes.getResult()),
                                  ctBytes.getMasterKeys(), ctBytes.getHeaders());
    }

    /**
     * Returns the equivalent to calling {@link #encryptString(MasterKeyProvider, String, Map)} with
     * an empty {@code encryptionContext}.
     * @deprecated Use the {@link #encryptData(MasterKeyProvider, byte[])} and
     * {@link #decryptData(MasterKeyProvider, byte[])} APIs instead. {@code encryptString} and {@code decryptString}
     * work as expected if you use them together. However, to work with other language implementations of the AWS 
     * Encryption SDK, you need to base64-decode the output of {@code encryptString} and base64-encode the input to
     * {@code decryptString}. These deprecated APIs will be removed in the future.
     */
    @Deprecated
    public <K extends MasterKey<K>> CryptoResult<String, K> encryptString(final MasterKeyProvider<K> provider,
            final String plaintext) {
        return encryptString(provider, plaintext, EMPTY_MAP);
    }

    /**
     * Returns the equivalent to calling {@link #encryptString(CryptoMaterialsManager, String, Map)} with
     * an empty {@code encryptionContext}.
     * @deprecated Use the {@link #encryptData(CryptoMaterialsManager, byte[])} and
     * {@link #decryptData(CryptoMaterialsManager, byte[])} APIs instead. {@code encryptString} and {@code decryptString}
     * work as expected if you use them together. However, to work with other language implementations of the AWS 
     * Encryption SDK, you need to base64-decode the output of {@code encryptString} and base64-encode the input to
     * {@code decryptString}. These deprecated APIs will be removed in the future.
     */
    @Deprecated
    public CryptoResult<String, ?> encryptString(
            final CryptoMaterialsManager materialsManager,
            final String plaintext
    ) {
        return encryptString(materialsManager, plaintext, EMPTY_MAP);
    }

    /**
     * Decrypts the provided {@code ciphertext} by requesting that the {@code provider} unwrap any
     * usable {@link DataKey} in the ciphertext and then decrypts the ciphertext using that
     * {@code DataKey}.
     *
     * @deprecated {@link MasterKeyProvider}s have been deprecated in favor of {@link Keyring}s.
     *              Replaced by {@link #decryptData(AwsCryptoConfig, byte[])}
     */
    @Deprecated
    public <K extends MasterKey<K>> CryptoResult<byte[], K> decryptData(final MasterKeyProvider<K> provider,
            final byte[] ciphertext) {
        return decryptData(Utils.assertNonNull(provider, "provider"), new
                ParsedCiphertext(ciphertext));
    }

    /**
     * Decrypts the provided ciphertext by delegating to the provided materialsManager to obtain the decrypted
     * {@link DataKey}.
     *
     * @param materialsManager the {@link CryptoMaterialsManager} to use for decryption operations.
     * @param ciphertext the ciphertext to attempt to decrypt.
     * @return the {@link CryptoResult} with the decrypted data.
     *
     * @deprecated Replaced by {@link #decryptData(AwsCryptoConfig, byte[])}
     */
    @Deprecated
    public CryptoResult<byte[], ?> decryptData(
            final CryptoMaterialsManager materialsManager,
            final byte[] ciphertext
    ) {
        return decryptData(Utils.assertNonNull(materialsManager, "materialsManager"),
                           new ParsedCiphertext(ciphertext));
    }

    /**
     * @see #decryptData(MasterKeyProvider, byte[])
     *
     * @deprecated {@link MasterKeyProvider}s have been deprecated in favor of {@link Keyring}s.
     *              Replaced by {@link #decryptData(AwsCryptoConfig, byte[])}
     */
    @SuppressWarnings("unchecked")
    @Deprecated
    public <K extends MasterKey<K>> CryptoResult<byte[], K> decryptData(
            final MasterKeyProvider<K> provider, final ParsedCiphertext ciphertext) {
        Utils.assertNonNull(provider, "provider");
        return (CryptoResult<byte[], K>) decryptData(new DefaultCryptoMaterialsManager(provider), ciphertext);
    }

    /**
     * @see #decryptData(CryptoMaterialsManager, byte[])
     *
     * @deprecated Replaced by {@link #decryptData(AwsCryptoConfig, byte[])}
     */
    @Deprecated
    public CryptoResult<byte[], ?> decryptData(
            final CryptoMaterialsManager materialsManager,
            final ParsedCiphertext ciphertext
    ) {
        return decryptData(AwsCryptoConfig.builder().cryptoMaterialsManager(materialsManager).build(),
                ciphertext).toCryptoResult();
    }

    /**
     * Decrypts the provided ciphertext using the {@link CryptoMaterialsManager} or the {@link Keyring} 
     * specified in the {@link AwsCryptoConfig}.
     *
     * @param config The AwsCryptoConfig containing either a {@link CryptoMaterialsManager} or a {@link Keyring}
     * @param ciphertext The ciphertext to decrypt
     * @return An {@link AwsCryptoResult} containing the decrypted data
     */
    public AwsCryptoResult<byte[]> decryptData(
            final AwsCryptoConfig config,
            final byte[] ciphertext
    ) {
        return decryptData(config, new ParsedCiphertext(ciphertext));
    }

    /**
     * Decrypts the provided ciphertext using the {@link CryptoMaterialsManager} or the {@link Keyring} 
     * specified in the {@link AwsCryptoConfig}.
     *
     * @param config The AwsCryptoConfig containing either a {@link CryptoMaterialsManager} or a {@link Keyring}
     * @param ciphertext The ciphertext to decrypt
     * @return An {@link AwsCryptoResult} containing the decrypted data
     */
    private AwsCryptoResult<byte[]> decryptData(
            final AwsCryptoConfig config,
            final ParsedCiphertext ciphertext
    ) {
        requireNonNull(config, "config is required");
        requireNonNull(ciphertext, "ciphertext is required");

        final MessageCryptoHandler cryptoHandler = DecryptionHandler.create(config.getCryptoMaterialsManager(), ciphertext);

        final byte[] ciphertextBytes = ciphertext.getCiphertext();
        final int contentLen = ciphertextBytes.length - ciphertext.getOffset();
        final int outSizeEstimate = cryptoHandler.estimateOutputSize(contentLen);
        final byte[] out = new byte[outSizeEstimate];
        final ProcessingSummary processed = cryptoHandler.processBytes(ciphertextBytes, ciphertext.getOffset(),
                contentLen, out, 0);
        if (processed.getBytesProcessed() != contentLen) {
            throw new BadCiphertextException("Unable to process entire ciphertext. May have trailing data.");
        }
        int outLen = processed.getBytesWritten();
        outLen += cryptoHandler.doFinal(out, outLen);

        final byte[] outBytes = Utils.truncate(out, outLen);

        return new AwsCryptoResult<>(outBytes, cryptoHandler.getKeyringTrace(),
                cryptoHandler.getMasterKeys(), cryptoHandler.getHeaders());
    }

    /**
     * Base64 decodes the {@code ciphertext} prior to decryption and then treats the results as a
     * UTF-8 encoded string.
     *
     * @see #decryptData(MasterKeyProvider, byte[])
     * @deprecated Use the {@link #decryptData(MasterKeyProvider, byte[])} and
     * {@link #encryptData(MasterKeyProvider, byte[], Map)} APIs instead. {@code encryptString} and {@code decryptString}
     * work as expected if you use them together. However, to work with other language implementations of the AWS 
     * Encryption SDK, you need to base64-decode the output of {@code encryptString} and base64-encode the input to
     * {@code decryptString}. These deprecated APIs will be removed in the future.
     */
    @Deprecated
    @SuppressWarnings("unchecked")
    public <K extends MasterKey<K>> CryptoResult<String, K> decryptString(
            final MasterKeyProvider<K> provider,
            final String ciphertext
    ) {
        return (CryptoResult<String, K>) decryptString(new DefaultCryptoMaterialsManager(provider), ciphertext);
    }

    /**
     * Base64 decodes the {@code ciphertext} prior to decryption and then treats the results as a
     * UTF-8 encoded string.
     *
     * @see #decryptData(CryptoMaterialsManager, byte[])
     * @deprecated Use the {@link #decryptData(CryptoMaterialsManager, byte[])} and
     * {@link #encryptData(CryptoMaterialsManager, byte[], Map)} APIs instead. {@code encryptString}  and {@code decryptString}
     * work as expected if you use them together. However, to work with other language implementations of the AWS 
     * Encryption SDK, you need to base64-decode the output of {@code encryptString} and base64-encode the input to
     * {@code decryptString}. These deprecated APIs will be removed in the future.
     */
    @Deprecated
    public CryptoResult<String, ?> decryptString(final CryptoMaterialsManager provider,
                                                                          final String ciphertext) {
        Utils.assertNonNull(provider, "provider");
        final byte[] ciphertextBytes;
        try {
            ciphertextBytes = Utils.decodeBase64String(Utils.assertNonNull(ciphertext, "ciphertext"));
        } catch (final IllegalArgumentException ex) {
            throw new BadCiphertextException("Invalid base 64", ex);
        }
        final CryptoResult<byte[], ?> ptBytes = decryptData(provider, ciphertextBytes);
        //noinspection unchecked
        return new CryptoResult(
                new String(ptBytes.getResult(), StandardCharsets.UTF_8),
                ptBytes.getMasterKeys(), ptBytes.getHeaders());
    }

    /**
     * Returns a {@link CryptoOutputStream} which encrypts the data prior to passing it onto the
     * underlying {@link OutputStream}.
     *
     * @see #encryptData(MasterKeyProvider, byte[], Map)
     * @see javax.crypto.CipherOutputStream
     *
     * @deprecated {@link MasterKeyProvider}s have been deprecated in favor of {@link Keyring}s.
     *              Replaced by {@link #createEncryptingStream(AwsCryptoConfig, OutputStream)}
     */
    @Deprecated
    public <K extends MasterKey<K>> CryptoOutputStream<K> createEncryptingStream(
            final MasterKeyProvider<K> provider,
            final OutputStream os,
            final Map<String, String> encryptionContext
    ) {
        //noinspection unchecked
        return (CryptoOutputStream<K>)
                createEncryptingStream(new DefaultCryptoMaterialsManager(provider), os, encryptionContext);
    }

    /**
     * Returns a {@link CryptoOutputStream} which encrypts the data prior to passing it onto the
     * underlying {@link OutputStream}.
     * 
     * @see #encryptData(MasterKeyProvider, byte[], Map)
     * @see javax.crypto.CipherOutputStream
     * 
     * @deprecated Replaced by {@link #createEncryptingStream(AwsCryptoConfig, OutputStream)}
     */
    @Deprecated
    public CryptoOutputStream<?> createEncryptingStream(
            final CryptoMaterialsManager materialsManager,
            final OutputStream os,
            final Map<String, String> encryptionContext
    ) {
        return createEncryptingStream(AwsCryptoConfig.builder()
                .cryptoMaterialsManager(materialsManager)
                .encryptionContext(encryptionContext)
        .build(), os).toCryptoOutputStream();
    }

    /**
     * Returns the equivalent to calling
     * {@link #createEncryptingStream(MasterKeyProvider, OutputStream, Map)} with an empty
     * {@code encryptionContext}.
     *
     * @deprecated {@link MasterKeyProvider}s have been deprecated in favor of {@link Keyring}s.
     *              Replaced by {@link #createEncryptingStream(AwsCryptoConfig, OutputStream)}
     */
    @Deprecated
    public <K extends MasterKey<K>> CryptoOutputStream<K> createEncryptingStream(
            final MasterKeyProvider<K> provider,
            final OutputStream os) {
        return createEncryptingStream(provider, os, EMPTY_MAP);
    }

    /**
     * Returns the equivalent to calling
     * {@link #createEncryptingStream(CryptoMaterialsManager, OutputStream, Map)} with an empty
     * {@code encryptionContext}.
     *
     * @deprecated Replaced by {@link #createEncryptingStream(AwsCryptoConfig, OutputStream)}
     */
    @Deprecated
    public CryptoOutputStream<?> createEncryptingStream(
            final CryptoMaterialsManager materialsManager,
            final OutputStream os
    ) {
        return createEncryptingStream(materialsManager, os, EMPTY_MAP);
    }

    /**
     * Returns a {@link AwsCryptoOutputStream} which encrypts the data prior to passing it onto the
     * underlying {@link OutputStream}.
     *
     * @see #encryptData(AwsCryptoConfig, byte[])
     * @see javax.crypto.CipherOutputStream
     */
    public AwsCryptoOutputStream createEncryptingStream(
            final AwsCryptoConfig config,
            final OutputStream os
    ) {
        return new AwsCryptoOutputStream(os, getEncryptingStreamHandler(
                config.getCryptoMaterialsManager(), config.encryptionContext));
    }

    /**
     * Returns a {@link CryptoInputStream} which encrypts the data after reading it from the
     * underlying {@link InputStream}.
     *
     * @see #encryptData(MasterKeyProvider, byte[], Map)
     * @see javax.crypto.CipherInputStream
     *
     * @deprecated {@link MasterKeyProvider}s have been deprecated in favor of {@link Keyring}s.
     *              Replaced by {@link #createEncryptingStream(AwsCryptoConfig, InputStream)}
     */
    @Deprecated
    public <K extends MasterKey<K>> CryptoInputStream<K> createEncryptingStream(
            final MasterKeyProvider<K> provider,
            final InputStream is,
            final Map<String, String> encryptionContext
    ) {
        //noinspection unchecked
        return (CryptoInputStream<K>)
                createEncryptingStream(new DefaultCryptoMaterialsManager(provider), is, encryptionContext);
    }

    /**
     * Returns a {@link CryptoInputStream} which encrypts the data after reading it from the
     * underlying {@link InputStream}.
     *
     * @see #encryptData(MasterKeyProvider, byte[], Map)
     * @see javax.crypto.CipherInputStream
     *
     * @deprecated Replaced by {@link #createEncryptingStream(AwsCryptoConfig, InputStream)}
     */
    @Deprecated
    public CryptoInputStream<?> createEncryptingStream(
            CryptoMaterialsManager materialsManager,
            final InputStream is,
            final Map<String, String> encryptionContext
    ) {
        return createEncryptingStream(AwsCryptoConfig.builder()
                .cryptoMaterialsManager(materialsManager)
                .encryptionContext(encryptionContext).build(), is)
                .toCryptoInputStream();
    }

    /**
     * Returns the equivalent to calling
     * {@link #createEncryptingStream(MasterKeyProvider, InputStream, Map)} with an empty
     * {@code encryptionContext}.
     *
     * @deprecated {@link MasterKeyProvider}s have been deprecated in favor of {@link Keyring}s.
     *              Replaced by {@link #createEncryptingStream(AwsCryptoConfig, InputStream)}
     */
    @Deprecated
    public <K extends MasterKey<K>> CryptoInputStream<K> createEncryptingStream(
            final MasterKeyProvider<K> provider,
            final InputStream is
    ) {
        return createEncryptingStream(provider, is, EMPTY_MAP);
    }

    /**
     * Returns the equivalent to calling
     * {@link #createEncryptingStream(CryptoMaterialsManager, InputStream, Map)} with an empty
     * {@code encryptionContext}.
     *
     * @deprecated Replaced by {@link #createEncryptingStream(AwsCryptoConfig, InputStream)}
     */
    @Deprecated
    public CryptoInputStream<?> createEncryptingStream(
            final CryptoMaterialsManager materialsManager,
            final InputStream is
    ) {
        return createEncryptingStream(AwsCryptoConfig.builder()
                .cryptoMaterialsManager(materialsManager).build(), is).toCryptoInputStream();
    }

    /**
     * Returns a {@link AwsCryptoInputStream} which encrypts the data after reading it from the
     * underlying {@link InputStream}.
     *
     * @see #encryptData(AwsCryptoConfig, byte[])
     * @see javax.crypto.CipherInputStream
     */
    public AwsCryptoInputStream createEncryptingStream(
            final AwsCryptoConfig config,
            final InputStream is
    ) {
        requireNonNull(config, "config is required");
        final MessageCryptoHandler cryptoHandler = getEncryptingStreamHandler(
                config.getCryptoMaterialsManager(), config.getEncryptionContext());

        return new AwsCryptoInputStream(is, cryptoHandler);
    }

    /**
     * Returns a {@link CryptoOutputStream} which decrypts the data prior to passing it onto the
     * underlying {@link OutputStream}.
     *
     * @see #decryptData(MasterKeyProvider, byte[])
     * @see javax.crypto.CipherOutputStream
     *
     * @deprecated {@link MasterKeyProvider}s have been deprecated in favor of {@link Keyring}s.
     *              Replaced by {@link #createDecryptingStream(AwsCryptoConfig, OutputStream)}
     */
    @Deprecated
    public <K extends MasterKey<K>> CryptoOutputStream<K> createDecryptingStream(
            final MasterKeyProvider<K> provider, final OutputStream os) {
        final MessageCryptoHandler cryptoHandler = DecryptionHandler.create(provider);
        return new CryptoOutputStream<K>(os, cryptoHandler);
    }

    /**
     * Returns a {@link CryptoInputStream} which decrypts the data after reading it from the
     * underlying {@link InputStream}.
     *
     * @see #decryptData(MasterKeyProvider, byte[])
     * @see javax.crypto.CipherInputStream
     *
     * @deprecated {@link MasterKeyProvider}s have been deprecated in favor of {@link Keyring}s.
     *              Replaced by {@link #createDecryptingStream(AwsCryptoConfig, InputStream)}
     */
    @Deprecated
    public <K extends MasterKey<K>> CryptoInputStream<K> createDecryptingStream(
            final MasterKeyProvider<K> provider, final InputStream is) {
        final MessageCryptoHandler cryptoHandler = DecryptionHandler.create(provider);
        return new CryptoInputStream<K>(is, cryptoHandler);
    }

    /**
     * Returns a {@link CryptoOutputStream} which decrypts the data prior to passing it onto the
     * underlying {@link OutputStream}.
     *
     * @see #decryptData(CryptoMaterialsManager, byte[])
     * @see javax.crypto.CipherOutputStream
     *
     * @deprecated Replaced by {@link #createDecryptingStream(AwsCryptoConfig, OutputStream)}
     */
    @Deprecated
    public CryptoOutputStream<?> createDecryptingStream(
            final CryptoMaterialsManager materialsManager, final OutputStream os
    ) {
        return createDecryptingStream(AwsCryptoConfig.builder().cryptoMaterialsManager(materialsManager).build(),
                os).toCryptoOutputStream();
    }

    /**
     * Returns a {@link AwsCryptoOutputStream} which decrypts the data prior to passing it onto the
     * underlying {@link OutputStream}.
     *
     * @see #decryptData(AwsCryptoConfig, byte[])
     * @see javax.crypto.CipherOutputStream
     */
    public AwsCryptoOutputStream createDecryptingStream(
            final AwsCryptoConfig config, final OutputStream os
    ) {
        final MessageCryptoHandler cryptoHandler = DecryptionHandler.create(config.getCryptoMaterialsManager());
        return new AwsCryptoOutputStream(os, cryptoHandler);
    }

    /**
     * Returns a {@link CryptoInputStream} which decrypts the data after reading it from the
     * underlying {@link InputStream}.
     *
     * @see #encryptData(CryptoMaterialsManager, byte[], Map)
     * @see javax.crypto.CipherInputStream
     *
     * @deprecated Replaced by {@link #createDecryptingStream(AwsCryptoConfig, InputStream)}
     */
    @Deprecated
    public CryptoInputStream<?> createDecryptingStream(
            final CryptoMaterialsManager materialsManager, final InputStream is
    ) {
        return createDecryptingStream(AwsCryptoConfig.builder().cryptoMaterialsManager(materialsManager).build(),
                is).toCryptoInputStream();
    }

    /**
     * Returns a {@link AwsCryptoInputStream} which decrypts the data after reading it from the
     * underlying {@link InputStream}.
     *
     * @see #encryptData(AwsCryptoConfig, byte[])
     * @see javax.crypto.CipherInputStream
     */
    public AwsCryptoInputStream createDecryptingStream(final AwsCryptoConfig config, final InputStream is
    ) {
        requireNonNull(config, "config is required");

        final MessageCryptoHandler cryptoHandler = DecryptionHandler.create(config.getCryptoMaterialsManager());
        return new AwsCryptoInputStream(is, cryptoHandler);
    }

    private MessageCryptoHandler getEncryptingStreamHandler(
            CryptoMaterialsManager materialsManager, Map<String, String> encryptionContext
    ) {
        Utils.assertNonNull(materialsManager, "materialsManager");
        Utils.assertNonNull(encryptionContext, "encryptionContext");

        EncryptionMaterialsRequest.Builder requestBuilder = EncryptionMaterialsRequest.newBuilder()
                                                                                      .setContext(encryptionContext)
                                                                                      .setRequestedAlgorithm(getEncryptionAlgorithm());

        return new LazyMessageCryptoHandler(info -> {
            // Hopefully we know the input size now, so we can pass it along to the CMM.
            if (info.getMaxInputSize() != -1) {
                requestBuilder.setPlaintextSize(info.getMaxInputSize());
            }

            return new EncryptionHandler(
                    getEncryptionFrameSize(),
                    checkAlgorithm(materialsManager.getMaterialsForEncrypt(requestBuilder.build()))
            );
        });
    }

    private EncryptionMaterials checkAlgorithm(EncryptionMaterials result) {
        if (encryptionAlgorithm_ != null && result.getAlgorithm() != encryptionAlgorithm_) {
            throw new AwsCryptoException(
                    String.format("Materials manager ignored requested algorithm; algorithm %s was set on AwsCrypto " +
                                          "but %s was selected", encryptionAlgorithm_, result.getAlgorithm())
            );
        }

        return result;
    }

    /**
     * Configuration class for managing inputs to the encryption and decryption methods in AwsCrypto.
     * Either a {@link CryptoMaterialsManager} or a {@link Keyring} is required, and a {@code Map<String, String}
     * Encryption Context is optional.
     *
     * Use {@code AwsCryptoConfig.builder()} to construct an instance.
     */
    public static class AwsCryptoConfig {

        private final CryptoMaterialsManager cryptoMaterialsManager;
        private final Map<String, String> encryptionContext;

        /**
         * Gets the CryptoMaterialsManager.
         *
         * @return The CryptoMaterialsManager
         */
        public CryptoMaterialsManager getCryptoMaterialsManager() {
            return cryptoMaterialsManager;
        }

        /**
         * Gets the encryption context.
         *
         * @return The encryption context
         */
        public Map<String, String> getEncryptionContext() {
            return encryptionContext;
        }

        /**
         * Instantiates a new Builder for constructing AwsCryptoConfig instances.
         *
         * @return The Builder
         */
        public static Builder builder() {
            return new Builder();
        }

        private AwsCryptoConfig(Builder builder) {
            isTrue(builder.cryptoMaterialsManager != null || builder.keyring != null,
                    "Either cryptoMaterialsManager or keyring is required");
            isTrue(builder.cryptoMaterialsManager == null || builder.keyring == null,
                    "Only one of cryptoMaterialsManager or keyring may be specified");
            requireNonNull(builder.encryptionContext, "encryptionContext is required");

            this.cryptoMaterialsManager = builder.cryptoMaterialsManager == null ?
                    new DefaultCryptoMaterialsManager(builder.keyring) : builder.cryptoMaterialsManager;
            this.encryptionContext = builder.encryptionContext;
        }

        public static class Builder {

            private CryptoMaterialsManager cryptoMaterialsManager;
            private Keyring keyring;
            private Map<String, String> encryptionContext = EMPTY_MAP;

            /**
             * Sets the {@link CryptoMaterialsManager}. Either a {@link CryptoMaterialsManager} or a
             * {@link Keyring} is required.
             *
             * @param cryptoMaterialsManager The {@link CryptoMaterialsManager}
             * @return The Builder, for method chaining
             */
            public Builder cryptoMaterialsManager(CryptoMaterialsManager cryptoMaterialsManager) {
                requireNonNull(cryptoMaterialsManager, "cryptoMaterialsManager is required");
                this.cryptoMaterialsManager = cryptoMaterialsManager;
                return this;
            }

            /**
             * Sets the {@link Keyring}. Either a {@link CryptoMaterialsManager} or a
             * {@link Keyring} is required.
             *
             * @param keyring The {@link Keyring}
             * @return The Builder, for method chaining
             */
            public Builder keyring(Keyring keyring) {
                requireNonNull(keyring, "keyring is required");
                this.keyring = keyring;
                return this;
            }

            /**
             * Sets the (optional) encryption context map.
             *
             * @param encryptionContext The encryption context
             * @return The Builder, for method chaining
             */
            public Builder encryptionContext(Map<String, String> encryptionContext) {
                requireNonNull(encryptionContext, "encryptionContext is required");
                this.encryptionContext = encryptionContext;
                return this;
            }

            /**
             * Constructs the AwsCryptoConfig instance.
             *
             * @return The AwsCryptoConfig instance
             */
            public AwsCryptoConfig build() {
                return new AwsCryptoConfig(this);
            }
        }
    }
}
