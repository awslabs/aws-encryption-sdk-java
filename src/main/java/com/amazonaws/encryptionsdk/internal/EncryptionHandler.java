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

import static com.amazonaws.encryptionsdk.internal.Utils.assertNonNull;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.DataKey;
import com.amazonaws.encryptionsdk.MasterKey;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.BadCiphertextException;
import com.amazonaws.encryptionsdk.model.CiphertextFooters;
import com.amazonaws.encryptionsdk.model.CiphertextHeaders;
import com.amazonaws.encryptionsdk.model.CiphertextType;
import com.amazonaws.encryptionsdk.model.ContentType;
import com.amazonaws.encryptionsdk.model.KeyBlob;
import com.amazonaws.util.Base64;

/**
 * This class implements the CryptoHandler interface by providing methods for the encryption of
 * plaintext data.
 * 
 * <p>
 * This class creates the ciphertext headers and delegates the encryption of the plaintext to the
 * {@link BlockEncryptionHandler} or {@link FrameEncryptionHandler} based on the content type.
 */
public class EncryptionHandler<K extends MasterKey<K>> implements MessageCryptoHandler<K> {
    private static final SecureRandom RND = new SecureRandom();
    private static final CiphertextType CIPHERTEXT_TYPE = CiphertextType.CUSTOMER_AUTHENTICATED_ENCRYPTED_DATA;

    private final Map<String, String> encryptionContext_;
    private final CryptoAlgorithm cryptoAlgo_;
    private final DataKey<K> dataKey_;
    private final List<K> masterKeys_;
    private final List<KeyBlob> keyBlobs_;
    private final SecretKey encryptionKey_;
    private final byte version_;
    private final CiphertextType type_;
    private final byte nonceLen_;
    private final byte[] messageId_;
    private final KeyPair trailingKeys_;
    private final Signature trailingSig_;

    private final CiphertextHeaders ciphertextHeaders_;
    private final byte[] ciphertextHeaderBytes_;
    private final CryptoHandler contentCryptoHandler_;

    private boolean firstOperation_ = true;
    private boolean complete_ = false;
    private boolean pointCompressionEnabled_ = true;

    /**
     * Create an encryption handler using the provided master key and encryption context.
     *
     * @param masterKeys
     *            the master keys to use.
     * @param encryptionContext
     *            the encryption context to use.
     * @param cryptoAlgorithm
     *            the cryptography algorithm to use for encryption
     * @param frameSize
     *            the size of the frames to use in storing encrypted content
     * @throws AwsCryptoException
     *            if the encryption context or master key is null.
     */
    public EncryptionHandler(final List<K> masterKeys, final Map<String, String> encryptionContext,
                             final CryptoAlgorithm cryptoAlgorithm, final int frameSize)
            throws AwsCryptoException {
        this(masterKeys, encryptionContext, cryptoAlgorithm, frameSize, true);
    }

    /**
     * Create an encryption handler using the provided master key and encryption context.
     * 
     * @param masterKeys
     *            the master keys to use.
     * @param encryptionContext
     *            the encryption context to use.
     * @param cryptoAlgorithm
     *            the cryptography algorithm to use for encryption
     * @param frameSize
     *            the size of the frames to use in storing encrypted content
     * @param pointCompressionEnabled
     *            determines if point compression is used or not
     * @throws AwsCryptoException
     *             if the encryption context or master key is null.
     */
    public EncryptionHandler(final List<K> masterKeys, final Map<String, String> encryptionContext,
            final CryptoAlgorithm cryptoAlgorithm, final int frameSize, final boolean pointCompressionEnabled)
            throws AwsCryptoException {
        assertNonNull(masterKeys, "customerMasterKey");

        this.pointCompressionEnabled_ = pointCompressionEnabled;

        cryptoAlgo_ = assertNonNull(cryptoAlgorithm, "cryptoAlgorithm");
        encryptionContext_ = new HashMap<>(assertNonNull(encryptionContext, "encryptionContext"));
        if (cryptoAlgo_.getTrailingSignatureLength() > 0) {
            try {
                trailingKeys_ = generateTrailingSigKeyPair();
                if (encryptionContext_.containsKey(Constants.EC_PUBLIC_KEY_FIELD)) {
                    throw new IllegalArgumentException("EncryptionContext contains reserved field "
                            + Constants.EC_PUBLIC_KEY_FIELD);
                }
                encryptionContext_.put(Constants.EC_PUBLIC_KEY_FIELD, serializeTrailingKeyForEc());
                trailingSig_ = Signature.getInstance(cryptoAlgo_.getTrailingSignatureAlgo());
                trailingSig_.initSign(trailingKeys_.getPrivate(), RND);
            } catch (final GeneralSecurityException ex) {
                throw new AwsCryptoException(ex);
            }
        } else {
            trailingKeys_ = null;
            trailingSig_ = null;
        }

        // set default values
        version_ = VersionInfo.CURRENT_CIPHERTEXT_VERSION;
        type_ = CIPHERTEXT_TYPE;
        nonceLen_ = cryptoAlgo_.getNonceLen();

        if (masterKeys.isEmpty()) {
            throw new IllegalArgumentException("No master keys provided");
        }
        masterKeys_ = Collections.unmodifiableList(masterKeys);
        dataKey_ = masterKeys.get(0).generateDataKey(cryptoAlgorithm, encryptionContext_);

        keyBlobs_ = new ArrayList<>(masterKeys.size());
        keyBlobs_.add(new KeyBlob(dataKey_));
        for (int x = 1; x < masterKeys.size(); x++) {
            keyBlobs_.add(new KeyBlob(masterKeys.get(x)
                    .encryptDataKey(cryptoAlgo_, encryptionContext_, dataKey_)));
        }

        ContentType contentType;
        if (frameSize > 0) {
            contentType = ContentType.FRAME;
        } else if (frameSize == 0) {
            contentType = ContentType.SINGLEBLOCK;
        } else {
            throw new AwsCryptoException("Frame size cannot be negative");
        }

        final CiphertextHeaders unsignedHeaders = createCiphertextHeaders(contentType, frameSize);
        try {
            encryptionKey_ = cryptoAlgo_.getEncryptionKeyFromDataKey(dataKey_.getKey(), unsignedHeaders);
        } catch (final InvalidKeyException ex) {
            throw new AwsCryptoException(ex);
        }
        ciphertextHeaders_ = signCiphertextHeaders(unsignedHeaders);
        ciphertextHeaderBytes_ = ciphertextHeaders_.toByteArray();
        messageId_ = ciphertextHeaders_.getMessageId();

        switch (contentType) {
            case FRAME:
                contentCryptoHandler_ = new FrameEncryptionHandler(encryptionKey_, nonceLen_, cryptoAlgo_, messageId_,
                        frameSize);
                break;
            case SINGLEBLOCK:
                contentCryptoHandler_ = new BlockEncryptionHandler(encryptionKey_, nonceLen_, cryptoAlgo_, messageId_);
                break;
            default:
                // should never get here because a valid content type is always
                // set above based on the frame size.
                throw new AwsCryptoException("Unknown content type.");
        }
    }

    /**
     * Encrypt a block of bytes from {@code in} putting the plaintext result into {@code out}.
     * 
     * <p>
     * It encrypts by performing the following operations:
     * <ol>
     * <li>if this is the first call to encrypt, write the ciphertext headers to the output being
     * returned.</li>
     * <li>else, pass off the input data to underlying content cryptohandler.</li>
     * </ol>
     * 
     * @param in
     *            the input byte array.
     * @param off
     *            the offset into the in array where the data to be encrypted starts.
     * @param len
     *            the number of bytes to be encrypted.
     * @param out
     *            the output buffer the encrypted bytes go into.
     * @param outOff
     *            the offset into the output byte array the encrypted data starts at.
     * @return the number of bytes written to out and processed
     * @throws AwsCryptoException
     *             if len or offset values are negative.
     * @throws BadCiphertextException
     *             thrown by the underlying cipher handler.
     */
    @Override
    public ProcessingSummary processBytes(final byte[] in, final int off, final int len, final byte[] out,
            final int outOff)
            throws AwsCryptoException, BadCiphertextException {
        if (len < 0 || off < 0) {
            throw new AwsCryptoException(String.format(
                    "Invalid values for input offset: %d and length: %d", off, len));
        }

        int actualOutLen = 0;

        if (firstOperation_ == true) {
            System.arraycopy(ciphertextHeaderBytes_, 0, out, outOff, ciphertextHeaderBytes_.length);
            actualOutLen += ciphertextHeaderBytes_.length;

            firstOperation_ = false;
        }

        ProcessingSummary contentOut =
                contentCryptoHandler_.processBytes(in, off, len, out, outOff + actualOutLen);
        actualOutLen += contentOut.getBytesWritten();
        updateTrailingSignature(out, outOff, actualOutLen);
        return new ProcessingSummary(actualOutLen, contentOut.getBytesProcessed());
    }

    /**
     * Finish encryption of the plaintext bytes.
     * 
     * @param out
     *            space for any resulting output data.
     * @param outOff
     *            offset into out to start copying the data at.
     * @return number of bytes written into out.
     * @throws BadCiphertextException
     *             thrown by the underlying cipher handler.
     */
    @Override
    public int doFinal(final byte[] out, final int outOff) throws BadCiphertextException {
        complete_ = true;
        int written = contentCryptoHandler_.doFinal(out, outOff);
        updateTrailingSignature(out, outOff, written);
        if (cryptoAlgo_.getTrailingSignatureLength() > 0) {
            try {
                CiphertextFooters footer = new CiphertextFooters(trailingSig_.sign());
                byte[] fBytes = footer.toByteArray();
                System.arraycopy(fBytes, 0, out, outOff + written, fBytes.length);
                return written + fBytes.length;
            } catch (final SignatureException ex) {
                throw new AwsCryptoException(ex);
            }
        } else {
            return written;
        }
    }

    /**
     * Return the size of the output buffer required for a {@code processBytes} plus a
     * {@code doFinal} with an input of inLen bytes.
     * 
     * @param inLen
     *            the length of the input.
     * @return the space required to accommodate a call to processBytes and doFinal with len bytes
     *         of input.
     */
    @Override
    public int estimateOutputSize(final int inLen) {
        int outSize = 0;
        if (firstOperation_ == true) {
            outSize += ciphertextHeaderBytes_.length;
        }
        outSize += contentCryptoHandler_.estimateOutputSize(inLen);

        if (cryptoAlgo_.getTrailingSignatureLength() > 0) {
            outSize += 2; // Length field in footer
            outSize += cryptoAlgo_.getTrailingSignatureLength();
        }
        return outSize;
    }

    /**
     * Return the encryption context.
     * 
     * @return the key-value map containing encryption context.
     */
    @Override
    public Map<String, String> getEncryptionContext() {
        return encryptionContext_;
    }

    @Override
    public CiphertextHeaders getHeaders() {
        return ciphertextHeaders_;
    }

    /**
     * Compute the MAC tag of the header bytes using the provided key, nonce, AAD, and crypto
     * algorithm identifier.
     * 
     * @param key
     *            the key to use in computing the MAC tag.
     * @param nonce
     *            the nonce to use in computing the MAC tag.
     * @param aad
     *            the AAD to use in computing the MAC tag.
     * @param cryptoAlgo
     *            the crypto algorithm to use for computing the MAC tag.
     * @return the bytes containing the computed MAC tag.
     */
    private byte[] computeHeaderTag(final byte[] nonce, final byte[] aad) {
        final CipherHandler cipherHandler = new CipherHandler(encryptionKey_, nonce, aad,
                Cipher.ENCRYPT_MODE,
                cryptoAlgo_);

        return cipherHandler.cipherData(new byte[0], 0, 0);
    }

    /**
     * Create ciphertext headers using the instance variables, and the provided content type and
     * frame size.
     * 
     * @param contentType
     *            the content type to set in the ciphertext headers.
     * @param frameSize
     *            the frame size to set in the ciphertext headers.
     * @return the bytes containing the ciphertext headers.
     */
    private CiphertextHeaders createCiphertextHeaders(final ContentType contentType, final int frameSize) {
        // create the ciphertext headers
        final byte[] headerNonce = new byte[nonceLen_];
        RND.nextBytes(headerNonce);

        final byte[] encryptionContextBytes = EncryptionContextSerializer.serialize(encryptionContext_);
        final CiphertextHeaders ciphertextHeaders = new CiphertextHeaders(version_, type_, cryptoAlgo_,
                encryptionContextBytes, keyBlobs_, contentType, frameSize);
        ciphertextHeaders.setHeaderNonce(headerNonce);

        return ciphertextHeaders;
    }

    private CiphertextHeaders signCiphertextHeaders(final CiphertextHeaders unsignedHeaders) {
        final byte[] headerFields = unsignedHeaders.serializeAuthenticatedFields();
        final byte[] headerTag = computeHeaderTag(unsignedHeaders.getHeaderNonce(), headerFields);

        unsignedHeaders.setHeaderTag(headerTag);

        return unsignedHeaders;
    }

    @Override
    public List<K> getMasterKeys() {
        return masterKeys_; // This is unmodifiable
    }

    private KeyPair generateTrailingSigKeyPair() throws GeneralSecurityException {
        final ECNamedCurveParameterSpec ecSpec;
        switch (cryptoAlgo_) {
            case ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256:
                ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
                break;
            case ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384:
            case ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384:
                ecSpec = ECNamedCurveTable.getParameterSpec("secp384r1");
                break;
            default:
                throw new IllegalStateException("Algorithm does not support trailing signature");
        }
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA", "BC");
        keyGen.initialize(ecSpec, RND);
        return keyGen.generateKeyPair();
    }

    private String serializeTrailingKeyForEc() {
        switch (cryptoAlgo_) {
            case ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256:
            case ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384:
            case ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384:
                ECPublicKey ecPub = (ECPublicKey) trailingKeys_.getPublic();
                return Base64.encodeAsString(ecPub.getQ().getEncoded(pointCompressionEnabled_));
            default:
                throw new IllegalStateException("Algorithm does not support trailing signature");
        }
    }

    private void updateTrailingSignature(byte[] input, int offset, int len) {
        if (trailingSig_ != null) {
            try {
                trailingSig_.update(input, offset, len);
            } catch (final SignatureException ex) {
                throw new AwsCryptoException(ex);
            }
        }
    }

    @Override
    public boolean isComplete() {
        return complete_;
    }
}
