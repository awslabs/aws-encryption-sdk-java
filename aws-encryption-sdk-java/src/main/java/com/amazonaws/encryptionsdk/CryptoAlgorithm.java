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

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidKeyException;
import java.security.Provider;
import java.security.Security;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

import com.amazonaws.encryptionsdk.internal.Constants;
import com.amazonaws.encryptionsdk.model.CiphertextHeaders;

/**
 * Describes the cryptographic algorithms available for use in this library.
 *
 * <p>
 * Format: CryptoAlgorithm(block size, nonce length, tag length, max content length, key algo, key
 * length, short value representing this algorithm, trailing signature alg, trailing signature
 * length)
 */
public enum CryptoAlgorithm {
    /**
     * AES-GCM 128
     */
    ALG_AES_128_GCM_IV12_TAG16_NO_KDF(128, 12, 16, Constants.GCM_MAX_CONTENT_LEN, "AES", 16, 0x0014, "AES", 16, false),
    /**
     * AES-GCM 192
     */
    ALG_AES_192_GCM_IV12_TAG16_NO_KDF(128, 12, 16, Constants.GCM_MAX_CONTENT_LEN, "AES", 24, 0x0046, "AES", 24, false),
    /**
     * AES-GCM 256
     */
    ALG_AES_256_GCM_IV12_TAG16_NO_KDF(128, 12, 16, Constants.GCM_MAX_CONTENT_LEN, "AES", 32, 0x0078, "AES", 32, false),
    /**
     * AES-GCM 128 with HKDF-SHA256
     */
    ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256(128, 12, 16, Constants.GCM_MAX_CONTENT_LEN, "AES", 16, 0x0114, "HkdfSHA256",
                                           16, true),
    /**
     * AES-GCM 192
     */
    ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA256(128, 12, 16, Constants.GCM_MAX_CONTENT_LEN, "AES", 24, 0x0146, "HkdfSHA256",
                                           24, true),
    /**
     * AES-GCM 256
     */
    ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256(128, 12, 16, Constants.GCM_MAX_CONTENT_LEN, "AES", 32, 0x0178, "HkdfSHA256",
                                           32, true),

    /**
     * AES-GCM 128 with ECDSA (SHA256 with the secp256r1 curve)
     */
    ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256(128, 12, 16, Constants.GCM_MAX_CONTENT_LEN, "AES", 16, 0x0214,
                                                      "HkdfSHA256", 16,
                                                      true, "SHA256withECDSA", 71),
    /**
     * AES-GCM 192 with ECDSA (SHA384 with the secp384r1 curve)
     */
    ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384(128, 12, 16, Constants.GCM_MAX_CONTENT_LEN, "AES", 24, 0x0346,
                                                      "HkdfSHA384", 24,
                                                      true, "SHA384withECDSA", 103),
    /**
     * AES-GCM 256 with ECDSA (SHA384 with the secp384r1 curve)
     */
    ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384(128, 12, 16, Constants.GCM_MAX_CONTENT_LEN, "AES", 32, 0x0378,
                                                      "HkdfSHA384", 32,
                                                      true, "SHA384withECDSA", 103);

    private final int blockSizeBits_;
    private final byte nonceLenBytes_;
    private final int tagLenBytes_;
    private final long maxContentLen_;
    private final String keyAlgo_;
    private final int keyLenBytes_;
    private final short value_;
    private final String trailingSigAlgo_;
    private final short trailingSigLen_;
    private final String dataKeyAlgo_;
    private final int dataKeyLen_;
    private final boolean safeToCache_;

    static {
        try {
            Security.addProvider((Provider)
                    Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider").newInstance());
        } catch (final Throwable ex) {
            // Swallow this error. We'll either succeed or fail later with reasonable
            // stacktraces.
        }
    }

    /*
     * Create a mapping between the CiphertextType object and its byte value representation. Make
     * this is a static method so the map is created when the object is created. This enables fast
     * lookups of the CryptoAlgorithm given its short value representation.
     */
    private static final Map<Short, CryptoAlgorithm> ID_MAPPING = new HashMap<Short, CryptoAlgorithm>();
    static {
        for (final CryptoAlgorithm s : EnumSet.allOf(CryptoAlgorithm.class)) {
            ID_MAPPING.put(s.value_, s);
        }
    }

    private CryptoAlgorithm(
            final int blockSizeBits, final int nonceLenBytes, final int tagLenBytes,
            final long maxContentLen, final String keyAlgo, final int keyLenBytes, final int value,
            final String dataKeyAlgo, final int dataKeyLen, boolean safeToCache
    ) {
        this(blockSizeBits, nonceLenBytes, tagLenBytes,
             maxContentLen, keyAlgo, keyLenBytes, value,
             dataKeyAlgo, dataKeyLen, safeToCache, null, 0);

    }

    private CryptoAlgorithm(
            final int blockSizeBits, final int nonceLenBytes, final int tagLenBytes,
            final long maxContentLen, final String keyAlgo, final int keyLenBytes, final int value,
            final String dataKeyAlgo, final int dataKeyLen,
            boolean safeToCache, final String trailingSignatureAlgo, final int trailingSignatureLength
    ) {
        blockSizeBits_ = blockSizeBits;
        nonceLenBytes_ = (byte) nonceLenBytes;
        tagLenBytes_ = tagLenBytes;
        keyAlgo_ = keyAlgo;
        keyLenBytes_ = keyLenBytes;
        maxContentLen_ = maxContentLen;
        safeToCache_ = safeToCache;
        if (value > Short.MAX_VALUE || value < Short.MIN_VALUE) {
            throw new IllegalArgumentException("Invalid value " + value);
        }
        value_ = (short) value;
        dataKeyAlgo_ = dataKeyAlgo;
        dataKeyLen_ = dataKeyLen;
        trailingSigAlgo_ = trailingSignatureAlgo;
        if (trailingSignatureLength > Short.MAX_VALUE || trailingSignatureLength < 0) {
            throw new IllegalArgumentException("Invalid value " + trailingSignatureLength);
        }
        trailingSigLen_ = (short) trailingSignatureLength;
    }

    /**
     * Returns the CryptoAlgorithm object that matches the given value.
     *
     * @param value
     *            the value of the object
     * @return the CryptoAlgorithm object that matches the given value, null if no match is found.
     */
    public static CryptoAlgorithm deserialize(final short value) {
        final CryptoAlgorithm result = ID_MAPPING.get(value);
        return result;
    }

    /**
     * Returns the block size of this algorithm in bytes.
     */
    public int getBlockSize() {
        return blockSizeBits_ / 8;
    }

    /**
     * Returns the nonce length used in this algorithm in bytes.
     */
    public byte getNonceLen() {
        return nonceLenBytes_;
    }

    /**
     * Returns the tag length used in this algorithm in bytes.
     */
    public int getTagLen() {
        return tagLenBytes_;
    }

    /**
     * Returns the maximum content length in bytes that can be processed under a single data key in
     * this algorithm.
     */
    public long getMaxContentLen() {
        return maxContentLen_;
    }

    /**
     * Returns the algorithm used for encrypting the plaintext data.
     */
    public String getKeyAlgo() {
        return keyAlgo_;
    }

    /**
     * Returns the length of the key used in this algorithm in bytes.
     */
    public int getKeyLength() {
        return keyLenBytes_;
    }

    /**
     * Returns the value used to encode this algorithm in the ciphertext.
     */
    public short getValue() {
        return value_;
    }

    /**
     * Returns the algorithm associated with the data key.
     */
    public String getDataKeyAlgo() {
        return dataKeyAlgo_;
    }

    /**
     * Returns the length of the data key in bytes.
     */
    public int getDataKeyLength() {
        return dataKeyLen_;
    }

    /**
     * Returns the algorithm used to calculate the trailing signature
     */
    public String getTrailingSignatureAlgo() {
        return trailingSigAlgo_;
    }

    /**
     * Returns whether data keys used with this crypto algorithm can safely be cached and reused for a different
     * message. If this returns false, reuse of data keys is likely to result in severe cryptographic weaknesses,
     * potentially even with only a single such use.
     */
    public boolean isSafeToCache() {
        return safeToCache_;
    }

    /**
     * Returns the length of the trailing signature generated by this algorithm. The actual trailing
     * signature may be shorter than this.
     */
    public short getTrailingSignatureLength() {
        return trailingSigLen_;
    }

    public SecretKey getEncryptionKeyFromDataKey(final SecretKey dataKey, final CiphertextHeaders headers)
            throws InvalidKeyException {
        if (!dataKey.getAlgorithm().equalsIgnoreCase(getDataKeyAlgo())) {
            throw new InvalidKeyException("DataKey of incorrect algorithm. Expected " + getDataKeyAlgo() + " but was "
                    + dataKey.getAlgorithm());
        }

        final Digest dgst;

        switch (this) {
            case ALG_AES_128_GCM_IV12_TAG16_NO_KDF:
            case ALG_AES_192_GCM_IV12_TAG16_NO_KDF:
            case ALG_AES_256_GCM_IV12_TAG16_NO_KDF:
                return dataKey;
            case ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256:
            case ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA256:
            case ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256:
            case ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256:
                dgst = new SHA256Digest();
                break;
            case ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384:
            case ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384:
                dgst = new SHA384Digest();
                break;
            default:
                throw new UnsupportedOperationException("Support for " + this + " not yet built.");
        }
        if (!dataKey.getFormat().equalsIgnoreCase("RAW")) {
            throw new InvalidKeyException(
                    "Currently only RAW format keys are supported for HKDF algorithms. Actual format was "
                            + dataKey.getFormat());
        }
        final byte[] messageId = headers.getMessageId();
        final ByteBuffer info = ByteBuffer.allocate(messageId.length + 2);
        info.order(ByteOrder.BIG_ENDIAN);
        info.putShort(getValue());
        info.put(messageId);

        final byte[] rawDataKey = dataKey.getEncoded();
        if (rawDataKey.length != getDataKeyLength()) {
            throw new InvalidKeyException("DataKey of incorrect length. Expected " + getDataKeyLength() + " but was "
                    + rawDataKey.length);
        }

        final byte[] rawEncKey = new byte[getKeyLength()];
        final HKDFBytesGenerator hkdf = new HKDFBytesGenerator(dgst);
        hkdf.init(new HKDFParameters(rawDataKey, null, info.array()));
        hkdf.generateBytes(rawEncKey, 0, getKeyLength());
        return new SecretKeySpec(rawEncKey, getKeyAlgo());
    }
}
