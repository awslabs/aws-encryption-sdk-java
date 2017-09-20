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

import java.nio.ByteBuffer;
import java.util.Arrays;

import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.BadCiphertextException;
import com.amazonaws.encryptionsdk.exception.ParseException;
import com.amazonaws.encryptionsdk.internal.Constants;
import com.amazonaws.encryptionsdk.internal.PrimitivesParser;

/**
 * This class implements the headers for the encrypted content stored in a
 * single block. These headers are parsed and used when the encrypted content
 * in the single block is decrypted.
 * 
 * <p>
 * It contains the following fields in order:
 * <ol>
 * <li>nonce</li>
 * <li>length of content</li>
 * </ol>
 */
public final class CipherBlockHeaders {
    private byte[] nonce_;
    private long contentLength_ = -1;

    // This is set after the nonce length is parsed in the CiphertextHeaders
    // during decryption. This can be set only using its setter.
    private short nonceLength_ = 0;

    private boolean isComplete_;

    /**
     * Default constructor.
     */
    public CipherBlockHeaders() {
    }

    /**
     * Construct the single block headers using the provided nonce
     * and length of content.
     * 
     * @param nonce
     *            the bytes containing the nonce.
     * @param contentLen
     *            the length of the content in the block.
     */
    public CipherBlockHeaders(final byte[] nonce, final long contentLen) {
        if (nonce == null) {
            throw new AwsCryptoException("Nonce cannot be null.");
        }
        if (nonce.length > Constants.MAX_NONCE_LENGTH) {
            throw new AwsCryptoException(
                    "Nonce length is greater than the maximum value of an unsigned byte.");
        }

        nonce_ = nonce.clone();
        contentLength_ = contentLen;
    }

    /**
     * Serialize the header into a byte array.
     * 
     * @return
     *         the serialized bytes of the header.
     */
    public byte[] toByteArray() {
        final int outLen = nonce_.length + (Long.SIZE / Byte.SIZE);
        final ByteBuffer out = ByteBuffer.allocate(outLen);

        out.put(nonce_);
        out.putLong(contentLength_);

        return out.array();
    }

    /**
     * Parse the nonce in the provided bytes. It looks for bytes of size
     * defined by the nonce length in the provided bytes starting at the
     * specified off.
     * 
     * <p>
     * If successful, it returns the size of the parsed bytes which is the nonce
     * length. On failure, it throws a parse exception.
     * 
     * @param b
     *            the byte array to parse.
     * @param off
     *            the offset in the byte array to use when parsing.
     * @return
     *         the size of the parsed bytes which is the nonce length.
     * @throws ParseException
     *             if there are not sufficient bytes to parse the nonce.
     */
    private int parseNonce(final byte[] b, final int off) throws ParseException {
        final int bytesToParseLen = b.length - off;
        if (bytesToParseLen >= nonceLength_) {
            nonce_ = Arrays.copyOfRange(b, off, off + nonceLength_);
            return nonceLength_;
        } else {
            throw new ParseException("Not enough bytes to parse nonce");
        }
    }

    /**
     * Parse the content length in the provided bytes. It looks for 8 bytes
     * representing a long primitive type in the provided bytes starting at the
     * specified off.
     * 
     * <p>
     * If successful, it returns the size of the parsed bytes which is the size
     * of the long primitive type. On failure, it throws a parse exception.
     * 
     * @param b
     *            the byte array to parse.
     * @param off
     *            the offset in the byte array to use when parsing.
     * @return
     *         the size of the parsed bytes which is the size of the long
     *         primitive type.
     * @throws ParseException
     *             if there are not sufficient bytes to parse the content
     *             length.
     */
    private int parseContentLength(final byte[] b, final int off) throws ParseException {
        contentLength_ = PrimitivesParser.parseLong(b, off);
        if (contentLength_ < 0) {
            throw new BadCiphertextException("Invalid content length in ciphertext");
        }
        return Long.SIZE / Byte.SIZE;
    }

    /**
     * Deserialize the provided bytes starting at the specified offset to
     * construct an instance of this class.
     * 
     * <p>
     * This method parses the provided bytes for the individual fields in this
     * class. This methods also supports partial parsing where not all the bytes
     * required for parsing the fields successfully are available.
     * 
     * @param b
     *            the byte array to deserialize.
     * @param off
     *            the offset in the byte array to use for deserialization.
     * @return
     *         the number of bytes consumed in deserialization.
     */
    public int deserialize(final byte[] b, final int off) {
        if (b == null) {
            return 0;
        }

        int parsedBytes = 0;
        try {
            if (nonceLength_ > 0 && nonce_ == null) {
                parsedBytes += parseNonce(b, off + parsedBytes);
            }

            if (contentLength_ < 0) {
                parsedBytes += parseContentLength(b, off + parsedBytes);
            }

            isComplete_ = true;
        } catch (ParseException e) {
            // this results when we do partial parsing and there aren't enough
            // bytes to parse; so just return the bytes parsed thus far.
        }

        return parsedBytes;
    }

    /**
     * Check if this object has all the header fields populated and available
     * for reading.
     * 
     * @return
     *         true if this object containing the single block header fields
     *         is complete; false otherwise.
     */
    public boolean isComplete() {
        return isComplete_;
    }

    /**
     * Return the nonce set in the single block header.
     * 
     * @return
     *         the bytes containing the nonce set in the single block header.
     */
    public byte[] getNonce() {
        return nonce_ != null ? nonce_.clone() : null;
    }

    /**
     * Return the content length set in the single block header.
     * 
     * @return
     *         the content length set in the single block header.
     */
    public long getContentLength() {
        return contentLength_;
    }

    /**
     * Set the length of the nonce used in the encryption of the content stored
     * in the single block.
     * 
     * @param nonceLength
     *            the length of the nonce used in the encryption of the content
     *            stored in the single block.
     */
    public void setNonceLength(final short nonceLength) {
        nonceLength_ = nonceLength;
    }
}