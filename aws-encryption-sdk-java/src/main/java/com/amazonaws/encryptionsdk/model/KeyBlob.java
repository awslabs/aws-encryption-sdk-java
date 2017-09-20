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
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import com.amazonaws.encryptionsdk.EncryptedDataKey;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.ParseException;
import com.amazonaws.encryptionsdk.internal.PrimitivesParser;

/**
 * This class implements the format of the key blob. The format contains the
 * following fields in order:
 * <ol>
 * <li>
 * length of key provider</li>
 * <li>
 * key provider</li>
 * <li>
 * length of key provider info</li>
 * <li>
 * key provider info</li>
 * <li>
 * length of encrypted key</li>
 * <li>
 * encrypted key</li>
 * </ol>
 */
public final class KeyBlob implements EncryptedDataKey {
    private short keyProviderIdLen_ = -1;
    private byte[] keyProviderId_;
    private short keyProviderInfoLen_ = -1;
    private byte[] keyProviderInfo_;
    private short encryptedKeyLen_ = -1;
    private byte[] encryptedKey_;

    private boolean isComplete_ = false;

    /**
     * Default constructor.
     */
    public KeyBlob() {
    }

    /**
     * Construct a key blob using the provided key, key provider identifier, and
     * key provider information.
     * @param keyProviderId
     *            the key provider identifier string.
     * @param keyProviderInfo
     *            the bytes containing the key provider info.
     * @param encryptedDataKey
     *            the encrypted bytes of the data key.
     */
    public KeyBlob(final String keyProviderId, final byte[] keyProviderInfo, final byte[] encryptedDataKey) {
        setEncryptedDataKey(encryptedDataKey);
        setKeyProviderId(keyProviderId);
        setKeyProviderInfo(keyProviderInfo);
    }

    public KeyBlob(final EncryptedDataKey edk) {
        setEncryptedDataKey(edk.getEncryptedDataKey());
        setKeyProviderId(edk.getProviderId());
        setKeyProviderInfo(edk.getProviderInformation());
    }
    /**
     * Parse the key provider identifier length in the provided bytes. It looks
     * for 2 bytes representing a short primitive type in the provided bytes
     * starting at the specified off.
     * 
     * <p>
     * If successful, it returns the size of the parsed bytes which is the size
     * of the short primitive type. On failure, it throws a parse exception.
     * 
     * @param b
     *            the byte array to parse.
     * @param off
     *            the offset in the byte array to use when parsing.
     * @return
     *         the size of the parsed bytes which is the size of the short
     *         primitive.
     * @throws ParseException
     *             if there are not sufficient bytes to parse the identifier
     *             length.
     */
    private int parseKeyProviderIdLen(final byte[] b, final int off) throws ParseException {
        keyProviderIdLen_ = PrimitivesParser.parseShort(b, off);
        return Short.SIZE / Byte.SIZE;
    }

    /**
     * Parse the key provider identifier in the provided bytes. It looks
     * for bytes of size defined by the key provider identifier length in the
     * provided bytes starting at the specified off.
     * 
     * <p>
     * If successful, it returns the size of the parsed bytes which is the key
     * provider identifier length. On failure, it throws a parse exception.
     * 
     * @param b
     *            the byte array to parse.
     * @param off
     *            the offset in the byte array to use when parsing.
     * @return
     *         the size of the parsed bytes which is the key provider identifier
     *         length.
     * @throws ParseException
     *             if there are not sufficient bytes to parse the identifier.
     */
    private int parseKeyProviderId(final byte[] b, final int off) throws ParseException {
        final int bytesToParseLen = b.length - off;
        if (bytesToParseLen >= keyProviderIdLen_) {
            keyProviderId_ = Arrays.copyOfRange(b, off, off + keyProviderIdLen_);
            return keyProviderIdLen_;
        } else {
            throw new ParseException("Not enough bytes to parse key provider id");
        }
    }

    /**
     * Parse the key provider info length in the provided bytes. It looks
     * for 2 bytes representing a short primitive type in the provided bytes
     * starting at the specified off.
     * 
     * <p>
     * If successful, it returns the size of the parsed bytes which is the size
     * of the short primitive type. On failure, it throws a parse exception.
     * 
     * @param b
     *            the byte array to parse.
     * @param off
     *            the offset in the byte array to use when parsing.
     * @return
     *         the size of the parsed bytes which is the size of the short
     *         primitive type.
     * @throws ParseException
     *             if there are not sufficient bytes to parse the provider info
     *             length.
     */
    private int parseKeyProviderInfoLen(final byte[] b, final int off) throws ParseException {
        keyProviderInfoLen_ = PrimitivesParser.parseShort(b, off);
        return Short.SIZE / Byte.SIZE;
    }

    /**
     * Parse the key provider info in the provided bytes. It looks for bytes of
     * size defined by the key provider info length in the provided bytes
     * starting at the specified off.
     * 
     * <p>
     * If successful, it returns the size of the parsed bytes which is the key
     * provider info length. On failure, it throws a parse exception.
     * 
     * @param b
     *            the byte array to parse.
     * @param off
     *            the offset in the byte array to use when parsing.
     * @return
     *         the size of the parsed bytes which is the key provider info
     *         length.
     * @throws ParseException
     *             if there are not sufficient bytes to parse the provider info.
     */
    private int parseKeyProviderInfo(final byte[] b, final int off) throws ParseException {
        final int bytesToParseLen = b.length - off;
        if (bytesToParseLen >= keyProviderInfoLen_) {
            keyProviderInfo_ = Arrays.copyOfRange(b, off, off + keyProviderInfoLen_);
            return keyProviderInfoLen_;
        } else {
            throw new ParseException("Not enough bytes to parse key provider info");
        }
    }

    /**
     * Parse the key length in the provided bytes. It looks for 2 bytes
     * representing a short primitive type in the provided bytes starting at the
     * specified off.
     * 
     * <p>
     * If successful, it returns the size of the parsed bytes which is the size
     * of the short primitive type. On failure, it throws a parse exception.
     * 
     * @param b
     *            the byte array to parse.
     * @param off
     *            the offset in the byte array to use when parsing.
     * @return
     *         the size of the parsed bytes which is the size of the short
     *         primitive type.
     * @throws ParseException
     *             if there are not sufficient bytes to parse the key length.
     */
    private int parseKeyLen(final byte[] b, final int off) throws ParseException {
        encryptedKeyLen_ = PrimitivesParser.parseShort(b, off);
        return Short.SIZE / Byte.SIZE;
    }

    /**
     * Parse the key in the provided bytes. It looks for bytes of size defined
     * by the key length in the provided bytes starting at the specified off.
     * 
     * <p>
     * If successful, it returns the size of the parsed bytes which is the key
     * length. On failure, it throws a parse exception.
     * 
     * @param b
     *            the byte array to parse.
     * @param off
     *            the offset in the byte array to use when parsing.
     * @return
     *         the size of the parsed bytes which is the key length.
     * @throws ParseException
     *             if there are not sufficient bytes to parse the key.
     */
    private int parseKey(final byte[] b, final int off) throws ParseException {
        final int bytesToParseLen = b.length - off;
        if (bytesToParseLen >= encryptedKeyLen_) {
            encryptedKey_ = Arrays.copyOfRange(b, off, off + encryptedKeyLen_);
            return encryptedKeyLen_;
        } else {
            throw new ParseException("Not enough bytes to parse key");
        }
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
     * 
     */
    public int deserialize(final byte[] b, final int off) {
        if (b == null) {
            return 0;
        }

        int parsedBytes = 0;
        try {
            if (keyProviderIdLen_ < 0) {
                parsedBytes += parseKeyProviderIdLen(b, off + parsedBytes);
            }

            if (keyProviderId_ == null) {
                parsedBytes += parseKeyProviderId(b, off + parsedBytes);
            }

            if (keyProviderInfoLen_ < 0) {
                parsedBytes += parseKeyProviderInfoLen(b, off + parsedBytes);
            }

            if (keyProviderInfo_ == null) {
                parsedBytes += parseKeyProviderInfo(b, off + parsedBytes);
            }

            if (encryptedKeyLen_ < 0) {
                parsedBytes += parseKeyLen(b, off + parsedBytes);
            }

            if (encryptedKey_ == null) {
                parsedBytes += parseKey(b, off + parsedBytes);
            }

            isComplete_ = true;
        } catch (ParseException e) {
            // this results when we do partial parsing and there aren't enough
            // bytes to parse; ignore it and return the bytes parsed thus far.
        }
        return parsedBytes;
    }

    /**
     * Serialize an instance of this class to a byte array.
     * 
     * @return
     *         the serialized bytes of the instance.
     */
    public byte[] toByteArray() {
        final int outLen = 3 * (Short.SIZE / Byte.SIZE) + keyProviderIdLen_ + keyProviderInfoLen_ + encryptedKeyLen_;
        final ByteBuffer out = ByteBuffer.allocate(outLen);

        out.putShort(keyProviderIdLen_);
        out.put(keyProviderId_, 0, keyProviderIdLen_);

        out.putShort(keyProviderInfoLen_);
        out.put(keyProviderInfo_, 0, keyProviderInfoLen_);

        out.putShort(encryptedKeyLen_);
        out.put(encryptedKey_, 0, encryptedKeyLen_);

        return out.array();
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
     * Return the length of the key provider identifier set in the header.
     * 
     * @return
     *         the length of the key provider identifier.
     */
    public short getKeyProviderIdLen() {
        return keyProviderIdLen_;
    }

    /**
     * Return the key provider identifier set in the header.
     * 
     * @return
     *         the string containing the key provider identifier.
     */
    @Override
    public String getProviderId() {
        return new String(keyProviderId_, StandardCharsets.UTF_8);
    }

    /**
     * Return the length of the key provider info set in the header.
     * 
     * @return
     *         the length of the key provider info.
     */
    public short getKeyProviderInfoLen() {
        return keyProviderInfoLen_;
    }

    /**
     * Return the information on the key provider set in the header.
     * 
     * @return
     *         the bytes containing information on the key provider.
     */
    @Override
    public byte[] getProviderInformation() {
        return keyProviderInfo_.clone();
    }

    /**
     * Return the length of the encrypted data key set in the header.
     * 
     * @return
     *         the length of the encrypted data key.
     */
    public short getEncryptedDataKeyLen() {
        return encryptedKeyLen_;
    }

    /**
     * Return the encrypted data key set in the header.
     * 
     * @return
     *         the bytes containing the encrypted data key.
     */
    @Override
    public byte[] getEncryptedDataKey() {
        return encryptedKey_.clone();
    }

    /**
     * Set the key provider identifier.
     * 
     * @param keyProviderId
     *            the key provider identifier.
     */
    public void setKeyProviderId(final String keyProviderId) {
        final byte[] keyProviderIdBytes = keyProviderId.getBytes(StandardCharsets.UTF_8);
        if (keyProviderIdBytes.length > Short.MAX_VALUE) {
            throw new AwsCryptoException(
                    "Key provider identifier length exceeds the max value of a short primitive.");
        }
        keyProviderId_ = keyProviderIdBytes;
        keyProviderIdLen_ = (short) keyProviderId_.length;
    }

    /**
     * Set the information on the key provider identifier.
     * 
     * @param keyProviderInfo
     *            the bytes containing information on the key provider
     *            identifier.
     */
    public void setKeyProviderInfo(final byte[] keyProviderInfo) {
        if (keyProviderInfo.length > Short.MAX_VALUE) {
            throw new AwsCryptoException(
                    "Key provider identifier information length exceeds the max value of a short primitive.");
        }
        keyProviderInfo_ = keyProviderInfo.clone();
        keyProviderInfoLen_ = (short) keyProviderInfo.length;
    }

    /**
     * Set the encrypted data key.
     * 
     * @param encryptedDataKey
     *            the bytes containing the encrypted data key.
     */
    public void setEncryptedDataKey(final byte[] encryptedDataKey) {
        if (encryptedDataKey.length > Short.MAX_VALUE) {
            throw new AwsCryptoException("Key length exceeds the max value of a short primitive.");
        }
        encryptedKey_ = encryptedDataKey.clone();
        encryptedKeyLen_ = (short) encryptedKey_.length;
    }
}