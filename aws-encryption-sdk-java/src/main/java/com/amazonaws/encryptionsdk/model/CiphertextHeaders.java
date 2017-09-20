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

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.BadCiphertextException;
import com.amazonaws.encryptionsdk.exception.ParseException;
import com.amazonaws.encryptionsdk.internal.Constants;
import com.amazonaws.encryptionsdk.internal.EncryptionContextSerializer;
import com.amazonaws.encryptionsdk.internal.PrimitivesParser;

/**
 * This class implements the headers for the message (ciphertext) produced by
 * this library. These headers are parsed and used when the ciphertext is
 * decrypted.
 * 
 * It contains the following fields in order:
 * <ol>
 * <li>version number of the message format</li>
 * <li>type of the object - e.g., Customer Authenticated Encrypted Data</li>
 * <li>algorithm Id - identifier for the algorithm used</li>
 * <li>Message ID - bytes that uniquely identify the message (encrypted content)
 * wrapped by this header</li>
 * <li>Encryption context length- length of the encryption context for
 * encrypting data key</li>
 * <li>Encryption context - encryption context for encrypting data key</li>
 * <li>Encrypted Data key count - count of the encrypted data keys embedded in
 * this object</li>
 * <li>KeyBlob - the {@link KeyBlob} containing the key provider, key provider
 * info, encrypted key, and their lengths for each data key</li>
 * <li>ContentType - single-block or framing</li>
 * <li>Reserved field - 4 bytes reserved for future use</li>
 * <li>Nonce length - the length of the nonce used in authenticating this header
 * and encrypting the content it wraps</li>
 * <li>Frame length - length of the frames (when framing)</li>
 * <li>Header nonce - the nonce used in creating the header tag</li>
 * <li>Header tag - the MAC tag created to protect the contents of the header</li>
 * </ol>
 * 
 * <p>
 * It is important to note that the header fields 1 through 12 are checked for
 * their integrity during decryption using AES-GCM with the nonce and MAC tag
 * values supplied in fields 13 and 14 respectively.
 */
public class CiphertextHeaders {
    private static final SecureRandom RND = new SecureRandom();
    private byte version_ = -1;
    private byte typeVal_; // don't set this to -1 since Java byte is signed
                           // while this value is unsigned and can go up to 128.
    private short cryptoAlgoVal_ = -1;
    private byte[] messageId_;
    private int encryptionContextLen_ = -1;
    private byte[] encryptionContext_ = new byte[0];
    private int cipherKeyCount_ = -1;
    private List<KeyBlob> cipherKeyBlobs_;
    private byte contentTypeVal_ = -1;
    private int reservedField_ = -1;
    private short nonceLen_ = -1;
    private int frameLength_ = -1;

    private byte[] headerNonce_;
    private byte[] headerTag_;

    // internal variables
    private int currKeyBlobIndex_ = 0;
    private boolean isComplete_;

    /**
     * Default constructor.
     */
    public CiphertextHeaders() {
    }

    /**
     * Construct the ciphertext headers using the provided values.
     * 
     * @param version
     *            the version to set in the header.
     * @param type
     *            the type to set in the header.
     * @param cryptoAlgo
     *            the CryptoAlgorithm enum to encode in the header.
     * @param encryptionContext
     *            the bytes containing the encryption context to set in the
     *            header.
     * @param keyBlob
     *            the keyBlob object containing the key provider id, key
     *            provider info, and encrypted data key to encode in the header.
     * @param contentType
     *            the content type to set in the header.
     * @param frameSize
     *            the frame payload size to set in the header.
     */
    public CiphertextHeaders(final byte version, final CiphertextType type, final CryptoAlgorithm cryptoAlgo,
            final byte[] encryptionContext, final List<KeyBlob> keyBlobs, final ContentType contentType,
            final int frameSize) {

        version_ = version;
        typeVal_ = type.getValue();

        cryptoAlgoVal_ = cryptoAlgo.getValue();

        encryptionContext_ = encryptionContext.clone();
        if (encryptionContext_.length > Constants.UNSIGNED_SHORT_MAX_VAL) {
            throw new AwsCryptoException("Size of encryption context exceeds the allowed maximum "
                    + Constants.UNSIGNED_SHORT_MAX_VAL);
        }
        encryptionContextLen_ = encryptionContext.length;

        // we only support the encoding of 1 data key in the cipher blob.
        cipherKeyCount_ = keyBlobs.size();
        cipherKeyBlobs_ = new ArrayList<>(keyBlobs);

        contentTypeVal_ = contentType.getValue();
        reservedField_ = 0;
        nonceLen_ = cryptoAlgo.getNonceLen();

        // generate random bytes and assign them as the unique identifier of the
        // message wrapped by this header.
        messageId_ = new byte[Constants.MESSAGE_ID_LEN];
        RND.nextBytes(messageId_);

        frameLength_ = frameSize;

        // Completed by construction
        isComplete_ = true;
    }

    /**
     * Check if this object has all the header fields populated and available
     * for reading.
     * 
     * @return
     *         true if this object containing the single block header fields
     *         is complete; false otherwise.
     */
    public Boolean isComplete() {
        return isComplete_;
    }

    /**
     * Parse the version in the provided bytes. It looks for a
     * single byte in the provided bytes starting at the specified off.
     * 
     * <p>
     * If successful, it returns 1 indicating that a byte was parsed. On
     * failure, it throws a parse exception.
     * 
     * @param b
     *            the byte array to parse.
     * @param off
     *            the offset in the byte array to use when parsing.
     * @return
     *         1 indicating that a byte was parsed.
     * @throws ParseException
     *             if there are not sufficient bytes to parse the version.
     */
    private int parseVersion(final byte[] b, final int off) throws ParseException {
        version_ = PrimitivesParser.parseByte(b, off);
        return 1;
    }

    /**
     * Parse the type in the provided bytes. It looks for a
     * single byte in the provided bytes starting at the specified off.
     * 
     * <p>
     * If successful, it returns 1 indicating that a byte was parsed. On
     * failure, it throws a parse exception.
     * 
     * @param b
     *            the byte array to parse.
     * @param off
     *            the offset in the byte array to use when parsing.
     * @return
     *         1 indicating that a byte was parsed.
     * @throws ParseException
     *             if there are not sufficient bytes to parse the type.
     */
    private int parseType(final byte[] b, final int off) throws ParseException {
        typeVal_ = PrimitivesParser.parseByte(b, off);
        if (CiphertextType.deserialize(typeVal_) == null) {
            throw new BadCiphertextException("Invalid ciphertext type.");
        }
        return 1;
    }

    /**
     * Parse the algorithm identifier in the provided bytes. It looks for 2
     * bytes representing a short primitive type in the provided bytes starting
     * at the specified off.
     * 
     * <p>
     * If successful, it returns the number of parsed bytes which is the size of
     * the short primitive type. On failure, it throws a parse exception.
     * 
     * @param b
     *            the byte array to parse.
     * @param off
     *            the offset in the byte array to use when parsing.
     * @return
     *         the number of parsed bytes which is the size of the short
     *         primitive type.
     * @throws ParseException
     *             if there are not sufficient bytes to parse the algorithm
     *             identifier.
     */
    private int parseAlgoId(final byte[] b, final int off) throws ParseException {
        cryptoAlgoVal_ = PrimitivesParser.parseShort(b, off);
        if (CryptoAlgorithm.deserialize(cryptoAlgoVal_) == null) {
            throw new BadCiphertextException("Invalid algorithm identifier in ciphertext");
        }
        return Short.SIZE / Byte.SIZE;
    }

    /**
     * Parse the message ID in the provided bytes. It looks for bytes of the
     * size defined by the message identifier length in the provided bytes
     * starting at the specified off.
     * 
     * <p>
     * If successful, it returns the number of parsed bytes which is the message
     * identifier length. On failure, it throws a parse exception.
     * 
     * @param b
     *            the byte array to parse.
     * @param off
     *            the offset in the byte array to use when parsing.
     * @return
     *         the number of parsed bytes which is the default message
     *         identifier length.
     * @throws ParseException
     *             if there are not sufficient bytes to parse the message
     *             identifier.
     */
    private int parseMessageId(final byte[] b, final int off) throws ParseException {
        final int messageIdLen = Constants.MESSAGE_ID_LEN;
        final int len = b.length - off;
        if (len >= messageIdLen) {
            messageId_ = Arrays.copyOfRange(b, off, off + messageIdLen);
            return messageIdLen;
        } else {
            throw new ParseException("Not enough bytes to parse serial number");
        }
    }

    /**
     * Parse the length of the encryption context in the provided bytes. It
     * looks for 2 bytes representing a short primitive type in the provided
     * bytes starting at the specified off.
     * 
     * <p>
     * If successful, it returns the number of parsed bytes which is the size of
     * the short primitive type. On failure, it throws a parse exception.
     * 
     * @param b
     *            the byte array to parse.
     * @param off
     *            the offset in the byte array to use when parsing.
     * @return
     *         the number of parsed bytes which is the size of the short
     *         primitive type.
     * @throws ParseException
     *             if there are not sufficient bytes to parse the length of the
     *             encryption context.
     */
    private int parseEncryptionContextLen(final byte[] b, final int off) throws ParseException {
        encryptionContextLen_ = PrimitivesParser.parseUnsignedShort(b, off);
        if (encryptionContextLen_ < 0) {
            throw new BadCiphertextException("Invalid encryption context length in ciphertext");
        }
        return Short.SIZE / Byte.SIZE;
    }

    /**
     * Parse the encryption context in the provided bytes. It looks for bytes of
     * size defined by the encryption context length in the provided bytes
     * starting at the specified off.
     * 
     * <p>
     * If successful, it returns the number of parsed bytes which is the
     * encryption context length. On failure, it throws a parse exception.
     * 
     * @param b
     *            the byte array to parse.
     * @param off
     *            the offset in the byte array to use when parsing.
     * @return
     *         the number of parsed bytes which is the encryption context
     *         length.
     * @throws ParseException
     *             if there are not sufficient bytes to parse the encryption
     *             context.
     */
    private int parseEncryptionContext(final byte[] b, final int off) throws ParseException {
        final int len = b.length - off;
        if (len >= encryptionContextLen_) {
            encryptionContext_ = Arrays.copyOfRange(b, off, off + encryptionContextLen_);
            return encryptionContextLen_;
        } else {
            throw new ParseException("Not enough bytes to parse encryption context");
        }
    }

    /**
     * Parse the data key count in the provided bytes. It looks for 2 bytes
     * representing a short primitive type in the provided bytes starting at the
     * specified off.
     * 
     * <p>
     * If successful, it returns the number of parsed bytes which is the size of
     * the short primitive type. On failure, it throws a parse exception.
     * 
     * @param b
     *            the byte array to parse.
     * @param off
     *            the offset in the byte array to use when parsing.
     * @return
     *         the number of parsed bytes which is the size of the short
     *         primitive type.
     * @throws ParseException
     *             if there are not sufficient bytes to parse the key count.
     */
    private int parseEncryptedDataKeyCount(final byte[] b, final int off) throws ParseException {
        cipherKeyCount_ = PrimitivesParser.parseUnsignedShort(b, off);
        if (cipherKeyCount_ < 0) {
            throw new BadCiphertextException("Invalid cipher key count in ciphertext");
        }
        return Short.SIZE / Byte.SIZE;
    }

    /**
     * Parse the encrypted key blob. It delegates the parsing to the methods in
     * the key blob class.
     * 
     * @param b
     *            the byte array to parse.
     * @param off
     *            the offset in the byte array to use when parsing.
     * @return
     *         the number of parsed bytes.
     * @throws ParseException
     *             if there are not sufficient bytes to parse the key blobs.
     */
    private int parseEncryptedKeyBlob(final byte[] b, final int off) throws ParseException {
        return cipherKeyBlobs_.get(currKeyBlobIndex_).deserialize(b, off);
    }

    /**
     * Parse the content type in the provided bytes. It looks for a
     * single byte in the provided bytes starting at the specified off.
     * 
     * <p>
     * If successful, it returns 1 indicating that a byte was parsed. On
     * failure, it throws a parse exception.
     * 
     * @param b
     *            the byte array to parse.
     * @param off
     *            the offset in the byte array to use when parsing.
     * @return
     *         1 indicating that a byte was parsed.
     * @throws ParseException
     *             if there are not sufficient bytes to parse the content type.
     */
    private int parseContentType(final byte[] b, final int off) throws ParseException {
        contentTypeVal_ = PrimitivesParser.parseByte(b, off);
        if (ContentType.deserialize(contentTypeVal_) == null) {
            throw new BadCiphertextException("Invalid content type in ciphertext.");
        }
        return 1;
    }

    /**
     * Parse reserved field in the provided bytes. It looks for 4 bytes
     * representing an integer primitive type in the provided bytes starting at
     * the specified off.
     * 
     * <p>
     * If successful, it returns the number of parsed bytes which is the size of
     * the integer primitive type. On failure, it throws a parse exception.
     * 
     * @param b
     *            the byte array to parse.
     * @param off
     *            the offset in the byte array to use when parsing.
     * @return
     *         the number of parsed bytes which is the size of the short
     *         primitive type.
     * @throws ParseException
     *             if there are not sufficient bytes to parse 4 bytes.
     */
    private int parseReservedField(final byte[] b, final int off) throws ParseException {
        reservedField_ = PrimitivesParser.parseInt(b, off);
        if (reservedField_ != 0) {
            throw new BadCiphertextException("Invalid value for reserved field in ciphertext");
        }
        return Integer.SIZE / Byte.SIZE;
    }

    /**
     * Parse the length of the nonce in the provided bytes. It looks for a
     * single byte in the provided bytes starting at the specified off.
     * 
     * <p>
     * If successful, it returns 1 indicating that a byte was parsed. On
     * failure, it throws a parse exception.
     * 
     * @param b
     *            the byte array to parse.
     * @param off
     *            the offset in the byte array to use when parsing.
     * @return
     *         1 indicating that a byte was parsed.
     * @throws ParseException
     *             if there are not sufficient bytes to parse the nonce length.
     */
    private int parseNonceLen(final byte[] b, final int off) throws ParseException {
        nonceLen_ = PrimitivesParser.parseByte(b, off);
        if (nonceLen_ < 0) {
            throw new BadCiphertextException("Invalid nonce length in ciphertext");
        }
        return 1;
    }

    /**
     * Parse the frame payload length in the provided bytes. It looks for 4
     * bytes representing an integer primitive type in the provided bytes
     * starting at the specified off.
     * 
     * <p>
     * If successful, it returns the size of the parsed bytes which is the size
     * of the integer primitive type. On failure, it throws a parse exception.
     * 
     * @param b
     *            the byte array to parse.
     * @param off
     *            the offset in the byte array to use when parsing.
     * @return
     *         the size of the parsed bytes which is the size of the integer
     *         primitive type.
     * @throws ParseException
     *             if there are not sufficient bytes to parse the frame payload
     *             length.
     */
    private int parseFramePayloadLength(final byte[] b, final int off) throws ParseException {
        frameLength_ = PrimitivesParser.parseInt(b, off);
        if (frameLength_ < 0) {
            throw new BadCiphertextException("Invalid frame length in ciphertext");
        }
        return Integer.SIZE / Byte.SIZE;
    }

    /**
     * Parse the header nonce in the provided bytes. It looks for bytes of the
     * size defined by the nonce length in the provided bytes starting at the
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
     *             if there are not sufficient bytes to parse the header nonce.
     */
    private int parseHeaderNonce(final byte[] b, final int off) throws ParseException {
        final int len = b.length - off;
        if (len >= nonceLen_) {
            headerNonce_ = Arrays.copyOfRange(b, off, off + nonceLen_);
            return nonceLen_;
        } else {
            throw new ParseException("Not enough bytes to parse header nonce");
        }
    }

    /**
     * Parse the header tag in the provided bytes. It uses the crypto algorithm
     * identifier to determine the length of the tag to parse. It looks for
     * bytes of size defined by the tag length in the provided bytes starting at
     * the specified off.
     * 
     * <p>
     * If successful, it returns the size of the parsed bytes which is the tag
     * length determined from the crypto algorithm identifier. On failure, it
     * throws a parse exception.
     * 
     * @param b
     *            the byte array to parse.
     * @param off
     *            the offset in the byte array to use when parsing.
     * @return
     *         the size of the parsed bytes which is the tag length determined
     *         from the crypto algorithm identifier.
     * @throws ParseException
     *             if there are not sufficient bytes to parse the header tag.
     */
    private int parseHeaderTag(final byte[] b, final int off) throws ParseException {
        final int len = b.length - off;
        final CryptoAlgorithm cryptoAlgo = CryptoAlgorithm.deserialize(cryptoAlgoVal_);
        final int tagLen = cryptoAlgo.getTagLen();
        if (len >= tagLen) {
            headerTag_ = Arrays.copyOfRange(b, off, off + tagLen);
            return tagLen;
        } else {
            throw new ParseException("Not enough bytes to parse header tag");
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
     */
    public int deserialize(final byte[] b, final int off) throws ParseException {
        if (b == null) {
            return 0;
        }

        int parsedBytes = 0;
        try {
            if (version_ < 0) {
                parsedBytes += parseVersion(b, off + parsedBytes);
            }

            if (typeVal_ == 0) {
                parsedBytes += parseType(b, off + parsedBytes);
            }

            if (cryptoAlgoVal_ < 0) {
                parsedBytes += parseAlgoId(b, off + parsedBytes);
            }

            if (messageId_ == null) {
                parsedBytes += parseMessageId(b, off + parsedBytes);
            }

            if (encryptionContextLen_ < 0) {
                parsedBytes += parseEncryptionContextLen(b, off + parsedBytes);
            }

            if (encryptionContextLen_ > 0 && encryptionContext_.length == 0) {
                parsedBytes += parseEncryptionContext(b, off + parsedBytes);
            }

            if (cipherKeyCount_ < 0) {
                parsedBytes += parseEncryptedDataKeyCount(b, off + parsedBytes);
                cipherKeyBlobs_ = Arrays.asList(new KeyBlob[cipherKeyCount_]);
            }

            if (cipherKeyCount_ > 0) {
                while (currKeyBlobIndex_ < cipherKeyCount_) {
                    if (cipherKeyBlobs_.get(currKeyBlobIndex_) == null) {
                        cipherKeyBlobs_.set(currKeyBlobIndex_, new KeyBlob());
                    }
                    if (cipherKeyBlobs_.get(currKeyBlobIndex_).isComplete() == false) {
                        parsedBytes += parseEncryptedKeyBlob(b, off + parsedBytes);
                        // check if we had enough bytes to parse the key blob
                        if (cipherKeyBlobs_.get(currKeyBlobIndex_).isComplete() == false) {
                            throw new ParseException("Not enough bytes to parse key blob");
                        }
                    }
                    currKeyBlobIndex_++;
                }
            }

            if (contentTypeVal_ < 0) {
                parsedBytes += parseContentType(b, off + parsedBytes);
            }

            if (reservedField_ < 0) {
                parsedBytes += parseReservedField(b, off + parsedBytes);
            }

            if (nonceLen_ < 0) {
                parsedBytes += parseNonceLen(b, off + parsedBytes);
            }

            if (frameLength_ < 0) {
                parsedBytes += parseFramePayloadLength(b, off + parsedBytes);
            }

            if (nonceLen_ > 0 && headerNonce_ == null) {
                parsedBytes += parseHeaderNonce(b, off + parsedBytes);
            }

            if (headerTag_ == null) {
                parsedBytes += parseHeaderTag(b, off + parsedBytes);
            }

            isComplete_ = true;
        } catch (ParseException e) {
            // this results when we do partial parsing and there aren't enough
            // bytes to parse; ignore it and return the bytes parsed thus far.
        }

        return parsedBytes;
    }

    /**
     * Serialize the header fields into a byte array. Note this method does not
     * serialize the header nonce and tag.
     * 
     * @return
     *         the serialized bytes of the header fields not including the
     *         header nonce and tag.
     */
    public byte[] serializeAuthenticatedFields() {
        try {
            ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
            DataOutputStream dataStream = new DataOutputStream(outBytes);

            dataStream.writeByte(version_);
            dataStream.writeByte(typeVal_);
            dataStream.writeShort(cryptoAlgoVal_);
            dataStream.write(messageId_);
            PrimitivesParser.writeUnsignedShort(dataStream, encryptionContextLen_);
            if (encryptionContextLen_ > 0) {
                dataStream.write(encryptionContext_);
            }

            dataStream.writeShort(cipherKeyCount_);
            for (int i = 0; i < cipherKeyCount_; i++) {
                final byte[] cipherKeyBlobBytes = cipherKeyBlobs_.get(i).toByteArray();
                dataStream.write(cipherKeyBlobBytes);
            }

            dataStream.writeByte(contentTypeVal_);
            dataStream.writeInt(reservedField_);

            dataStream.writeByte(nonceLen_);
            dataStream.writeInt(frameLength_);

            dataStream.close();
            return outBytes.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Failed to serialize cipher text headers", e);
        }
    }

    /**
     * Serialize the header fields into a byte array. This method serializes all
     * the header fields including the header nonce and tag.
     * 
     * @return
     *         the serialized bytes of the entire header.
     */
    public byte[] toByteArray() {
        if (headerNonce_ == null || headerTag_ == null) {
            throw new AwsCryptoException("Header nonce and tag cannot be null.");
        }

        final byte[] serializedFields = serializeAuthenticatedFields();
        final int outLen = serializedFields.length + headerNonce_.length + headerTag_.length;
        final ByteBuffer serializedBytes = ByteBuffer.allocate(outLen);

        serializedBytes.put(serializedFields);
        serializedBytes.put(headerNonce_);
        serializedBytes.put(headerTag_);

        return serializedBytes.array();
    }

    /**
     * Return the version set in the header.
     * 
     * @return
     *         the byte value representing the version.
     */
    public byte getVersion() {
        return version_;
    }

    /**
     * Return the type set in the header.
     * 
     * @return
     *         the CiphertextType enum value representing the type set in the
     *         header.
     */
    public CiphertextType getType() {
        return CiphertextType.deserialize(typeVal_);
    }

    /**
     * Return the crypto algorithm identifier set in the header.
     * 
     * @return
     *         the CryptoAlgorithm enum value representing the identifier set in
     *         the header.
     */
    public CryptoAlgorithm getCryptoAlgoId() {
        return CryptoAlgorithm.deserialize(cryptoAlgoVal_);
    }

    /**
     * Return the length of the encryption context set in the header.
     * 
     * @return
     *         the length of the encryption context set in the header.
     */
    public int getEncryptionContextLen() {
        return encryptionContextLen_;
    }

    /**
     * Return the encryption context set in the header.
     * 
     * @return
     *         the bytes containing encryption context set in the header.
     */
    public byte[] getEncryptionContext() {
        return encryptionContext_.clone();
    }

    public Map<String, String> getEncryptionContextMap() {
        return EncryptionContextSerializer.deserialize(encryptionContext_);
    }

    /**
     * Return the count of the encrypted key blobs set in the header.
     * 
     * @return
     *         the count of the encrypted key blobs set in the header.
     */
    public int getEncryptedKeyBlobCount() {
        return cipherKeyCount_;
    }

    /**
     * Return the encrypted key blobs set in the header.
     * 
     * @return
     *         the KeyBlob objects representing the key blobs set in the header.
     */
    public List<KeyBlob> getEncryptedKeyBlobs() {
        return new ArrayList<>(cipherKeyBlobs_);
    }

    /**
     * Return the content type set in the header.
     * 
     * @return
     *         the ContentType enum value representing the content type set in
     *         the header.
     */
    public ContentType getContentType() {
        return ContentType.deserialize(contentTypeVal_);
    }

    /**
     * Return the message identifier set in the header.
     * 
     * @return
     *         the bytes containing the message identifier set in the header.
     */
    public byte[] getMessageId() {
        return messageId_ != null ? messageId_.clone() : null;
    }

    /**
     * Return the length of the nonce set in the header.
     * 
     * @return
     *         the length of the nonce set in the header.
     */
    public short getNonceLength() {
        return nonceLen_;
    }

    /**
     * Return the length of the frame set in the header.
     * 
     * @return
     *         the length of the frame set in the header.
     */
    public int getFrameLength() {
        return frameLength_;
    }

    /**
     * Return the header nonce set in the header.
     * 
     * @return
     *         the bytes containing the header nonce set in the header.
     */
    public byte[] getHeaderNonce() {
        return headerNonce_ != null ? headerNonce_.clone() : null;
    }

    /**
     * Return the header tag set in the header.
     * 
     * @return
     *         the header tag set in the header.
     */
    public byte[] getHeaderTag() {
        return headerTag_ != null ? headerTag_.clone() : null;
    }

    /**
     * Set the header nonce to use for authenticating the header data.
     * 
     * @param headerNonce
     *            the header nonce to use.
     */
    public void setHeaderNonce(final byte[] headerNonce) {
        headerNonce_ = headerNonce.clone();
    }

    /**
     * Set the header tag to use for authenticating the header data.
     * 
     * @param headerTag
     *            the header tag to use.
     */
    public void setHeaderTag(final byte[] headerTag) {
        headerTag_ = headerTag.clone();
    }
}