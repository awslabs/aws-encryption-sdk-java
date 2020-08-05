/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

import com.amazonaws.encryptionsdk.caching.CachingCryptoMaterialsManager;
import com.amazonaws.encryptionsdk.exception.BadCiphertextException;
import com.amazonaws.encryptionsdk.internal.MessageCryptoHandler;

import java.io.IOException;
import java.io.InputStream;

/**
 * An AwsCryptoInputStream is a subclass of java.io.InputStream. It performs cryptographic
 * transformation of the bytes passing through it.
 *
 * <p>
 * The AwsCryptoInputStream wraps a provided InputStream object and performs cryptographic
 * transformation of the bytes read from the wrapped InputStream. It uses the cryptography handler
 * provided during construction to invoke methods that perform the cryptographic transformations.
 *
 * <p>
 * In short, reading from the AwsCryptoInputStream returns bytes that are the cryptographic
 * transformations of the bytes read from the wrapped InputStream.
 *
 * <p>
 * For example, if the cryptography handler provides methods for decryption, the AwsCryptoInputStream
 * will read ciphertext bytes from the wrapped InputStream, decrypt, and return them as plaintext
 * bytes.
 *
 * <p>
 * This class adheres strictly to the semantics, especially the failure semantics, of its ancestor
 * class java.io.InputStream. This class overrides all the methods specified in its ancestor class.
 *
 * <p>
 * To instantiate an instance of this class, please see {@link AwsCrypto}.
 *
 */
public class AwsCryptoInputStream extends InputStream {

    private final CryptoInputStream<?> cryptoInputStream;

    /**
     * Constructs an AwsCryptoInputStream that wraps the provided InputStream object. It performs
     * cryptographic transformation of the bytes read from the wrapped InputStream using the methods
     * provided in the provided CryptoHandler implementation.
     *
     * @param inputStream
     *            the inputStream object to be wrapped.
     * @param cryptoHandler
     *            the cryptoHandler implementation that provides the methods to use in performing
     *            cryptographic transformation of the bytes read from the inputStream.
     */
    AwsCryptoInputStream(final InputStream inputStream, final MessageCryptoHandler cryptoHandler) {
        cryptoInputStream = new CryptoInputStream<>(inputStream, cryptoHandler);
    }

    /**
     * {@inheritDoc}
     *
     * @throws BadCiphertextException
     *             This is thrown only during decryption if b contains invalid or corrupt
     *             ciphertext.
     */
    @Override
    public int read(final byte[] b, final int off, final int len) throws IllegalArgumentException, IOException,
            BadCiphertextException {
        return cryptoInputStream.read(b, off, len);
    }

    /**
     * {@inheritDoc}
     *
     * @throws BadCiphertextException
     *             This is thrown only during decryption if b contains invalid or corrupt
     *             ciphertext.
     */
    @Override
    public int read(final byte[] b) throws IllegalArgumentException, IOException, BadCiphertextException {
        return cryptoInputStream.read(b);
    }

    /**
     * {@inheritDoc}
     *
     * @throws BadCiphertextException
     *             if b contains invalid or corrupt ciphertext. This is thrown only during
     *             decryption.
     */
    @Override
    public int read() throws IOException, BadCiphertextException {
        return cryptoInputStream.read();
    }

    @Override
    public void close() throws IOException {
        cryptoInputStream.close();
    }

    /**
     * Returns metadata associated with the performed cryptographic operation.
     */
    @Override
    public int available() throws IOException {
        return cryptoInputStream.available();
    }

    /**
     * Sets an upper bound on the size of the input data. This method should be called before reading any data from the
     * stream. If this method is not called prior to reading any data, performance may be reduced (notably, it will not
     * be possible to cache data keys when encrypting).
     *
     * Among other things, this size is used to enforce limits configured on the {@link CachingCryptoMaterialsManager}.
     *
     * If the input size set here is exceeded, an exception will be thrown, and the encryption or decryption will fail.
     *
     * @param size Maximum input size.
     */
    public void setMaxInputLength(long size) {
        cryptoInputStream.setMaxInputLength(size);
    }

    /**
     * Gets the {@link AwsCryptoResult}.
     *
     * @return The {@link AwsCryptoResult}
     * @throws IOException if an input/output exception occurs while processing the result
     */
    public AwsCryptoResult<AwsCryptoInputStream> getAwsCryptoResult() throws IOException {
        return cryptoInputStream.getAwsCryptoResult(this);
    }
    
    CryptoInputStream<?> toCryptoInputStream() {
        return cryptoInputStream;
    }
}
