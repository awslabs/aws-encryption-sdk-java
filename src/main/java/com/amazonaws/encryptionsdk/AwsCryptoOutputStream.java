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
import java.io.OutputStream;

/**
 * An AwsCryptoOutputStream is a subclass of java.io.OutputStream. It performs cryptographic
 * transformation of the bytes passing through it.
 *
 * <p>
 * The AwsCryptoOutputStream wraps a provided OutputStream object and performs cryptographic
 * transformation of the bytes written to it. The transformed bytes are then written to the wrapped
 * OutputStream. It uses the cryptography handler provided during construction to invoke methods
 * that perform the cryptographic transformations.
 *
 * <p>
 * In short, writing to the AwsCryptoOutputStream results in those bytes being cryptographically
 * transformed and written to the wrapped OutputStream.
 *
 * <p>
 * For example, if the crypto handler provides methods for decryption, the AwsCryptoOutputStream will
 * decrypt the provided ciphertext bytes and write the plaintext bytes to the wrapped OutputStream.
 *
 * <p>
 * This class adheres strictly to the semantics, especially the failure semantics, of its ancestor
 * class java.io.OutputStream. This class overrides all the methods specified in its ancestor class.
 *
 * <p>
 * To instantiate an instance of this class, please see {@link AwsCrypto}.
 *
 */
public class AwsCryptoOutputStream extends OutputStream {

    private final CryptoOutputStream<?> cryptoOutputStream;

    /**
     * Constructs an AwsCryptoOutputStream that wraps the provided OutputStream object. It performs
     * cryptographic transformation of the bytes written to it using the methods provided in the
     * provided CryptoHandler implementation. The transformed bytes are then written to the wrapped
     * OutputStream.
     *
     * @param outputStream
     *            the outputStream object to be wrapped.
     * @param cryptoHandler
     *            the cryptoHandler implementation that provides the methods to use in performing
     *            cryptographic transformation of the bytes written to this stream.
     */
    AwsCryptoOutputStream(final OutputStream outputStream, final MessageCryptoHandler cryptoHandler) {
        cryptoOutputStream = new CryptoOutputStream<>(outputStream, cryptoHandler);
    }

    /**
     * {@inheritDoc}
     *
     * @throws BadCiphertextException
     *             This is thrown only during decryption if b contains invalid or corrupt
     *             ciphertext.
     */
    @Override
    public void write(final byte[] b) throws IllegalArgumentException, IOException, BadCiphertextException {
        cryptoOutputStream.write(b);
    }

    /**
     * {@inheritDoc}
     *
     * @throws BadCiphertextException
     *             This is thrown only during decryption if b contains invalid or corrupt
     *             ciphertext.
     */
    @Override
    public void write(final byte[] b, final int off, final int len) throws IllegalArgumentException, IOException,
            BadCiphertextException {
        cryptoOutputStream.write(b, off, len);
    }

    /**
     * {@inheritDoc}
     *
     * @throws BadCiphertextException
     *             This is thrown only during decryption if b contains invalid or corrupt
     *             ciphertext.
     */
    @Override
    public void write(int b) throws IOException, BadCiphertextException {
        cryptoOutputStream.write(b);
    }

    /**
     * Closes this output stream and releases any system resources associated
     * with this stream.
     *
     * <p>
     * This method writes any final bytes to the underlying stream that complete
     * the cryptographic transformation of the written bytes. It also calls close
     * on the wrapped OutputStream.
     *
     * @throws IOException
     *             if an I/O error occurs.
     * @throws BadCiphertextException
     *             This is thrown only during decryption if b contains invalid
     *             or corrupt ciphertext.
     */
    @Override
    public void close() throws IOException, BadCiphertextException {
        cryptoOutputStream.close();
    }

    /**
     * Sets an upper bound on the size of the input data. This method should be called before writing any data to the
     * stream. If this method is not called prior to writing data, performance may be reduced (notably, it will not
     * be possible to cache data keys when encrypting).
     *
     * Among other things, this size is used to enforce limits configured on the {@link CachingCryptoMaterialsManager}.
     *
     * If the size set here is exceeded, an exception will be thrown, and the encryption or decryption will fail.
     *
     * @param size Maximum input size.
     */
    public void setMaxInputLength(long size) {
        cryptoOutputStream.setMaxInputLength(size);
    }

    /**
     * Gets the {@link AwsCryptoResult}.
     *
     * @return The {@link AwsCryptoResult}
     */
    public AwsCryptoResult<AwsCryptoOutputStream> getAwsCryptoResult() {
        return cryptoOutputStream.getAwsCryptoResult(this);
    }

    CryptoOutputStream<?> toCryptoOutputStream() {
        return cryptoOutputStream;
    }
}
