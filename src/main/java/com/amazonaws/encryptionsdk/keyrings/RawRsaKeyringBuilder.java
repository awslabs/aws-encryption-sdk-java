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

package com.amazonaws.encryptionsdk.keyrings;

import java.security.PrivateKey;
import java.security.PublicKey;

public class RawRsaKeyringBuilder {
    private String keyNamespace;
    private String keyName;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private RsaPaddingScheme paddingScheme;

    private RawRsaKeyringBuilder() {
        // Use RawRsaKeyringBuilder.standard() or StandardKeyrings.rawRsa() to instantiate
    }

    /**
     * Constructs a new instance of {@code RawRsaKeyringBuilder}
     *
     * @return The {@code RawRsaKeyringBuilder}
     */
    public static RawRsaKeyringBuilder standard() {
        return new RawRsaKeyringBuilder();
    }

    /**
     * A value that, together with the key name, identifies the wrapping key (required).
     *
     * @param keyNamespace The key namespace
     * @return The RawAesKeyringBuilder, for method chaining
     */
    public RawRsaKeyringBuilder keyNamespace(String keyNamespace) {
        this.keyNamespace = keyNamespace;
        return this;
    }

    /**
     * A value that, together with the key namespace, identifies the wrapping key (required).
     *
     * @param keyName The key name
     * @return The RawAesKeyringBuilder, for method chaining
     */
    public RawRsaKeyringBuilder keyName(String keyName) {
        this.keyName = keyName;
        return this;
    }

    /**
     * The RSA public key used by this keyring to encrypt data keys. Not required when used for decryption.
     *
     * @param publicKey The public key
     * @return The RawRsaKeyringBuilder, for method chaining
     */
    public RawRsaKeyringBuilder publicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
        return this;
    }

    /**
     * The RSA private key used by this keyring to decrypt data keys. Not required when used for encryption.
     *
     * @param privateKey The public key
     * @return The RawRsaKeyringBuilder, for method chaining
     */
    public RawRsaKeyringBuilder privateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
        return this;
    }

    /**
     * The RSA padding scheme to use with this keyring (required).
     *
     * @param paddingScheme The RSA padding scheme
     * @return The RawRsaKeyringBuilder, for method chaining
     */
    public RawRsaKeyringBuilder paddingScheme(RsaPaddingScheme paddingScheme) {
        this.paddingScheme = paddingScheme;
        return this;
    }

    /**
     * Constructs the {@link Keyring} instance.
     *
     * @return The {@link Keyring} instance
     */
    public Keyring build() {
        return new RawRsaKeyring(keyNamespace, keyName, publicKey, privateKey, paddingScheme);
    }

    public enum RsaPaddingScheme {

        PKCS1("RSA/ECB/PKCS1Padding"),
        OAEP_SHA1_MGF1("RSA/ECB/OAEPWithSHA-1AndMGF1Padding"),
        OAEP_SHA256_MGF1("RSA/ECB/OAEPWithSHA-256AndMGF1Padding"),
        OAEP_SHA384_MGF1("RSA/ECB/OAEPWithSHA-384AndMGF1Padding"),
        OAEP_SHA512_MGF1("RSA/ECB/OAEPWithSHA-512AndMGF1Padding");

        private final String transformation;

        RsaPaddingScheme(String transformation) {
            this.transformation = transformation;
        }

        /**
         * The Cipher transformation standard name as specified in
         * https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Cipher
         * Note: In all cases the hash function used with MGF1 is the
         * same as the hash function used directly with the message.
         *
         * @return The transformation name
         */
        public String getTransformation() {
            return transformation;
        }
    }
}
