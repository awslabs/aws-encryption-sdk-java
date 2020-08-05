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

import javax.crypto.SecretKey;

public class RawAesKeyringBuilder {
    private String keyNamespace;
    private String keyName;
    private SecretKey wrappingKey;

    private RawAesKeyringBuilder() {
        // Use RawAesKeyringBuilder.standard() or StandardKeyrings.rawAes() to instantiate
    }

    /**
     * Constructs a new instance of {@code RawAesKeyringBuilder}
     *
     * @return The {@code RawAesKeyringBuilder}
     */
    public static RawAesKeyringBuilder standard() {
        return new RawAesKeyringBuilder();
    }

    /**
     * A value that, together with the key name, identifies the wrapping key (required).
     *
     * @param keyNamespace The key namespace
     * @return The RawAesKeyringBuilder, for method chaining
     */
    public RawAesKeyringBuilder keyNamespace(String keyNamespace) {
        this.keyNamespace = keyNamespace;
        return this;
    }

    /**
     * A value that, together with the key namespace, identifies the wrapping key (required).
     *
     * @param keyName The key name
     * @return The RawAesKeyringBuilder, for method chaining
     */
    public RawAesKeyringBuilder keyName(String keyName) {
        this.keyName = keyName;
        return this;
    }

    /**
     * The AES key input to AES-GCM to encrypt plaintext data keys (required).
     *
     * @param wrappingKey The wrapping key
     * @return The RawAesKeyringBuilder, for method chaining
     */
    public RawAesKeyringBuilder wrappingKey(SecretKey wrappingKey) {
        this.wrappingKey = wrappingKey;
        return this;
    }

    /**
     * Constructs the {@link Keyring} instance.
     *
     * @return The {@link Keyring} instance
     */
    public Keyring build() {
        return new RawAesKeyring(keyNamespace, keyName, wrappingKey);
    }
}
