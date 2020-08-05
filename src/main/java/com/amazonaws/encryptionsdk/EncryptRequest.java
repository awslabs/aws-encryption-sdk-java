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

import com.amazonaws.encryptionsdk.keyrings.Keyring;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static java.util.Objects.requireNonNull;

public class EncryptRequest extends AwsCryptoRequest {

    private final byte[] plaintext;
    private final Map<String, String> encryptionContext;

    private EncryptRequest(Builder builder) {
        super(builder);

        requireNonNull(builder.plaintext, "plaintext is required");
        requireNonNull(builder.encryptionContext, "encryptionContext is required");
        this.plaintext = builder.plaintext;
        this.encryptionContext = builder.encryptionContext;
    }

    public byte[] plaintext() {
        return this.plaintext;
    }

    public Map<String, String> encryptionContext() {
        return this.encryptionContext;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder extends AwsCryptoRequest.Builder<Builder> {

        private byte[] plaintext;
        private Map<String, String> encryptionContext = Collections.emptyMap();

        /**
         * Sets the plaintext byte array to encrypt. Note that this does not make a defensive copy of the
         * plaintext and so any modifications made to the backing array will be reflected in this Builder.
         *
         * @param plaintext The {@link Keyring}
         * @return The Builder, for method chaining
         */
        public Builder plaintext(byte[] plaintext) {
            requireNonNull(plaintext, "plaintext is required");
            this.plaintext = plaintext;
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
            this.encryptionContext = Collections.unmodifiableMap(new HashMap<>(encryptionContext));
            return this;
        }

        /**
         * Constructs the EncryptRequest instance.
         *
         * @return The EncryptRequest instance
         */
        public EncryptRequest build() {
            return new EncryptRequest(this);
        }

        @Override
        Builder getThis() {
            return this;
        }
    }
}
