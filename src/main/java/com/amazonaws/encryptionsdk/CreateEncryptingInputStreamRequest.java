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

import java.io.InputStream;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static java.util.Objects.requireNonNull;

public class CreateEncryptingInputStreamRequest extends AwsCryptoRequest {

    private final InputStream inputStream;
    private final Map<String, String> encryptionContext;

    private CreateEncryptingInputStreamRequest(Builder builder) {
        super(builder);

        requireNonNull(builder.inputStream, "inputStream is required");
        requireNonNull(builder.encryptionContext, "encryptionContext is required");
        this.inputStream = builder.inputStream;
        this.encryptionContext = builder.encryptionContext;
    }

    /**
     * The {@link InputStream} to be read from.
     *
     * @return The {@link InputStream} to be read from.
     */
    public InputStream inputStream() {
        return this.inputStream;
    }

    /**
     * The encryption context associated with this encryption.
     *
     * @return The encryption context associated with this encryption.
     */
    public Map<String, String> encryptionContext() {
        return this.encryptionContext;
    }

    /**
     * A builder for constructing an instance of {@code CreateEncryptingInputStreamRequest}.
     *
     * @return A builder for constructing an instance of {@code CreateEncryptingInputStreamRequest}.
     */
    public static Builder builder() {
        return new Builder();
    }

    public static class Builder extends AwsCryptoRequest.Builder<Builder> {

        private InputStream inputStream;
        private Map<String, String> encryptionContext = Collections.emptyMap();

        /**
         * Sets the {@link InputStream}
         *
         * @param inputStream The {@link InputStream}
         * @return The Builder, for method chaining
         */
        public Builder inputStream(InputStream inputStream) {
            requireNonNull(inputStream, "inputStream is required");
            this.inputStream = inputStream;
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
         * Constructs the CreateEncryptingInputStreamRequest instance.
         *
         * @return The CreateEncryptingInputStreamRequest instance
         */
        public CreateEncryptingInputStreamRequest build() {
            return new CreateEncryptingInputStreamRequest(this);
        }

        @Override
        Builder getThis() {
            return this;
        }
    }
}
