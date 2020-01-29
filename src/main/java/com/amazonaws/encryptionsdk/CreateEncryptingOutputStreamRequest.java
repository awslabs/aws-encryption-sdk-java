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

import java.io.OutputStream;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static java.util.Objects.requireNonNull;

public class CreateEncryptingOutputStreamRequest extends AwsCryptoRequest {

    private final OutputStream outputStream;
    private final Map<String, String> encryptionContext;

    private CreateEncryptingOutputStreamRequest(Builder builder) {
        super(builder);

        requireNonNull(builder.outputStream, "outputStream is required");
        requireNonNull(builder.encryptionContext, "encryptionContext is required");
        this.outputStream = builder.outputStream;
        this.encryptionContext = builder.encryptionContext;
    }

    /**
     * The {@link OutputStream} to be read from.
     *
     * @return The {@link OutputStream} to be read from.
     */
    public OutputStream outputStream() {
        return this.outputStream;
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
     * A builder for constructing an instance of {@code CreateEncryptingOutputStreamRequest}.
     *
     * @return A builder for constructing an instance of {@code CreateEncryptingOutputStreamRequest}.
     */
    public static Builder builder() {
        return new Builder();
    }

    public static class Builder extends AwsCryptoRequest.Builder<Builder> {

        private OutputStream outputStream;
        private Map<String, String> encryptionContext = Collections.emptyMap();

        /**
         * Sets the {@link OutputStream}
         *
         * @param outputStream The {@link OutputStream}
         * @return The Builder, for method chaining
         */
        public Builder outputStream(OutputStream outputStream) {
            requireNonNull(outputStream, "outputStream is required");
            this.outputStream = outputStream;
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
         * Constructs the CreateEncryptingOutputStreamRequest instance.
         *
         * @return The CreateEncryptingOutputStreamRequest instance
         */
        public CreateEncryptingOutputStreamRequest build() {
            return new CreateEncryptingOutputStreamRequest(this);
        }

        @Override
        Builder getThis() {
            return this;
        }
    }
}
