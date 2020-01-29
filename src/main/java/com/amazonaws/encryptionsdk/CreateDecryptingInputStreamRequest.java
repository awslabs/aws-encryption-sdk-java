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

import static java.util.Objects.requireNonNull;

public class CreateDecryptingInputStreamRequest extends AwsCryptoRequest {

    private final InputStream inputStream;

    private CreateDecryptingInputStreamRequest(Builder builder) {
        super(builder);

        requireNonNull(builder.inputStream, "inputStream is required");
        this.inputStream = builder.inputStream;
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
     * A builder for constructing an instance of {@code CreateDecryptingInputStreamRequest}.
     *
     * @return A builder for constructing an instance of {@code CreateDecryptingInputStreamRequest}.
     */
    public static Builder builder() {
        return new Builder();
    }

    public static class Builder extends AwsCryptoRequest.Builder<Builder> {

        private InputStream inputStream;

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
         * Constructs the CreateEncryptingInputStreamRequest instance.
         *
         * @return The CreateEncryptingInputStreamRequest instance
         */
        public CreateDecryptingInputStreamRequest build() {
            return new CreateDecryptingInputStreamRequest(this);
        }

        @Override
        Builder getThis() {
            return this;
        }
    }
}
