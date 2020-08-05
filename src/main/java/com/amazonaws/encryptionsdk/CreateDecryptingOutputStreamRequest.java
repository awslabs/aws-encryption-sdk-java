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

import static java.util.Objects.requireNonNull;

public class CreateDecryptingOutputStreamRequest extends AwsCryptoRequest {

    private final OutputStream outputStream;

    private CreateDecryptingOutputStreamRequest(Builder builder) {
        super(builder);

        requireNonNull(builder.outputStream, "outputStream is required");
        this.outputStream = builder.outputStream;
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
     * A builder for constructing an instance of {@code CreateDecryptingOutputStreamRequest}.
     *
     * @return A builder for constructing an instance of {@code CreateDecryptingOutputStreamRequest}.
     */
    public static Builder builder() {
        return new Builder();
    }

    public static class Builder extends AwsCryptoRequest.Builder<Builder> {

        private OutputStream outputStream;

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
         * Constructs the CreateDecryptingOutputStreamRequest instance.
         *
         * @return The CreateDecryptingOutputStreamRequest instance
         */
        public CreateDecryptingOutputStreamRequest build() {
            return new CreateDecryptingOutputStreamRequest(this);
        }

        @Override
        Builder getThis() {
            return this;
        }
    }
}
