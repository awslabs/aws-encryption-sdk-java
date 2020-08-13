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
    private final Integer maxBodySize;
    private final Integer maxHeaderSize;

    private CreateDecryptingOutputStreamRequest(Builder builder) {
        super(builder);

        requireNonNull(builder.outputStream, "outputStream is required");
        if (builder.maxBodySize != null && builder.maxBodySize < 0) {
            throw new IllegalArgumentException("maxBodySize must be null or non-negative.");
        }
        if (builder.maxHeaderSize != null && builder.maxHeaderSize < 0) {
            throw new IllegalArgumentException("maxHeaderSize must be null or positive.");
        }
        this.outputStream = builder.outputStream;
        this.maxBodySize = builder.maxBodySize;
        this.maxHeaderSize = builder.maxHeaderSize;
    }

    /**
     * The {@link OutputStream} to be read from.
     *
     * @return The {@link OutputStream} to be read from.
     */
    public OutputStream outputStream() {
        return this.outputStream;
    }

    public Integer maxBodySize() {
        return maxBodySize;
    }

    public Integer maxHeaderSize() {
        return maxHeaderSize;
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
        private Integer maxBodySize;
        private Integer maxHeaderSize;

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
         * Sets the maxBodySize
         *
         * @param maxBodySize The maximum length of encrypted content that is
         *   allowed to be decrypted at once. Decryption will fail on any encrypted message
         *   that requires performing one decryption operation on a length greater
         *   than this value.
         * @return The Builder, for method chaining
         */
        public Builder maxBodySize(Integer maxBodySize) {
            if (maxBodySize < 0) {
                throw new IllegalArgumentException("maxBodySize must be null or non-negative");
            }
            this.maxBodySize = maxBodySize;
            return this;
        }

        /**
         * Sets the maxHeaderSize
         *
         * @param maxHeaderSize The maximum length of message header that is
         *   allowed to be deserialized. Decryption will fail on any encrypted message
         *   with a message header length greater than this value.
         * @return The Builder, for method chaining
         */
        public Builder maxHeaderSize(Integer maxHeaderSize) {
            if (maxHeaderSize < 0) {
                throw new IllegalArgumentException("maxHeaderSize must be null or positive");
            }
            this.maxHeaderSize = maxHeaderSize;
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
