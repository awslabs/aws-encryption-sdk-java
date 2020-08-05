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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static java.util.Objects.requireNonNull;

public class EstimateCiphertextSizeRequest extends AwsCryptoRequest {

    private final int plaintextSize;
    private final Map<String, String> encryptionContext;

    private EstimateCiphertextSizeRequest(Builder builder) {
        super(builder);
        requireNonNull(builder.encryptionContext, "encryptionContext is required");

        this.plaintextSize = builder.plaintextSize;
        this.encryptionContext = builder.encryptionContext;
    }

    public int plaintextSize() {
        return plaintextSize;
    }

    public Map<String, String> encryptionContext() {
        return encryptionContext;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder extends AwsCryptoRequest.Builder<Builder> {

        private int plaintextSize;
        private Map<String, String> encryptionContext = Collections.emptyMap();

        /**
         * Sets the plaintextSize.
         *
         * @param plaintextSize The plaintext size
         * @return The Builder, for method chaining
         */
        public Builder plaintextSize(int plaintextSize) {
            this.plaintextSize = plaintextSize;
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
         * Constructs the EstimateCiphertextSizeRequest instance.
         *
         * @return The EstimateCiphertextSizeRequest instance
         */
        public EstimateCiphertextSizeRequest build() {
            return new EstimateCiphertextSizeRequest(this);
        }

        @Override
        Builder getThis() {
            return this;
        }
    }
}
