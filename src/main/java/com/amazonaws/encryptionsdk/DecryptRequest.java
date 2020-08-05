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

import static java.util.Objects.requireNonNull;
import static org.apache.commons.lang3.Validate.isTrue;

public class DecryptRequest extends AwsCryptoRequest {

    private final ParsedCiphertext parsedCiphertext;

    private DecryptRequest(Builder builder) {
        super(builder);

        isTrue(builder.ciphertext != null || builder.parsedCiphertext != null,
                "Either ciphertext or parsedCiphertext is required");
        isTrue(builder.ciphertext == null || builder.parsedCiphertext == null,
                "Only one of ciphertext or parsedCiphertext may be specified");

        this.parsedCiphertext = builder.parsedCiphertext == null ?
                new ParsedCiphertext(builder.ciphertext) : builder.parsedCiphertext;
    }

    public ParsedCiphertext parsedCiphertext() {
        return this.parsedCiphertext;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder extends AwsCryptoRequest.Builder<Builder> {

        private ParsedCiphertext parsedCiphertext;
        private byte[] ciphertext;

        /**
         * Sets the {@link ParsedCiphertext} to decrypt. Either {@link ParsedCiphertext} or a
         * {@code byte[]} ciphertext is required.
         *
         * @param parsedCiphertext The {@link ParsedCiphertext}
         * @return The Builder, for method chaining
         */
        public Builder parsedCiphertext(ParsedCiphertext parsedCiphertext) {
            requireNonNull(parsedCiphertext, "parsedCiphertext is required");
            this.parsedCiphertext = parsedCiphertext;
            return this;
        }

        /**
         * Sets the ciphertext byte array to decrypt. Either {@link ParsedCiphertext} or a
         * {@code byte[]} ciphertext is required. Note that this does not make a defensive
         * copy of the ciphertext and so any modifications made to the backing array will be
         * reflected in this Builder.
         *
         * @param ciphertext The ciphertext
         * @return The Builder, for method chaining
         */
        public Builder ciphertext(byte[] ciphertext) {
            requireNonNull(ciphertext, "ciphertext is required");
            this.ciphertext = ciphertext;
            return this;
        }

        /**
         * Constructs the DecryptRequest instance.
         *
         * @return The DecryptRequest instance
         */
        public DecryptRequest build() {
            return new DecryptRequest(this);
        }

        @Override
        Builder getThis() {
            return this;
        }
    }
}
