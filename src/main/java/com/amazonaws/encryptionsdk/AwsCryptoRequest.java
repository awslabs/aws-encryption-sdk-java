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

import java.util.function.Consumer;

import static java.util.Objects.requireNonNull;
import static org.apache.commons.lang3.Validate.isTrue;

class AwsCryptoRequest {
    private final CryptoMaterialsManager cryptoMaterialsManager;

    AwsCryptoRequest(Builder builder) {
        isTrue(builder.cryptoMaterialsManager != null || builder.keyring != null,
                "Either a cryptoMaterialsManager or keyring is required");
        isTrue(builder.cryptoMaterialsManager == null || builder.keyring == null,
                "Only one of cryptoMaterialsManager or keyring may be specified");

        this.cryptoMaterialsManager = builder.cryptoMaterialsManager == null ?
                new DefaultCryptoMaterialsManager(builder.keyring) : builder.cryptoMaterialsManager;
    }

    public CryptoMaterialsManager cryptoMaterialsManager() {
        return cryptoMaterialsManager;
    }

    abstract static class Builder<T extends Builder<T>> {

        private CryptoMaterialsManager cryptoMaterialsManager;
        private Keyring keyring;

        /**
         * Sets the {@link CryptoMaterialsManager}. Either a {@link CryptoMaterialsManager} or a
         * {@link Keyring} is required.
         *
         * @param cryptoMaterialsManager The {@link CryptoMaterialsManager}
         * @return The Builder, for method chaining
         */
        public T cryptoMaterialsManager(CryptoMaterialsManager cryptoMaterialsManager) {
            requireNonNull(cryptoMaterialsManager, "cryptoMaterialsManager is required");
            this.cryptoMaterialsManager = cryptoMaterialsManager;
            return getThis();
        }

        /**
         * Sets the {@link Keyring}. Either a {@link CryptoMaterialsManager} or a
         * {@link Keyring} is required.
         *
         * @param keyring The {@link Keyring}
         * @return The Builder, for method chaining
         */
        public T keyring(Keyring keyring) {
            requireNonNull(keyring, "keyring is required");
            this.keyring = keyring;
            return getThis();
        }

        abstract T getThis();

        T applyMutation(Consumer<T> mutator) {
            mutator.accept(getThis());
            return getThis();
        }
    }
}
