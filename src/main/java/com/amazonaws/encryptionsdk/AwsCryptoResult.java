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

import com.amazonaws.encryptionsdk.keyrings.KeyringTrace;
import com.amazonaws.encryptionsdk.model.CiphertextHeaders;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Represents the result of an operation by {@link AwsCrypto}. It not only captures the
 * {@code result} of the operation but also additional metadata such as the
 * {@code encryptionContext}, {@code algorithm}, {@link KeyringTrace}, and any other information
 * captured in the {@link CiphertextHeaders}.
 *
 * @param <T>
 *            the type of the underlying {@code result}
 */
public class AwsCryptoResult<T> {
    private final T result;
    private final KeyringTrace keyringTrace;
    private final List<MasterKey> masterKeys;
    private final Map<String, String> encryptionContext;
    private final CiphertextHeaders headers;

    /**
     * Note, does not make a defensive copy of any of the data.
     */
    AwsCryptoResult(final T result, final KeyringTrace keyringTrace, final List<? extends MasterKey> masterKeys, final CiphertextHeaders headers) {
        this.result = result;
        this.keyringTrace = keyringTrace;
        this.masterKeys = Collections.unmodifiableList(masterKeys);
        this.headers = headers;
        encryptionContext = this.headers.getEncryptionContextMap();
    }

    /**
     * The actual result of the cryptographic operation. This is not a defensive copy and callers
     * should not modify it.
     *
     * @return The result
     */
    public T getResult() {
        return result;
    }

    /**
     * The {@link KeyringTrace} containing all of the actions that keyrings have taken.
     *
     * @return The {@link KeyringTrace}
     */
    public KeyringTrace getKeyringTrace() {
        return keyringTrace;
    }

    /**
     * The encryption context.
     *
     * @return The encryption context
     */
    public Map<String, String> getEncryptionContext() {
        return encryptionContext;
    }

    /**
     * Convenience method equivalent to {@link #getHeaders()}{@code .getCryptoAlgoId()}.
     */
    public CryptoAlgorithm getAlgorithmSuite() {
        return headers.getCryptoAlgoId();
    }

    /**
     * The Ciphertext Headers.
     *
     * @return The CiphertextHeaders
     */
    public CiphertextHeaders getHeaders() {
        return headers;
    }

    /**
     * Package-private method for converting to a legacy CryptoResult.
     */
    CryptoResult<T, ?> toCryptoResult() {
        return new CryptoResult<>(result, masterKeys, headers);
    }
}
