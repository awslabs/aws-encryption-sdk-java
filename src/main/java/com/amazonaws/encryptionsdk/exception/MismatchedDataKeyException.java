/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package com.amazonaws.encryptionsdk.exception;

/**
 * This exception is thrown when the key used by KMS to decrypt a data key does not
 * match the provider information contained within the encrypted data key.
 */
public class MismatchedDataKeyException extends AwsCryptoException {

    private static final long serialVersionUID = -1L;

    public MismatchedDataKeyException() {
        super();
    }

    public MismatchedDataKeyException(final String message) {
        super(message);
    }

    public MismatchedDataKeyException(final Throwable cause) {
        super(cause);
    }

    public MismatchedDataKeyException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
