/*
 * Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

import com.amazonaws.encryptionsdk.DataKey;

/**
 * This exception is thrown when there are no {@link DataKey}s which can be decrypted.
 */
public class CannotUnwrapDataKeyException extends AwsCryptoException {
    private static final long serialVersionUID = -1L;

    public CannotUnwrapDataKeyException() {
        super();
    }

    public CannotUnwrapDataKeyException(final String message) {
        super(message);
    }

    public CannotUnwrapDataKeyException(final Throwable cause) {
        super(cause);
    }

    public CannotUnwrapDataKeyException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
