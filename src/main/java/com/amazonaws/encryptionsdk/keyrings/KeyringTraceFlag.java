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

package com.amazonaws.encryptionsdk.keyrings;

/**
 * Enum representing the possible actions a keyring may take on the
 * different wrapping keys it manages.
 */
public enum KeyringTraceFlag {

    /**
     * A flag to represent that a keyring has generated a plaintext data key.
     */
    GENERATED_DATA_KEY,

    /**
     * A flag to represent that a keyring has created an encrypted data key.
     */
    ENCRYPTED_DATA_KEY,

    /**
     * A flag to represent that a keyring has obtained the
     * corresponding plaintext data key from an encrypted data key.
     */
    DECRYPTED_DATA_KEY,

    /**
     * A flag to represent that the keyring has cryptographically
     * bound the encryption context to a newly created encrypted data key.
     */
    SIGNED_ENCRYPTION_CONTEXT,

    /**
     * A flag to represent that the keyring has verified that an encrypted
     * data key was originally created with a particular encryption context.
     */
    VERIFIED_ENCRYPTION_CONTEXT
}
