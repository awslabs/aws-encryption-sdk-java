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

import com.amazonaws.encryptionsdk.EncryptedDataKey;
import com.amazonaws.encryptionsdk.model.DecryptionMaterials;
import com.amazonaws.encryptionsdk.model.EncryptionMaterials;

import java.util.List;

/**
 * Keyrings are responsible for the generation, encryption, and decryption of data keys.
 */
public interface Keyring {

    /**
     * Attempt to encrypt either the given data key (if present) or one that may be generated
     *
     * @param encryptionMaterials Materials needed for encryption that the keyring may modify.
     */
    void onEncrypt(EncryptionMaterials encryptionMaterials);

    /**
     * Attempt to decrypt the encrypted data keys
     *
     * @param decryptionMaterials Materials needed for decryption that the keyring may modify.
     * @param encryptedDataKeys   List of encrypted data keys.
     */
    void onDecrypt(DecryptionMaterials decryptionMaterials, List<? extends EncryptedDataKey> encryptedDataKeys);

}
