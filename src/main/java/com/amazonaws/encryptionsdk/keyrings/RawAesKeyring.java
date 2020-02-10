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
import com.amazonaws.encryptionsdk.internal.JceKeyCipher;
import com.amazonaws.encryptionsdk.internal.Utils;

import javax.crypto.SecretKey;

/**
 * A {@code Keyring} which does local AES-GCM encryption
 * decryption of data keys using the provided wrapping key.
 * <p>
 * Instantiate by using the {@code StandardKeyrings.rawAesBuilder(...)} factory method.
 */
class RawAesKeyring extends RawKeyring {

    RawAesKeyring(String keyNamespace, String keyName, SecretKey wrappingKey) {
        super(keyNamespace, keyName, JceKeyCipher.aesGcm(wrappingKey));
    }

    @Override
    boolean validToDecrypt(EncryptedDataKey encryptedDataKey) {

        // the key provider ID of the encrypted data key must
        // have a value equal to this keyring's key namespace.
        if (!keyNamespace.equals(encryptedDataKey.getProviderId())) {
            return false;
        }

        // the key name obtained from the encrypted data key's key provider
        // information must have a value equal to this keyring's key name.
        if (!Utils.arrayPrefixEquals(encryptedDataKey.getProviderInformation(), keyNameBytes, keyNameBytes.length)) {
            return false;
        }

        return true;
    }
}
