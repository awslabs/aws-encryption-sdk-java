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
import com.amazonaws.encryptionsdk.model.DecryptionMaterials;
import com.amazonaws.encryptionsdk.model.EncryptionMaterials;
import com.amazonaws.encryptionsdk.model.KeyBlob;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.List;
import java.util.logging.Logger;

import static com.amazonaws.encryptionsdk.EncryptedDataKey.PROVIDER_ENCODING;
import static java.util.Objects.requireNonNull;
import static org.apache.commons.lang3.Validate.notBlank;

/**
 * A keyring supporting local encryption and decryption using either RSA or AES-GCM.
 */
abstract class RawKeyring implements Keyring {

    final String keyNamespace;
    final String keyName;
    final byte[] keyNameBytes;
    private final JceKeyCipher jceKeyCipher;
    private static final Logger LOGGER = Logger.getLogger(RawKeyring.class.getName());

    RawKeyring(final String keyNamespace, final String keyName, JceKeyCipher jceKeyCipher) {
        notBlank(keyNamespace, "keyNamespace is required");
        notBlank(keyName, "keyName is required");
        requireNonNull(jceKeyCipher, "jceKeyCipher is required");

        this.keyNamespace = keyNamespace;
        this.keyName = keyName;
        this.keyNameBytes = keyName.getBytes(PROVIDER_ENCODING);
        this.jceKeyCipher = jceKeyCipher;
    }

    /**
     * Returns true if the given encrypted data key may be decrypted with this keyring.
     *
     * @param encryptedDataKey The encrypted data key.
     * @return True if the key may be decrypted, false otherwise.
     */
    abstract boolean validToDecrypt(EncryptedDataKey encryptedDataKey);

    @Override
    public EncryptionMaterials onEncrypt(EncryptionMaterials encryptionMaterials) {
        requireNonNull(encryptionMaterials, "encryptionMaterials are required");

        EncryptionMaterials resultMaterials = encryptionMaterials;

        if (!encryptionMaterials.hasCleartextDataKey()) {
            resultMaterials = generateDataKey(encryptionMaterials);
        }

        final EncryptedDataKey encryptedDataKey = jceKeyCipher.encryptKey(
                resultMaterials.getCleartextDataKey().getEncoded(),
                keyName, keyNamespace, resultMaterials.getEncryptionContext());
        return resultMaterials.withEncryptedDataKey(new KeyBlob(encryptedDataKey));
    }

    @Override
    public DecryptionMaterials onDecrypt(DecryptionMaterials decryptionMaterials, List<? extends EncryptedDataKey> encryptedDataKeys) {
        requireNonNull(decryptionMaterials, "decryptionMaterials are required");
        requireNonNull(encryptedDataKeys, "encryptedDataKeys are required");

        if (decryptionMaterials.hasCleartextDataKey() || encryptedDataKeys.isEmpty()) {
            return decryptionMaterials;
        }

        for (EncryptedDataKey encryptedDataKey : encryptedDataKeys) {
            if (validToDecrypt(encryptedDataKey)) {
                try {
                    final byte[] decryptedKey = jceKeyCipher.decryptKey(
                            encryptedDataKey, keyName, decryptionMaterials.getEncryptionContext());
                    return decryptionMaterials.withCleartextDataKey(
                            new SecretKeySpec(decryptedKey, decryptionMaterials.getAlgorithm().getDataKeyAlgo()));
                } catch (Exception e) {
                    LOGGER.info("Could not decrypt key due to: " + e.getMessage());
                }
            }
        }

        return decryptionMaterials;
    }

    private EncryptionMaterials generateDataKey(EncryptionMaterials encryptionMaterials) {
        final byte[] rawKey = new byte[encryptionMaterials.getAlgorithm().getDataKeyLength()];
        Utils.getSecureRandom().nextBytes(rawKey);
        final SecretKey key = new SecretKeySpec(rawKey, encryptionMaterials.getAlgorithm().getDataKeyAlgo());

        return encryptionMaterials.withCleartextDataKey(key);
    }
}
