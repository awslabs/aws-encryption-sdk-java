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
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.CannotUnwrapDataKeyException;

import java.util.ArrayList;
import java.util.List;

import static java.util.Collections.emptyList;
import static java.util.Collections.unmodifiableList;
import static java.util.Objects.requireNonNull;
import static org.apache.commons.lang3.Validate.isTrue;

/**
 * A keyring which combines other keyrings, allowing one OnEncrypt or OnDecrypt call to
 * modify the encryption or decryption materials using more than one keyring.
 */
class MultiKeyring implements Keyring {

    final Keyring generatorKeyring;
    final List<Keyring> childrenKeyrings;

    MultiKeyring(Keyring generatorKeyring, List<Keyring> childrenKeyrings) {
        this.generatorKeyring = generatorKeyring;
        this.childrenKeyrings = childrenKeyrings == null ? emptyList() : unmodifiableList(new ArrayList<>(childrenKeyrings));

        isTrue(this.generatorKeyring != null || !this.childrenKeyrings.isEmpty(),
                "At least a generator keyring or children keyrings must be defined");
    }

    @Override
    public void onEncrypt(EncryptionMaterials encryptionMaterials) {
        requireNonNull(encryptionMaterials, "encryptionMaterials are required");

        if (generatorKeyring != null) {
            generatorKeyring.onEncrypt(encryptionMaterials);
        }

        if (!encryptionMaterials.hasPlaintextDataKey()) {
            throw new AwsCryptoException("Either a generator keyring must be supplied that produces a plaintext " +
                    "data key or a plaintext data key must already be present in the encryption materials.");
        }

        for (Keyring keyring : childrenKeyrings) {
            keyring.onEncrypt(encryptionMaterials);
        }
    }

    @Override
    public void onDecrypt(DecryptionMaterials decryptionMaterials, List<? extends EncryptedDataKey> encryptedDataKeys) {
        requireNonNull(decryptionMaterials, "decryptionMaterials are required");
        requireNonNull(encryptedDataKeys, "encryptedDataKeys are required");

        if (decryptionMaterials.hasPlaintextDataKey()) {
            return;
        }

        final List<Keyring> keyringsToDecryptWith = new ArrayList<>();

        if (generatorKeyring != null) {
            keyringsToDecryptWith.add(generatorKeyring);
        }

        keyringsToDecryptWith.addAll(childrenKeyrings);

        final List<Exception> exceptions = new ArrayList<>();

        for (Keyring keyring : keyringsToDecryptWith) {
            try {
                keyring.onDecrypt(decryptionMaterials, encryptedDataKeys);

                if (decryptionMaterials.hasPlaintextDataKey()) {
                    // Decryption succeeded, return immediately
                    return;
                }
            } catch (Exception e) {
                exceptions.add(e);
            }
        }

        if (!exceptions.isEmpty()) {
            final AwsCryptoException exception = new CannotUnwrapDataKeyException(
                    "Unable to decrypt data key and one or more child keyrings had an error.", exceptions.get(0));
            exceptions.forEach(exception::addSuppressed);
            throw exception;
        }
    }
}
