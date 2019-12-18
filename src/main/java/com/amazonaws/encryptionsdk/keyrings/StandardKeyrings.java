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

import com.amazonaws.encryptionsdk.kms.DataKeyEncryptionDao;
import com.amazonaws.encryptionsdk.kms.KmsClientSupplier;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.List;

/**
 * Factory methods for instantiating the standard {@code Keyring}s provided by the AWS Encryption SDK.
 */
public class StandardKeyrings {

    private StandardKeyrings() {
    }

    /**
     * Constructs a {@code Keyring} which does local AES-GCM encryption
     * decryption of data keys using the provided wrapping key.
     *
     * @param keyNamespace A value that, together with the key name, identifies the wrapping key.
     * @param keyName      A value that, together with the key namespace, identifies the wrapping key.
     * @param wrappingKey  The AES key input to AES-GCM to encrypt plaintext data keys.
     * @return The {@link Keyring}
     */
    public static Keyring rawAes(String keyNamespace, String keyName, SecretKey wrappingKey) {
        return new RawAesKeyring(keyNamespace, keyName, wrappingKey);
    }

    /**
     * Constructs a {@code Keyring} which does local RSA encryption and decryption of data keys using the
     * provided public and private keys. If {@code privateKey} is {@code null} then the returned {@code Keyring}
     * can only be used for encryption.
     *
     * @param keyNamespace      A value that, together with the key name, identifies the wrapping key.
     * @param keyName           A value that, together with the key namespace, identifies the wrapping key.
     * @param publicKey         The RSA public key used by this keyring to encrypt data keys.
     * @param privateKey        The RSA private key used by this keyring to decrypt data keys.
     * @param wrappingAlgorithm The RSA algorithm to use with this keyring.
     * @return The {@link Keyring}
     */
    public static Keyring rawRsa(String keyNamespace, String keyName, PublicKey publicKey, PrivateKey privateKey, String wrappingAlgorithm) {
        return new RawRsaKeyring(keyNamespace, keyName, publicKey, privateKey, wrappingAlgorithm);
    }

    /**
     * Constructs a {@code Keyring} which interacts with AWS Key Management Service (KMS) to create,
     * encrypt, and decrypt data keys using KMS defined Customer Master Keys (CMKs).
     *
     * @param clientSupplier    A function that returns a KMS client that can make GenerateDataKey,
     *                          Encrypt, and Decrypt calls in a particular AWS region.
     * @param grantTokens       A list of string grant tokens to be included in all KMS calls.
     * @param keyIds            A list of strings identifying KMS CMKs, in ARN, CMK Alias, or ARN Alias format.
     * @param generator         A string that identifies a KMS CMK responsible for generating a data key,
     *                          as well as encrypting and decrypting data keys in ARN, CMK Alias, or ARN Alias format.
     * @return The {@code Keyring}
     */
    public static Keyring kms(KmsClientSupplier clientSupplier, List<String> grantTokens, List<String> keyIds, String generator) {
        return new KmsKeyring(DataKeyEncryptionDao.kms(clientSupplier, grantTokens), keyIds, generator);
    }

    /**
     * Constructs a {@code Keyring} which combines other keyrings, allowing one OnEncrypt or OnDecrypt call
     * to modify the encryption or decryption materials using more than one keyring.
     *
     * @param generatorKeyring A keyring that can generate data keys. Required if childrenKeyrings is empty.
     * @param childrenKeyrings A list of keyrings to be used to modify the encryption or decryption materials.
     *                         At least one is required if generatorKeyring is null.
     * @return The {@link Keyring}
     */
    public static Keyring multi(Keyring generatorKeyring, List<Keyring> childrenKeyrings) {
        return new MultiKeyring(generatorKeyring, childrenKeyrings);
    }

    /**
     * Constructs a {@code Keyring} which combines other keyrings, allowing one OnEncrypt or OnDecrypt call
     * to modify the encryption or decryption materials using more than one keyring.
     *
     * @param generatorKeyring A keyring that can generate data keys. Required if childrenKeyrings is empty.
     * @param childrenKeyrings Keyrings to be used to modify the encryption or decryption materials.
     *                         At least one is required if generatorKeyring is null.
     * @return The {@link Keyring}
     */
    public static Keyring multi(Keyring generatorKeyring, Keyring... childrenKeyrings) {
        return new MultiKeyring(generatorKeyring, Arrays.asList(childrenKeyrings));
    }
}
