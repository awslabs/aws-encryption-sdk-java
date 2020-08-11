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

package com.amazonaws.encryptionsdk.kms;

import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.EncryptedDataKey;

import javax.crypto.SecretKey;
import java.util.Map;

public interface DataKeyEncryptionDao {

    /**
     * Generates a unique data key, returning both the plaintext copy of the key and an encrypted copy encrypted using
     * the customer master key specified by the given keyId.
     *
     * @param keyId             The customer master key to encrypt the generated key with.
     * @param algorithmSuite    The algorithm suite associated with the key.
     * @param encryptionContext The encryption context.
     * @return GenerateDataKeyResult containing the plaintext data key and the encrypted data key.
     */
    GenerateDataKeyResult generateDataKey(AwsKmsCmkId keyId, CryptoAlgorithm algorithmSuite, Map<String, String> encryptionContext);

    /**
     * Encrypts the given plaintext data key using the customer aster key specified by the given keyId.
     *
     * @param keyId             The customer master key to encrypt the plaintext data key with.
     * @param plaintextDataKey  The plaintext data key to encrypt.
     * @param encryptionContext The encryption context.
     * @return The encrypted data key.
     */
    EncryptedDataKey encryptDataKey(final AwsKmsCmkId keyId, SecretKey plaintextDataKey, Map<String, String> encryptionContext);

    /**
     * Decrypted the given encrypted data key.
     *
     * @param encryptedDataKey  The encrypted data key to decrypt.
     * @param algorithmSuite    The algorithm suite associated with the key.
     * @param encryptionContext The encryption context.
     * @return DecryptDataKeyResult containing the plaintext data key and the ARN of the key that decrypted it.
     */
    DecryptDataKeyResult decryptDataKey(EncryptedDataKey encryptedDataKey, CryptoAlgorithm algorithmSuite, Map<String, String> encryptionContext);

    class GenerateDataKeyResult {
        private final SecretKey plaintextDataKey;
        private final EncryptedDataKey encryptedDataKey;

        public GenerateDataKeyResult(SecretKey plaintextDataKey, EncryptedDataKey encryptedDataKey) {
            this.plaintextDataKey = plaintextDataKey;
            this.encryptedDataKey = encryptedDataKey;
        }

        public SecretKey getPlaintextDataKey() {
            return plaintextDataKey;
        }

        public EncryptedDataKey getEncryptedDataKey() {
            return encryptedDataKey;
        }
    }

    class DecryptDataKeyResult {
        private final String keyArn;
        private final SecretKey plaintextDataKey;

        public DecryptDataKeyResult(String keyArn, SecretKey plaintextDataKey) {
            this.keyArn = keyArn;
            this.plaintextDataKey = plaintextDataKey;
        }

        public String getKeyArn() {
            return keyArn;
        }

        public SecretKey getPlaintextDataKey() {
            return plaintextDataKey;
        }

    }
}
