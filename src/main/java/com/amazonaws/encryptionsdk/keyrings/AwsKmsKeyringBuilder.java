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

package com.amazonaws.encryptionsdk.keyrings;

import com.amazonaws.encryptionsdk.kms.AwsKmsClientSupplier;
import com.amazonaws.encryptionsdk.kms.DataKeyEncryptionDao;

import java.util.List;

public class AwsKmsKeyringBuilder {
    private AwsKmsClientSupplier awsKmsClientSupplier;
    private List<String> grantTokens;
    private List<String> keyIds;
    private String generatorKeyId;

    AwsKmsKeyringBuilder() {
        // Use StandardKeyrings.awsKms() to instantiate
    }

    /**
     * A function that returns an AWS KMS client that can make GenerateDataKey, Encrypt, and Decrypt calls in
     * a particular AWS region. If this is not supplied, the default AwsKmsClientSupplier will
     * be used. AwsKmsClientSupplier.builder() can be used to construct this type.
     *
     * @param awsKmsClientSupplier The AWS KMS client supplier
     * @return The AwsKmsKeyringBuilder, for method chaining
     */
    public AwsKmsKeyringBuilder awsKmsClientSupplier(AwsKmsClientSupplier awsKmsClientSupplier) {
        this.awsKmsClientSupplier = awsKmsClientSupplier;
        return this;
    }

    /**
     * A list of string grant tokens to be included in all KMS calls.
     *
     * @param grantTokens The list of grant tokens
     * @return The AwsKmsKeyringBuilder, for method chaining
     */
    public AwsKmsKeyringBuilder grantTokens(List<String> grantTokens) {
        this.grantTokens = grantTokens;
        return this;
    }

    /**
     * A list of strings identifying AWS KMS CMKs used for encrypting and decrypting data keys
     * in ARN, CMK Alias, or ARN Alias format.
     *
     * @param keyIds The list of AWS KMS CMKs
     * @return The AwsKmsKeyringBuilder, for method chaining
     */
    public AwsKmsKeyringBuilder keyIds(List<String> keyIds) {
        this.keyIds = keyIds;
        return this;
    }

    /**
     * A string that identifies a AWS KMS CMK responsible for generating a data key,
     * as well as encrypting and decrypting data keys in ARN, CMK Alias, or ARN Alias format.
     *
     * @param generatorKeyId The generator AWS KMS CMK
     * @return The AwsKmsKeyringBuilder, for method chaining
     */
    public AwsKmsKeyringBuilder generatorKeyId(String generatorKeyId) {
        this.generatorKeyId = generatorKeyId;
        return this;
    }

    /**
     * Constructs the {@link Keyring} instance.
     *
     * @return The {@link Keyring} instance
     */
    public Keyring build() {
        if(awsKmsClientSupplier == null) {
            awsKmsClientSupplier = AwsKmsClientSupplier.builder().build();
        }
        return new AwsKmsKeyring(DataKeyEncryptionDao.awsKms(awsKmsClientSupplier, grantTokens), keyIds, generatorKeyId);
    }
}
