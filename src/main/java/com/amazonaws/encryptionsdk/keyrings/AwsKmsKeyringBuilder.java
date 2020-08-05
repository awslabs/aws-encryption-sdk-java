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
import com.amazonaws.encryptionsdk.kms.AwsKmsCmkId;
import com.amazonaws.encryptionsdk.kms.DataKeyEncryptionDao;
import com.amazonaws.encryptionsdk.kms.StandardAwsKmsClientSuppliers;

import java.util.List;

public class AwsKmsKeyringBuilder {
    private AwsKmsClientSupplier awsKmsClientSupplier;
    private List<String> grantTokens;
    private List<AwsKmsCmkId> keyIds;
    private AwsKmsCmkId generatorKeyId;
    private final boolean isDiscovery;

    private AwsKmsKeyringBuilder(boolean isDiscovery) {
        // Use AwsKmsKeyringBuilder.standard() or StandardKeyrings.awsKmsBuilder() to instantiate
        // a standard Aws Kms Keyring builder. If an Aws Kms Discovery Keyring builder is needed use
        // AwsKmsKeyringBuilder.discovery() or StandardKeyrings.awsKmsDiscoveryBuilder().
        this.isDiscovery = isDiscovery;
    }

    /**
     * Constructs a new instance of {@code AwsKmsKeyringBuilder}
     *
     * @return The {@code AwsKmsKeyringBuilder}
     */
    public static AwsKmsKeyringBuilder standard() {
        return new AwsKmsKeyringBuilder(false);
    }

    /**
     * Constructs a new instance of {@code AwsKmsKeyringBuilder} that produces an AWS KMS Discovery keyring.
     * AWS KMS Discovery keyrings do not specify any CMKs to decrypt with, and thus will attempt to decrypt
     * using any encrypted data key in an encrypted message. AWS KMS Discovery keyrings do not perform encryption.
     *
     * @return The {@code AwsKmsKeyringBuilder}
     */
    public static AwsKmsKeyringBuilder discovery() {
        return new AwsKmsKeyringBuilder(true);
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
     * A list of {@link AwsKmsCmkId}s in ARN, CMK Alias, or ARN Alias format identifying AWS KMS CMKs
     * used for encrypting and decrypting data keys.
     *
     * @param keyIds The list of AWS KMS CMKs
     * @return The AwsKmsKeyringBuilder, for method chaining
     */
    public AwsKmsKeyringBuilder keyIds(List<AwsKmsCmkId> keyIds) {
        this.keyIds = keyIds;
        return this;
    }

    /**
     * An {@link AwsKmsCmkId} in ARN, CMK Alias, or ARN Alias format that identifies a
     * AWS KMS CMK responsible for generating a data key, as well as encrypting and
     * decrypting data keys .
     *
     * @param generatorKeyId An {@link AwsKmsCmkId} in ARN, CMK Alias, or ARN Alias format that identifies a
     *                       AWS KMS CMK responsible for generating a data key, as well as encrypting and
     *                       decrypting data keys.
     * @return The AwsKmsKeyringBuilder, for method chaining
     */
    public AwsKmsKeyringBuilder generatorKeyId(AwsKmsCmkId generatorKeyId) {
        this.generatorKeyId = generatorKeyId;
        return this;
    }

    /**
     * Constructs the {@link Keyring} instance.
     *
     * @return The {@link Keyring} instance
     */
    public Keyring build() {
        if (awsKmsClientSupplier == null) {
            awsKmsClientSupplier = StandardAwsKmsClientSuppliers.defaultBuilder().build();
        }

        return new AwsKmsKeyring(DataKeyEncryptionDao.awsKms(awsKmsClientSupplier, grantTokens),
                keyIds, generatorKeyId, isDiscovery);
    }

}
