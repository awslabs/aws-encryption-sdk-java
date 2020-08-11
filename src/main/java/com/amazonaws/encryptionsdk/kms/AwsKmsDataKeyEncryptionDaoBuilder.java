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

package com.amazonaws.encryptionsdk.kms;

import com.amazonaws.ClientConfiguration;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.services.kms.AWSKMSClientBuilder;

import java.util.List;

/**
 * Builder to construct an AwsKmsDataKeyEncryptionDao.
 * CredentialProvider and ClientConfiguration are optional
 * and may be configured if necessary.
 */
public class AwsKmsDataKeyEncryptionDaoBuilder {

    private AWSKMSClientBuilder awsKmsClientBuilder;
    private AWSCredentialsProvider credentialsProvider;
    private ClientConfiguration clientConfiguration;
    private List<String> grantTokens;
    private String regionId;

    // The user agent string is used to note the AWS Encryption SDK's language and version in calls to AWS KMS
    // Since the AWS KMS client is being constructed the AWS Encryption SDK, we can append this value
    // unless a custom client configuration was provided
    private boolean canAppendUserAgentString = true;

    /**
     * A builder to construct the default AwsKmsDataKeyEncryptionDaoBuilder that will create clients
     * for an AWS region. Credentials, client configuration, and grant tokens may be specified if necessary.
     *
     * @return The AwsKmsDataKeyEncryptionDaoBuilder
     */
    public static AwsKmsDataKeyEncryptionDaoBuilder defaultBuilder() {
        return new AwsKmsDataKeyEncryptionDaoBuilder(AWSKMSClientBuilder.standard());
    }

    AwsKmsDataKeyEncryptionDaoBuilder(AWSKMSClientBuilder awsKmsClientBuilder) {
        this.awsKmsClientBuilder = awsKmsClientBuilder;
    }

    public AwsKmsDataKeyEncryptionDao build() {
        if (credentialsProvider != null) {
            awsKmsClientBuilder = awsKmsClientBuilder.withCredentials(credentialsProvider);
        }

        if (clientConfiguration != null) {
            awsKmsClientBuilder = awsKmsClientBuilder.withClientConfiguration(clientConfiguration);
        }

        if (regionId != null) {
            awsKmsClientBuilder = awsKmsClientBuilder.withRegion(regionId);
        }

        return new AwsKmsDataKeyEncryptionDao(awsKmsClientBuilder.build(), grantTokens, canAppendUserAgentString);
    }

    /**
     * Sets a list of string grant tokens to be included in all AWS KMS calls.
     *
     * @param grantTokens The list of grant tokens.
     * @return The AwsKmsDataKeyEncryptionDaoBuilder, for method chaining
     */
    public AwsKmsDataKeyEncryptionDaoBuilder grantTokens(List<String> grantTokens) {
        this.grantTokens = grantTokens;
        return this;
    }

    /**
     * Sets a non-null AWSCredentialsProvider to be used by the client.
     *
     * @param credentialsProvider New AWSCredentialsProvider to use.
     * @return The AwsKmsDataKeyEncryptionDaoBuilder, for method chaining
     */
    public AwsKmsDataKeyEncryptionDaoBuilder credentialsProvider(AWSCredentialsProvider credentialsProvider) {
        if (credentialsProvider != null) {
            this.credentialsProvider = credentialsProvider;
        }
        return this;
    }

    /**
     * Sets a non-null ClientConfiguration to be used by the client.
     *
     * @param clientConfiguration Custom configuration to use.
     * @return The AwsKmsDataKeyEncryptionDaoBuilder, for method chaining
     */
    public AwsKmsDataKeyEncryptionDaoBuilder clientConfiguration(ClientConfiguration clientConfiguration) {
        if (clientConfiguration != null) {
            this.clientConfiguration = clientConfiguration;
            // If a client configuration is provided, we must not modify the user agent string
            this.canAppendUserAgentString = false;
        }
        return this;
    }

    /**
     * Sets a non-null AWS region string to be used by the client.
     *
     * @param regionId AWS region for the client.
     * @return The AwsKmsDataKeyEncryptionDaoBuilder, for method chaining
     */
    public AwsKmsDataKeyEncryptionDaoBuilder regionId(String regionId) {
        if (regionId != null) {
            this.regionId = regionId;
        }
        return this;
    }
}
