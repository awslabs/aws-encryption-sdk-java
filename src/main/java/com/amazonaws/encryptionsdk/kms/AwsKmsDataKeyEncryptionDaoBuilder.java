// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk.kms;

import com.amazonaws.ClientConfiguration;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import org.apache.commons.lang3.StringUtils;

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
            canAppendUserAgentString = false;
            awsKmsClientBuilder = awsKmsClientBuilder.withClientConfiguration(clientConfiguration);
        }

        if (StringUtils.isNotBlank(regionId)) {
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
     * Sets an AWSCredentialsProvider to be used by the client.
     *
     * @param credentialsProvider Custom AWSCredentialsProvider to use.
     * @return The AwsKmsDataKeyEncryptionDaoBuilder, for method chaining
     */
    public AwsKmsDataKeyEncryptionDaoBuilder credentialsProvider(AWSCredentialsProvider credentialsProvider) {
        this.credentialsProvider = credentialsProvider;
        return this;
    }

    /**
     * Sets a ClientConfiguration to be used by the client.
     *
     * @param clientConfiguration Custom configuration to use.
     * @return The AwsKmsDataKeyEncryptionDaoBuilder, for method chaining
     */
    public AwsKmsDataKeyEncryptionDaoBuilder clientConfiguration(ClientConfiguration clientConfiguration) {
        this.clientConfiguration = clientConfiguration;
        return this;
    }

    /**
     * Sets an AWS region string to be used by the client.
     *
     * @param regionId AWS region for the client.
     * @return The AwsKmsDataKeyEncryptionDaoBuilder, for method chaining
     */
    public AwsKmsDataKeyEncryptionDaoBuilder regionId(String regionId) {
        this.regionId = regionId;
        return this;
    }
}
