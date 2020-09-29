// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk.keyrings;

import com.amazonaws.ClientConfiguration;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.encryptionsdk.kms.AwsKmsDataKeyEncryptionDaoBuilder;
import com.amazonaws.encryptionsdk.kms.DataKeyEncryptionDao;
import org.apache.commons.lang3.StringUtils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class AwsKmsSymmetricMultiRegionDiscoveryKeyringBuilder {

    private List<String> regionIds;
    private String awsAccountId;
    private List<String> grantTokens;
    private AWSCredentialsProvider credentialsProvider;
    private ClientConfiguration clientConfiguration;

    private AwsKmsDataKeyEncryptionDaoBuilder daoBuilder;

    AwsKmsSymmetricMultiRegionDiscoveryKeyringBuilder(AwsKmsDataKeyEncryptionDaoBuilder daoBuilder) {
        // Use AwsKmsSymmetricMultiRegionDiscoveryKeyringBuilder.standard()
        // or StandardKeyrings.awsKmsSymmetricMultiRegionDiscoveryKeyringBuilder()
        // to instantiate a standard AWS KMS symmetric multi-region discovery keyring Builder.
        // If an AWS KMS symmetric multi-CMK keyring builder is needed use
        // AwsKmsSymmetricMultiCmkKeyringBuilder.standard() or
        // StandardKeyrings.awsKmsSymmetricMultiCmkBuilder().
        this.daoBuilder = daoBuilder;
    }

    /**
     * Constructs a new instance of {@code AwsKmsSymmetricMultiRegionDiscoveryKeyringBuilder}
     *
     * @return The {@code AwsKmsSymmetricMultiRegionDiscoveryKeyringBuilder}
     */
    public static AwsKmsSymmetricMultiRegionDiscoveryKeyringBuilder standard() {
        return new AwsKmsSymmetricMultiRegionDiscoveryKeyringBuilder(AwsKmsDataKeyEncryptionDaoBuilder.defaultBuilder());
    }

    /**
     * An optional AWSCredentialsProvider for use with every AWS SDK KMS service client.
     *
     * @param credentialsProvider Custom AWSCredentialsProvider to use.
     * @return The AwsKmsSymmetricMultiRegionDiscoveryKeyringBuilder, for method chaining
     */
    public AwsKmsSymmetricMultiRegionDiscoveryKeyringBuilder credentialsProvider(AWSCredentialsProvider credentialsProvider) {
        this.credentialsProvider = credentialsProvider;
        return this;
    }

    /**
     * An optional ClientConfiguration for use with every AWS SDK KMS service client.
     *
     * @param clientConfiguration Custom ClientConfiguration to use.
     * @return The AwsKmsSymmetricMultiRegionDiscoveryKeyringBuilder, for method chaining
     */
    public AwsKmsSymmetricMultiRegionDiscoveryKeyringBuilder clientConfiguration(ClientConfiguration clientConfiguration) {
        this.clientConfiguration = clientConfiguration;
        return this;
    }

    /**
     * A list of string grant tokens to be included in all KMS calls.
     *
     * @param grantTokens The list of grant tokens.
     * @return The AwsKmsSymmetricMultiRegionDiscoveryKeyringBuilder, for method chaining
     */
    public AwsKmsSymmetricMultiRegionDiscoveryKeyringBuilder grantTokens(List<String> grantTokens) {
        this.grantTokens = grantTokens;
        return this;
    }

    /**
     * A list of AWS regions Ids identifying the AWS regions to attempt decryption in.
     *
     * @param regionIds The list of regions.
     * @return The AwsKmsSymmetricMultiRegionDiscoveryKeyringBuilder, for method chaining
     */
    public AwsKmsSymmetricMultiRegionDiscoveryKeyringBuilder regions(List<String> regionIds) {
        this.regionIds = regionIds;
        return this;
    }

    /**
     * An AWS Account Id to limit decryption to encrypted data keys for a specific AWS account.
     *
     * @param awsAccountId An AWS account id.
     * @return The AwsKmsSymmetricMultiRegionDiscoveryKeyringBuilder, for method chaining
     */
    public AwsKmsSymmetricMultiRegionDiscoveryKeyringBuilder awsAccountId(String awsAccountId) {
        this.awsAccountId = awsAccountId;
        return this;
    }

    /**
     * Constructs the {@code MultiKeyring} of {@code AwsKmsSymmetricRegionDiscoveryKeyring}s.
     *
     * @return The {@link Keyring} instance
     */
    public MultiKeyring build() {
        // A mapping of AWS region to DataKeyEncryptionDao
        final Map<String, DataKeyEncryptionDao> clientMapping = new HashMap<>();

        // Construct each AwsKmsSymmetricRegionDiscoveryKeyring
        List<Keyring> discoveryKeyrings = new ArrayList<>();
        if (this.regionIds == null) {
            throw new IllegalArgumentException("AwsKmsSymmetricMultiRegionDiscoveryKeyringBuilder requires at least one region to build");
        }

        for (final String region : this.regionIds) {
            if (StringUtils.isBlank(region)) {
                throw new IllegalArgumentException("AwsKmsSymmetricMultiRegionDiscoveryKeyringBuilder provided a null or blank region");
            }

            // Check if a dao already exists for the given region
            // and use the existing dao or construct a new one and save it
            final boolean discoveryDaoExists = clientMapping.containsKey(region);
            final DataKeyEncryptionDao discoveryDao = discoveryDaoExists ? clientMapping.get(region) : constructDataKeyEncryptionDao(region);
            if (!discoveryDaoExists) {
                clientMapping.put(region, discoveryDao);
            }

            final Keyring discoveryKeyring = new AwsKmsSymmetricRegionDiscoveryKeyring(discoveryDao, region, this.awsAccountId);
            discoveryKeyrings.add(discoveryKeyring);
        }

        // Finally, construct a multi-keyring
        return new MultiKeyring(null, discoveryKeyrings);
    }

    private DataKeyEncryptionDao constructDataKeyEncryptionDao(String regionId) {
        return this.daoBuilder
            .clientConfiguration(clientConfiguration)
            .credentialsProvider(credentialsProvider)
            .grantTokens(grantTokens)
            .regionId(regionId)
            .build();
    }
}
