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

import com.amazonaws.ClientConfiguration;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.encryptionsdk.kms.AwsKmsDataKeyEncryptionDaoBuilder;
import com.amazonaws.encryptionsdk.kms.DataKeyEncryptionDao;
import org.apache.commons.lang3.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class AwsKmsSymmetricMultiRegionDiscoveryKeyringBuilder {

    private List<String> regionIds;
    private String awsAccountId;
    private List<String> grantTokens;
    private AWSCredentialsProvider credentialsProvider;
    private ClientConfiguration clientConfiguration;

    private AwsKmsSymmetricMultiRegionDiscoveryKeyringBuilder() {
        // Use AwsKmsSymmetricMultiRegionDiscoveryKeyringBuilder.standard()
        // or StandardKeyrings.awsKmsSymmetricMultiRegionDiscoveryKeyringBuilder()
        // to instantiate a standard AWS KMS symmetric multi-region discovery keyring Builder.
        // If an AWS KMS symmetric multi-CMK keyring builder is needed use
        // AwsKmsSymmetricMultiCmkKeyringBuilder.standard() or
        // StandardKeyrings.awsKmsSymmetricMultiCmkBuilder().
    }

    /**
     * Constructs a new instance of {@code AwsKmsSymmetricMultiRegionDiscoveryKeyringBuilder}
     *
     * @return The {@code AwsKmsSymmetricMultiRegionDiscoveryKeyringBuilder}
     */
    public static AwsKmsSymmetricMultiRegionDiscoveryKeyringBuilder standard() {
        return new AwsKmsSymmetricMultiRegionDiscoveryKeyringBuilder();
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
     * Constructs the {@link Keyring} instance.
     *
     * @return The {@link Keyring} instance
     */
    public Keyring build() {
        // A mapping of AWS region to DataKeyEncryptionDao
        final Map<String, DataKeyEncryptionDao> clientMapping = new ConcurrentHashMap<>();

        // Construct each AwsKmsSymmetricRegionDiscoveryKeyring
        List<Keyring> discoveryKeyrings = new ArrayList<>();
        if (this.regionIds != null) {
            for (final String region : this.regionIds) {
                if (StringUtils.isBlank(region)) {
                    continue;
                }

                // Check if a client already exists for the given region
                // and use the existing dao or construct a new one
                if (clientMapping.containsKey(region)) {
                    final Keyring discoveryKeyring = new AwsKmsSymmetricRegionDiscoveryKeyring(clientMapping.get(region), region, this.awsAccountId);
                    discoveryKeyrings.add(discoveryKeyring);
                } else {
                    final DataKeyEncryptionDao discoveryDao = constructDataKeyEncryptionDao(region);
                    clientMapping.put(region, discoveryDao);
                    final Keyring discoveryKeyring = new AwsKmsSymmetricRegionDiscoveryKeyring(discoveryDao, region, this.awsAccountId);
                    discoveryKeyrings.add(discoveryKeyring);
                }
            }
        }

        // Finally, construct a multi-keyring
        return new MultiKeyring(null, discoveryKeyrings);
    }

    private DataKeyEncryptionDao constructDataKeyEncryptionDao(String regionId) {
        return AwsKmsDataKeyEncryptionDaoBuilder
            .defaultBuilder()
            .clientConfiguration(clientConfiguration)
            .credentialsProvider(credentialsProvider)
            .grantTokens(grantTokens)
            .regionId(regionId)
            .build();
    }
}
