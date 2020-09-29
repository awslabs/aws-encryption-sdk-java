// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk.keyrings;

import com.amazonaws.ClientConfiguration;
import com.amazonaws.arn.Arn;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.encryptionsdk.kms.AwsKmsCmkId;
import com.amazonaws.encryptionsdk.kms.AwsKmsDataKeyEncryptionDaoBuilder;
import com.amazonaws.encryptionsdk.kms.DataKeyEncryptionDao;
import org.apache.commons.lang3.StringUtils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class AwsKmsSymmetricMultiCmkKeyringBuilder {

    private static final String NULL_REGION = "null-region";

    private List<AwsKmsCmkId> childKeyNames;
    private AwsKmsCmkId generatorKeyName;
    private List<String> grantTokens;
    private AWSCredentialsProvider credentialsProvider;
    private ClientConfiguration clientConfiguration;

    private AwsKmsDataKeyEncryptionDaoBuilder daoBuilder;

    AwsKmsSymmetricMultiCmkKeyringBuilder(AwsKmsDataKeyEncryptionDaoBuilder daoBuilder) {
        // Use AwsKmsSymmetricMultiCmkKeyringBuilder.standard() or StandardKeyrings.awsKmsSymmetricMultiCmkBuilder()
        // to instantiate a standard AWS KMS symmetric multi-CMK keyring Builder.
        // If an AWS KMS symmetric multi-region discovery keyring builder is needed use
        // AwsKmsSymmetricMultiRegionDiscoveryKeyringBuilder.standard() or
        // StandardKeyrings.awsKmsSymmetricMultiRegionDiscoveryKeyringBuilder().
        this.daoBuilder = daoBuilder;
    }

    /**
     * Constructs a new instance of {@code AwsKmsSymmetricMultiCmkKeyringBuilder}
     *
     * @return The {@code AwsKmsSymmetricMultiCmkKeyringBuilder}
     */
    public static AwsKmsSymmetricMultiCmkKeyringBuilder standard() {
        return new AwsKmsSymmetricMultiCmkKeyringBuilder(AwsKmsDataKeyEncryptionDaoBuilder.defaultBuilder());
    }

    /**
     * An optional AWSCredentialsProvider for use with every AWS SDK KMS service client.
     *
     * @param credentialsProvider Custom AWSCredentialsProvider to use.
     * @return The AwsKmsSymmetricMultiCmkKeyringBuilder, for method chaining
     */
    public AwsKmsSymmetricMultiCmkKeyringBuilder credentialsProvider(AWSCredentialsProvider credentialsProvider) {
        this.credentialsProvider = credentialsProvider;
        return this;
    }

    /**
     * An optional ClientConfiguration for use with every AWS SDK KMS service client.
     *
     * @param clientConfiguration Custom ClientConfiguration to use.
     * @return The AwsKmsSymmetricMultiCmkKeyringBuilder, for method chaining
     */
    public AwsKmsSymmetricMultiCmkKeyringBuilder clientConfiguration(ClientConfiguration clientConfiguration) {
        this.clientConfiguration = clientConfiguration;
        return this;
    }

    /**
     * A list of string grant tokens to be included in all KMS calls.
     *
     * @param grantTokens The list of grant tokens.
     * @return The AwsKmsSymmetricMultiCmkKeyringBuilder, for method chaining
     */
    public AwsKmsSymmetricMultiCmkKeyringBuilder grantTokens(List<String> grantTokens) {
        this.grantTokens = grantTokens;
        return this;
    }

    /**
     * A list of {@link AwsKmsCmkId}s in ARN, CMK Alias, or ARN Alias format identifying AWS KMS CMKs
     * used for encrypting and decrypting data keys.
     *
     * @param childKeyNames The list of key names identifying AWS KMS CMKs.
     * @return The AwsKmsSymmetricMultiCmkKeyringBuilder, for method chaining
     */
    public AwsKmsSymmetricMultiCmkKeyringBuilder keyNames(List<AwsKmsCmkId> childKeyNames) {
        this.childKeyNames = childKeyNames;
        return this;
    }

    /**
     * An {@link AwsKmsCmkId} in ARN, CMK Alias, or ARN Alias format that identifies a
     * AWS KMS CMK responsible for generating a data key, as well as encrypting and
     * decrypting data keys.
     *
     * @param generatorKeyName An {@link AwsKmsCmkId} in ARN, CMK Alias, or ARN Alias format that identifies a
     *                         AWS KMS CMK responsible for generating a data key, as well as encrypting and
     *                         decrypting data keys.
     * @return The AwsKmsSymmetricMultiCmkKeyringBuilder, for method chaining
     */
    public AwsKmsSymmetricMultiCmkKeyringBuilder generator(AwsKmsCmkId generatorKeyName) {
        this.generatorKeyName = generatorKeyName;
        return this;
    }

    /**
     * Constructs the {@code MultiKeyring} of {@code AwsKmsSymmetricKeyring}s.
     *
     * @return The {@link MultiKeyring} instance
     */
    public MultiKeyring build() {
        // A mapping of AWS region to DataKeyEncryptionDao
        final Map<String, DataKeyEncryptionDao> clientMapping = new HashMap<>();

        // First construct the generator keyring
        Keyring generatorKeyring = null;
        if (this.generatorKeyName != null) {
            // If we have an ARN, obtain the region from the ARN
            // to specify the region of the AWS SDK KMS service client
            final Optional<Arn> generatorArn = AwsKmsCmkId.getArnFromKeyName(this.generatorKeyName.toString());
            final String generatorRegion = generatorArn.isPresent() ? generatorArn.get().getRegion() : null;
            final DataKeyEncryptionDao generatorDao = constructDataKeyEncryptionDao(generatorRegion);

            // Add the client to the mapping with the region key
            // This prevents re-creating multiple clients for the same region during a single build call
            final String generatorRegionKey = StringUtils.isBlank(generatorRegion) ? NULL_REGION : generatorRegion;
            clientMapping.put(generatorRegionKey, generatorDao);

            // Construct the generator keyring
            generatorKeyring = new AwsKmsSymmetricKeyring(generatorDao, this.generatorKeyName);
        }

        // Next, construct the child (non-generator) keyrings
        List<Keyring> childKeyrings = new ArrayList<>();
        if (this.childKeyNames != null) {
            for (final AwsKmsCmkId keyName : this.childKeyNames) {
                if (keyName == null) {
                    throw new IllegalArgumentException("AwsKmsSymmetricMultiCmkKeyringBuilder provided a null AwsKmsCmkId");
                }

                // If we have an ARN, obtain the region from the ARN (to specify the region of the AWS SDK KMS service client)
                final Optional<Arn> childArn = AwsKmsCmkId.getArnFromKeyName(keyName.toString());
                final String childRegion = childArn.isPresent() ? childArn.get().getRegion() : null;
                final String childKey = StringUtils.isBlank(childRegion) ? NULL_REGION : childRegion;

                // Check if a dao already exists for the given region
                // and use the existing dao or construct a new one and save it
                final boolean daoExists = clientMapping.containsKey(childKey);
                final DataKeyEncryptionDao childDao = daoExists ? clientMapping.get(childKey) : constructDataKeyEncryptionDao(childRegion);
                if (!daoExists) {
                    clientMapping.put(childKey, childDao);
                }
                final Keyring childKeyring = new AwsKmsSymmetricKeyring(childDao, keyName);
                childKeyrings.add(childKeyring);
            }
        }

        // Finally, construct a multi-keyring
        return new MultiKeyring(generatorKeyring, childKeyrings);
    }

    private DataKeyEncryptionDao constructDataKeyEncryptionDao(String regionId) {
        return this.daoBuilder
            .clientConfiguration(this.clientConfiguration)
            .credentialsProvider(this.credentialsProvider)
            .grantTokens(this.grantTokens)
            .regionId(regionId)
            .build();
    }
}
