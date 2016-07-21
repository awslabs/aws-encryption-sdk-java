package com.amazonaws.encryptionsdk.kms;

import com.amazonaws.ClientConfiguration;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.regions.Region;
import com.amazonaws.regions.RegionUtils;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.kms.AWSKMSClient;
import com.amazonaws.services.kms.AWSKMSClientBuilder;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Used to build a {@link KmsMasterKeyProvider} using {@link AWSKMSClientBuilder}, which will use provider chains to get
 * defaults if the properties are not explicitly set.
 *
 * Default usage will use all the defaults found by AWSKMSClientBuilder. If a region is not found in the configuration
 * chain, then {@link Regions#DEFAULT_REGION} is used.
 * <pre>
 *     KmsMasterKeyProvider keyProvider = KmsMasterKeyProviderBuilder.defaultProvider();
 * </pre>
 *
 * Example, specifying a region:
 * <pre>
 *     KmsMasterKeyProvider keyProvider = KmsMasterKeyProviderBuilder.standard()
 *       .withRegion("us-east-1")
 *       .build();
 * </pre>
 */
public class KmsMasterKeyProviderBuilder {

    private AWSKMSClientBuilder clientBuilder;
    private List<String> keyIds;

    /**
     * @return a new {@link KmsMasterKeyProviderBuilder} with the defaults set.
     */
    public static KmsMasterKeyProviderBuilder standard() {
        return new KmsMasterKeyProviderBuilder();
    }

    /**
     * @return a KmsMasterKeyProvider using the {@link AWSKMSClientBuilder} defaults, and an empty key ID list.
     */
    public static KmsMasterKeyProvider defaultProvider() {
        return standard().build();
    }

    private KmsMasterKeyProviderBuilder() {
        clientBuilder = AWSKMSClientBuilder.standard();
    }

    /**
     * Sets the region to be used by the client. Overrides any previously set region.
     */
    public KmsMasterKeyProviderBuilder withRegion(Region region) {
        return withRegion(region.getName());
    }

    /**
     * Sets the region to be used by the client. Overrides any previously set region.
     */
    public KmsMasterKeyProviderBuilder withRegion(String regionName) {
        clientBuilder.withRegion(regionName);
        return this;
    }

    /**
     * Sets the client configuration to use.
     */
    public KmsMasterKeyProviderBuilder withClientConfiguration(ClientConfiguration clientConfiguration) {
        clientBuilder.withClientConfiguration(clientConfiguration);
        return this;
    }

    /**
     * Sets the credentials to use.
     */
    public KmsMasterKeyProviderBuilder withCredentials(AWSCredentialsProvider credentialsProvider) {
        clientBuilder.withCredentials(credentialsProvider);
        return this;
    }

    /**
     * Sets the region using a keyId. This will override any previously set regions.
     */
    public KmsMasterKeyProviderBuilder withKeyId(String keyId) {
        withKeyIds(Collections.singletonList(keyId));

        withRegion(KmsMasterKeyProvider.getStartingRegion(keyId));

        return this;
    }

    /**
     * Adds {@code keyIds}, but does not use them to set the region.
     */
    public KmsMasterKeyProviderBuilder withKeyIds(List<String> keyIds) {
        if (this.keyIds == null) {
            this.keyIds = new ArrayList<>();
        }

        this.keyIds.addAll(keyIds);

        return this;
    }

    /**
     * Builds the {@link KmsMasterKeyProvider} using the information it was built with or {@link AWSKMSClientBuilder}'s
     * defaults.
     */
    public KmsMasterKeyProvider build() {
        keyIds = (keyIds == null) ? Collections.emptyList() : keyIds;

        String clientBuilderRegion = clientBuilder.getRegion();

        String regionName = (clientBuilderRegion == null) ? Regions.DEFAULT_REGION.getName()
                : clientBuilderRegion;

        clientBuilder = clientBuilder.withRegion(regionName);

        return new KmsMasterKeyProvider((AWSKMSClient) clientBuilder.build(),
                RegionUtils.getRegion(regionName),
                keyIds);
    }
}
