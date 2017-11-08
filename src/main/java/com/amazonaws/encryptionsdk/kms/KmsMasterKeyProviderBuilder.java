package com.amazonaws.encryptionsdk.kms;

import com.amazonaws.ClientConfigurationFactory;
import com.amazonaws.client.AwsSyncClientParams;
import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.regions.AwsRegionProvider;
import com.amazonaws.regions.DefaultAwsRegionProviderChain;
import com.amazonaws.regions.Region;
import com.amazonaws.regions.RegionUtils;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.kms.AWSKMSClient;
import com.amazonaws.services.kms.AWSKMSClientBuilder;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Used to build a {@link KmsMasterKeyProvider} which will use the defaults found in the relevant provider chains.
 *
 * If a region is not defined and no region can be found in the region provider chain, then
 * {@link Regions#DEFAULT_REGION} is used.
 * <pre>
 *     KmsMasterKeyProvider keyProvider = KmsMasterKeyProviderBuilder.defaultProvider();
 * </pre>
 *
 * Example, specifying a region:
 * <pre>
 *     KmsMasterKeyProvider keyProvider = KmsMasterKeyProviderBuilder.standard()
 *       .withDefaultRegion("us-east-1")
 *       .build();
 * </pre>
 */
public class KmsMasterKeyProviderBuilder extends AwsClientBuilder<KmsMasterKeyProviderBuilder, KmsMasterKeyProvider> {

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
        super(new ClientConfigurationFactory());
    }

    /**
     * Sets the default region to be used by the client. Overrides any previously set region.
     */
    public KmsMasterKeyProviderBuilder withDefaultRegion(Region region) {
        return withRegion(region.getName());
    }

    /**
     * Sets the region using a keyId. This will override any previously set regions.
     */
    public KmsMasterKeyProviderBuilder withKeyId(String keyId) {
        withKeyIds(Collections.singletonList(keyId));

        withDefaultRegion(KmsMasterKeyProvider.getStartingRegion(keyId));

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
     * Builds a {@link KmsMasterKeyProvider} using the information it was built with, or with defaults where necessary.
     */
    @Override
    public KmsMasterKeyProvider build() {
        return build(getSyncClientParams());
    }

    private KmsMasterKeyProvider build(AwsSyncClientParams clientParams) {
        keyIds = (keyIds == null) ? Collections.emptyList() : keyIds;

        AWSKMSClient client = new AWSKMSClient(clientParams.getCredentialsProvider(),
                clientParams.getClientConfiguration(),
                clientParams.getRequestMetricCollector());

        Region region = determineRegion();

        return new KmsMasterKeyProvider(client,
                region,
                keyIds);
    }

    private Region determineRegion() {
        Region region = RegionUtils.getRegion(this.getRegion());

        final AwsRegionProvider regionProvider = new DefaultAwsRegionProviderChain();

        if (region != null) {
            return region;
        } else {
            final String regionName = regionProvider.getRegion();
            if (regionName != null) {
                return Region.getRegion(Regions.fromName(regionName));
            } else {
                return Region.getRegion(Regions.DEFAULT_REGION);
            }
        }
    }
}
