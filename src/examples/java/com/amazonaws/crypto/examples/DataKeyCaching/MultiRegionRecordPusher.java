/*
 * Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
package com.amazonaws.crypto.examples.kinesisdatakeycaching;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import com.amazonaws.ClientConfiguration;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoResult;
import com.amazonaws.encryptionsdk.MasterKeyProvider;
import com.amazonaws.encryptionsdk.caching.CachingCryptoMaterialsManager;
import com.amazonaws.encryptionsdk.caching.LocalCryptoMaterialsCache;
import com.amazonaws.encryptionsdk.kms.KmsMasterKey;
import com.amazonaws.encryptionsdk.kms.KmsMasterKeyProvider;
import com.amazonaws.encryptionsdk.multi.MultipleProviderFactory;
import com.amazonaws.regions.Region;
import com.amazonaws.services.kinesis.AmazonKinesis;
import com.amazonaws.services.kinesis.AmazonKinesisClientBuilder;
import com.amazonaws.util.json.Jackson;

/**
 * Pushes data to Kinesis Streams in multiple regions.
 */
public class MultiRegionRecordPusher {
    private static long MAX_ENTRY_AGE_MILLISECONDS = 300000;
    private static long MAX_ENTRY_USES = 100;
    private static int MAX_CACHE_ENTRIES = 100;
    private final String streamName_;
    private ArrayList<AmazonKinesis> kinesisClients_;
    private CachingCryptoMaterialsManager cachingMaterialsManager_;
    private AwsCrypto crypto_;

    /**
     * Creates an instance of this object with Kinesis clients for all target regions
     * and a cached key provider containing KMS master keys in all target regions.
     */
    public MultiRegionRecordPusher(final Region[] regions, final String kmsAliasName, final String streamName){
        streamName_ = streamName;
        crypto_ = new AwsCrypto();
        kinesisClients_ = new ArrayList<AmazonKinesis>();

        DefaultAWSCredentialsProviderChain credentialsProvider = new DefaultAWSCredentialsProviderChain();
        ClientConfiguration clientConfig = new ClientConfiguration();

        // Build KmsMasterKey and AmazonKinesisClient objects for each target region
        List<KmsMasterKey> masterKeys = new ArrayList<KmsMasterKey>();
        for (Region region : regions) {
            kinesisClients_.add(AmazonKinesisClientBuilder.standard()
                    .withCredentials(credentialsProvider)
                    .withRegion(region.getName())
                    .build());

            KmsMasterKey regionMasterKey = new KmsMasterKeyProvider(
                credentialsProvider,
                region,
                clientConfig,
                kmsAliasName
            ).getMasterKey(kmsAliasName);

            masterKeys.add(regionMasterKey);
        }

        // Collect KmsMasterKey objects into single provider and add cache
        MasterKeyProvider<?> masterKeyProvider = MultipleProviderFactory.buildMultiProvider(
                KmsMasterKey.class,
                masterKeys
        );

        cachingMaterialsManager_ = CachingCryptoMaterialsManager.newBuilder()
            .withMasterKeyProvider(masterKeyProvider)
            .withCache(new LocalCryptoMaterialsCache(MAX_CACHE_ENTRIES))
            .withMaxAge(MAX_ENTRY_AGE_MILLISECONDS, TimeUnit.MILLISECONDS)
            .withMessageUseLimit(MAX_ENTRY_USES)
            .build();
    }

    /**
     * JSON serializes and encrypts the received record data and pushes it to all target streams.
     */
    public void putRecord(final Map<Object, Object> data){
        String partitionKey = UUID.randomUUID().toString();
        Map<String, String> encryptionContext = new HashMap<String, String>();
        encryptionContext.put("stream", streamName_);

        // JSON serialize data
        String jsonData = Jackson.toJsonString(data);

        // Encrypt data
        CryptoResult<byte[], ?> result = crypto_.encryptData(
            cachingMaterialsManager_,
            jsonData.getBytes(),
            encryptionContext
        );
        byte[] encryptedData = result.getResult();

        // Put records to Kinesis stream in all regions
        for (AmazonKinesis regionalKinesisClient : kinesisClients_) {
            regionalKinesisClient.putRecord(
                streamName_,
                ByteBuffer.wrap(encryptedData),
                partitionKey
            );
        }
    }
}