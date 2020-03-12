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

package com.amazonaws.crypto.examples.datakeycaching;

import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.AwsCryptoResult;
import com.amazonaws.encryptionsdk.EncryptRequest;
import com.amazonaws.encryptionsdk.caching.CachingCryptoMaterialsManager;
import com.amazonaws.encryptionsdk.caching.LocalCryptoMaterialsCache;
import com.amazonaws.encryptionsdk.keyrings.Keyring;
import com.amazonaws.encryptionsdk.keyrings.StandardKeyrings;
import com.amazonaws.encryptionsdk.kms.AwsKmsCmkId;
import com.amazonaws.encryptionsdk.kms.StandardAwsKmsClientSuppliers;
import com.amazonaws.regions.Region;
import com.amazonaws.services.kinesis.AmazonKinesis;
import com.amazonaws.services.kinesis.AmazonKinesisClientBuilder;
import com.amazonaws.util.json.Jackson;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static java.util.Collections.emptyList;

/**
 * Pushes data to Kinesis Streams in multiple Regions.
 */
public class MultiRegionRecordPusherExample {
    private static final long MAX_ENTRY_AGE_MILLISECONDS = 300000;
    private static final long MAX_ENTRY_USES = 100;
    private static final int MAX_CACHE_ENTRIES = 100;
    private final String streamName_;
    private final ArrayList<AmazonKinesis> kinesisClients_;
    private final CachingCryptoMaterialsManager cachingMaterialsManager_;
    private final AwsCrypto crypto_;

    /**
     * Creates an instance of this object with Kinesis clients for all target Regions
     * and a cached key provider containing AWS KMS master keys in all target Regions.
     */
    public MultiRegionRecordPusherExample(final Region[] regions, final String kmsAliasName, final String streamName) {
        streamName_ = streamName;
        crypto_ = new AwsCrypto();
        kinesisClients_ = new ArrayList<>();

        final DefaultAWSCredentialsProviderChain credentialsProvider = new DefaultAWSCredentialsProviderChain();

        // Build AwsKmsKeyring and AmazonKinesisClient objects for each target Region
        final List<Keyring> keyrings = new ArrayList<>();

        for (Region region : regions) {
            kinesisClients_.add(AmazonKinesisClientBuilder.standard()
                    .withCredentials(credentialsProvider)
                    .withRegion(region.getName())
                    .build());

            keyrings.add(StandardKeyrings.awsKmsBuilder()
                    .awsKmsClientSupplier(StandardAwsKmsClientSuppliers
                            .allowRegionsBuilder(Collections.singleton(region.getName()))
                            .baseClientSupplier(StandardAwsKmsClientSuppliers.defaultBuilder()
                                    .credentialsProvider(credentialsProvider).build()).build())
                    .generatorKeyId(AwsKmsCmkId.fromString(kmsAliasName)).build());
        }

        // Collect keyrings into a single multi-keyring and add cache. In this example, the keyring for the
        // first region is used as the generatorKeyring to generate a data key.
        final List<Keyring> childrenKeyrings = keyrings.size() > 1 ? keyrings.subList(1, keyrings.size()) : emptyList();
        final Keyring keyring = StandardKeyrings.multi(keyrings.get(0), childrenKeyrings);

        cachingMaterialsManager_ = CachingCryptoMaterialsManager.newBuilder()
                .withKeyring(keyring)
                .withCache(new LocalCryptoMaterialsCache(MAX_CACHE_ENTRIES))
                .withMaxAge(MAX_ENTRY_AGE_MILLISECONDS, TimeUnit.MILLISECONDS)
                .withMessageUseLimit(MAX_ENTRY_USES)
                .build();
    }

    /**
     * JSON serializes and encrypts the received record data and pushes it to all target streams.
     */
    public void putRecord(final Map<Object, Object> data) {
        String partitionKey = UUID.randomUUID().toString();
        Map<String, String> encryptionContext = Collections.singletonMap("stream", streamName_);

        // JSON serialize data
        String jsonData = Jackson.toJsonString(data);

        // Encrypt data
        AwsCryptoResult<byte[]> result = crypto_.encrypt(
                EncryptRequest.builder()
                        .cryptoMaterialsManager(cachingMaterialsManager_)
                        .plaintext(jsonData.getBytes())
                        .encryptionContext(encryptionContext)
                        .build());

        byte[] encryptedData = result.getResult();

        // Put records to Kinesis stream in all Regions
        for (AmazonKinesis regionalKinesisClient : kinesisClients_) {
            regionalKinesisClient.putRecord(
                    streamName_,
                    ByteBuffer.wrap(encryptedData),
                    partitionKey
            );
        }
    }
}
