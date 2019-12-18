/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
import com.amazonaws.encryptionsdk.exception.UnsupportedRegionException;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.AWSKMSException;

import javax.annotation.Nullable;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static java.util.Objects.requireNonNull;
import static org.apache.commons.lang3.Validate.isTrue;
import static org.apache.commons.lang3.Validate.notEmpty;

/**
 * Represents a function that accepts an AWS region and returns an {@code AWSKMS} client for that region. The
 * function should be able to handle when the region is null.
 */
@FunctionalInterface
public interface KmsClientSupplier {

    /**
     * Gets an {@code AWSKMS} client for the given regionId.
     *
     * @param regionId The AWS region (or null)
     * @return The AWSKMS client
     * @throws UnsupportedRegionException if a regionId is specified that this
     *                                    client supplier is configured to not allow.
     */
    AWSKMS getClient(@Nullable String regionId) throws UnsupportedRegionException;

    /**
     * Gets a Builder for constructing a KmsClientSupplier
     *
     * @return The builder
     */
    static Builder builder() {
        return new Builder(AWSKMSClientBuilder.standard());
    }

    /**
     * Builder to construct a KmsClientSupplier given various
     * optional settings.
     */
    class Builder {

        private AWSCredentialsProvider credentialsProvider;
        private ClientConfiguration clientConfiguration;
        private Set<String> allowedRegions = Collections.emptySet();
        private Set<String> excludedRegions = Collections.emptySet();
        private boolean clientCachingEnabled = false;
        private final Map<String, AWSKMS> clientsCache = new HashMap<>();
        private static final Set<String> KMS_METHODS = new HashSet<>();
        private AWSKMSClientBuilder kmsClientBuilder;

        static {
            KMS_METHODS.add("generateDataKey");
            KMS_METHODS.add("encrypt");
            KMS_METHODS.add("decrypt");
        }

        Builder(AWSKMSClientBuilder kmsClientBuilder) {
            this.kmsClientBuilder = kmsClientBuilder;
        }

        public KmsClientSupplier build() {
            isTrue(allowedRegions.isEmpty() || excludedRegions.isEmpty(),
                    "Either allowed regions or excluded regions may be set, not both.");

            return regionId -> {
                if (!allowedRegions.isEmpty() && !allowedRegions.contains(regionId)) {
                    throw new UnsupportedRegionException(String.format("Region %s is not in the list of allowed regions %s",
                            regionId, allowedRegions));
                }

                if (excludedRegions.contains(regionId)) {
                    throw new UnsupportedRegionException(String.format("Region %s is in the list of excluded regions %s",
                            regionId, excludedRegions));
                }

                if (clientsCache.containsKey(regionId)) {
                    return clientsCache.get(regionId);
                }

                if (credentialsProvider != null) {
                    kmsClientBuilder = kmsClientBuilder.withCredentials(credentialsProvider);
                }

                if (clientConfiguration != null) {
                    kmsClientBuilder = kmsClientBuilder.withClientConfiguration(clientConfiguration);
                }

                if (regionId != null) {
                    kmsClientBuilder = kmsClientBuilder.withRegion(regionId);
                }

                AWSKMS client = kmsClientBuilder.build();

                if (clientCachingEnabled) {
                    client = newCachingProxy(client, regionId);
                }

                return client;
            };
        }

        /**
         * Sets the AWSCredentialsProvider used by the client.
         *
         * @param credentialsProvider New AWSCredentialsProvider to use.
         */
        public Builder credentialsProvider(AWSCredentialsProvider credentialsProvider) {
            this.credentialsProvider = credentialsProvider;
            return this;
        }

        /**
         * Sets the ClientConfiguration to be used by the client.
         *
         * @param clientConfiguration Custom configuration to use.
         */
        public Builder clientConfiguration(ClientConfiguration clientConfiguration) {
            this.clientConfiguration = clientConfiguration;
            return this;
        }

        /**
         * Sets the AWS regions that the client supplier is permitted to use.
         *
         * @param regions The set of regions.
         */
        public Builder allowedRegions(Set<String> regions) {
            notEmpty(regions, "At least one region is required");
            this.allowedRegions = Collections.unmodifiableSet(new HashSet<>(regions));
            return this;
        }

        /**
         * Sets the AWS regions that the client supplier is not permitted to use.
         *
         * @param regions The set of regions.
         */
        public Builder excludedRegions(Set<String> regions) {
            requireNonNull(regions, "regions is required");
            this.excludedRegions = Collections.unmodifiableSet(new HashSet<>(regions));
            return this;
        }

        /**
         * When set to true, allows for the AWSKMS client for each region to be cached and reused.
         *
         * @param enabled Whether or not caching is enabled.
         */
        public Builder clientCaching(boolean enabled) {
            this.clientCachingEnabled = enabled;
            return this;
        }

        /**
         * Creates a proxy for the AWSKMS client that will populate the client into the client cache
         * after a KMS method successfully completes or a KMS exception occurs. This is to prevent a
         * a malicious user from causing a local resource DOS by sending ciphertext with a large number
         * of spurious regions, thereby filling the cache with regions and exhausting resources.
         *
         * @param client   The client to proxy
         * @param regionId The region the client is associated with
         * @return The proxy
         */
        private AWSKMS newCachingProxy(AWSKMS client, String regionId) {
            return (AWSKMS) Proxy.newProxyInstance(
                    AWSKMS.class.getClassLoader(),
                    new Class[]{AWSKMS.class},
                    (proxy, method, methodArgs) -> {
                        try {
                            final Object result = method.invoke(client, methodArgs);
                            if (KMS_METHODS.contains(method.getName())) {
                                clientsCache.put(regionId, client);
                            }
                            return result;
                        } catch (InvocationTargetException e) {
                            if (e.getTargetException() instanceof AWSKMSException &&
                                    KMS_METHODS.contains(method.getName())) {
                                clientsCache.put(regionId, client);
                            }

                            throw e.getTargetException();
                        }
                    });
        }
    }
}
