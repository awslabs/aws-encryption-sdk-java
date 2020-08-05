/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import static java.util.Objects.requireNonNull;
import static org.apache.commons.lang3.Validate.notEmpty;

/**
 * Factory methods for instantiating the standard {@code AwsKmsClientSupplier}s provided by the AWS Encryption SDK.
 */
public class StandardAwsKmsClientSuppliers {

    /**
     * A builder to construct the default AwsKmsClientSupplier that will create and cache clients
     * for any region. Credentials and client configuration may be specified if necessary.
     *
     * @return The builder
     */
    public static DefaultAwsKmsClientSupplierBuilder defaultBuilder() {
        return new DefaultAwsKmsClientSupplierBuilder(AWSKMSClientBuilder.standard());
    }

    /**
     * A builder to construct an AwsKmsClientSupplier that will
     * only supply clients for a given set of AWS regions.
     *
     * @param allowedRegions the AWS regions that the client supplier is allowed to supply clients for
     * @return The builder
     */
    public static AllowRegionsAwsKmsClientSupplierBuilder allowRegionsBuilder(Set<String> allowedRegions) {
        return new AllowRegionsAwsKmsClientSupplierBuilder(allowedRegions);
    }

    /**
     * A builder to construct an AwsKmsClientSupplier that will
     * supply clients for all AWS regions except the given set of regions.
     *
     * @param deniedRegions the AWS regions that the client supplier will not supply clients for
     * @return The builder
     */
    public static DenyRegionsAwsKmsClientSupplierBuilder denyRegionsBuilder(Set<String> deniedRegions) {
        return new DenyRegionsAwsKmsClientSupplierBuilder(deniedRegions);
    }


    /**
     * Builder to construct an AwsKmsClientSupplier that will create and cache clients
     * for any region. CredentialProvider and ClientConfiguration are optional and may
     * be configured if necessary.
     */
    public static class DefaultAwsKmsClientSupplierBuilder {

        private AWSCredentialsProvider credentialsProvider;
        private ClientConfiguration clientConfiguration;
        private final Map<String, AWSKMS> clientsCache = new ConcurrentHashMap<>();
        private static final Set<String> AWSKMS_METHODS = new HashSet<>();
        private AWSKMSClientBuilder awsKmsClientBuilder;
        private static final String NULL_REGION = "null-region";

        static {
            AWSKMS_METHODS.add("generateDataKey");
            AWSKMS_METHODS.add("encrypt");
            AWSKMS_METHODS.add("decrypt");
        }

        DefaultAwsKmsClientSupplierBuilder(AWSKMSClientBuilder awsKmsClientBuilder) {
            this.awsKmsClientBuilder = awsKmsClientBuilder;
        }

        public AwsKmsClientSupplier build() {

            return regionId -> {

                if(regionId == null) {
                    regionId = NULL_REGION;
                }

                if (clientsCache.containsKey(regionId)) {
                    return clientsCache.get(regionId);
                }

                if (credentialsProvider != null) {
                    awsKmsClientBuilder = awsKmsClientBuilder.withCredentials(credentialsProvider);
                }

                if (clientConfiguration != null) {
                    awsKmsClientBuilder = awsKmsClientBuilder.withClientConfiguration(clientConfiguration);
                }

                if (!regionId.equals(NULL_REGION)) {
                    awsKmsClientBuilder = awsKmsClientBuilder.withRegion(regionId);
                }

                return newCachingProxy(awsKmsClientBuilder.build(), regionId);
            };
        }

        /**
         * Sets the AWSCredentialsProvider used by the client.
         *
         * @param credentialsProvider New AWSCredentialsProvider to use.
         */
        public DefaultAwsKmsClientSupplierBuilder credentialsProvider(AWSCredentialsProvider credentialsProvider) {
            this.credentialsProvider = credentialsProvider;
            return this;
        }

        /**
         * Sets the ClientConfiguration to be used by the client.
         *
         * @param clientConfiguration Custom configuration to use.
         */
        public DefaultAwsKmsClientSupplierBuilder clientConfiguration(ClientConfiguration clientConfiguration) {
            this.clientConfiguration = clientConfiguration;
            return this;
        }

        /**
         * Creates a proxy for the AWSKMS client that will populate the client into the client cache
         * after an AWS KMS method successfully completes or an AWS KMS exception occurs. This is to prevent a
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
                            if (AWSKMS_METHODS.contains(method.getName())) {
                                clientsCache.put(regionId, client);
                            }
                            return result;
                        } catch (InvocationTargetException e) {
                            if (e.getTargetException() instanceof AWSKMSException &&
                                    AWSKMS_METHODS.contains(method.getName())) {
                                clientsCache.put(regionId, client);
                            }

                            throw e.getTargetException();
                        }
                    });
        }
    }

    /**
     * An AwsKmsClientSupplier that will only supply clients for a given set of AWS regions.
     */
    public static class AllowRegionsAwsKmsClientSupplierBuilder {

        private final Set<String> allowedRegions;
        private AwsKmsClientSupplier baseClientSupplier = StandardAwsKmsClientSuppliers.defaultBuilder().build();

        private AllowRegionsAwsKmsClientSupplierBuilder(Set<String> allowedRegions) {
            notEmpty(allowedRegions, "At least one region is required");
            requireNonNull(baseClientSupplier, "baseClientSupplier is required");

            this.allowedRegions = allowedRegions;
        }

        /**
         * Constructs the AwsKmsClientSupplier.
         *
         * @return The AwsKmsClientSupplier
         */
        public AwsKmsClientSupplier build() {
            return regionId -> {

                if (!allowedRegions.contains(regionId)) {
                    throw new UnsupportedRegionException(String.format("Region %s is not in the set of allowed regions %s",
                            regionId, allowedRegions));
                }

                return baseClientSupplier.getClient(regionId);
            };
        }

        /**
         * Sets the client supplier that will supply the client if the region is allowed.
         *
         * @param baseClientSupplier the client supplier that will supply the client if the region is allowed.
         */
        public AllowRegionsAwsKmsClientSupplierBuilder baseClientSupplier(AwsKmsClientSupplier baseClientSupplier) {
            this.baseClientSupplier = baseClientSupplier;
            return this;
        }
    }

    /**
     * A client supplier that supplies clients for any region except the specified AWS regions.
     */
    public static class DenyRegionsAwsKmsClientSupplierBuilder {

        private final Set<String> deniedRegions;
        private AwsKmsClientSupplier baseClientSupplier = StandardAwsKmsClientSuppliers.defaultBuilder().build();

        private DenyRegionsAwsKmsClientSupplierBuilder(Set<String> deniedRegions) {
            notEmpty(deniedRegions, "At least one region is required");
            requireNonNull(baseClientSupplier, "baseClientSupplier is required");

            this.deniedRegions = deniedRegions;
        }

        /**
         * Sets the client supplier that will supply the client if the region is allowed.
         *
         * @param baseClientSupplier the client supplier that will supply the client if the region is allowed.
         */
        public DenyRegionsAwsKmsClientSupplierBuilder baseClientSupplier(AwsKmsClientSupplier baseClientSupplier) {
            this.baseClientSupplier = baseClientSupplier;
            return this;
        }

        public AwsKmsClientSupplier build() {

            return regionId -> {

                if (deniedRegions.contains(regionId)) {
                    throw new UnsupportedRegionException(String.format("Region %s is in the set of denied regions %s",
                            regionId, deniedRegions));
                }

                return baseClientSupplier.getClient(regionId);
            };
        }
    }
}
