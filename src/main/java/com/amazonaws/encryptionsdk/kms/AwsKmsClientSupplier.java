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
import com.amazonaws.arn.Arn;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.encryptionsdk.exception.UnsupportedRegionException;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.AWSKMSException;

import javax.annotation.Nullable;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * Represents a function that accepts an AWS region and returns an {@code AWSKMS} client for that region. The
 * function should be able to handle when the region is null.
 */
@FunctionalInterface
public interface AwsKmsClientSupplier {

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
     * Gets a Builder for constructing an AwsKmsClientSupplier
     *
     * @return The builder
     */
    static Builder builder() {
        return new Builder(AWSKMSClientBuilder.standard());
    }

    /**
     * Parses region from the given key id (if possible) and passes that region to the
     * given clientSupplier to produce an {@code AWSKMS} client.
     *
     * @param keyId          The Amazon Resource Name, Key Alias, Alias ARN or KeyId
     * @param clientSupplier The client supplier
     * @return AWSKMS The client
     */
    static AWSKMS getClientByKeyId(AwsKmsCmkId keyId, AwsKmsClientSupplier clientSupplier) {
        requireNonNull(keyId, "keyId is required");
        requireNonNull(clientSupplier, "clientSupplier is required");

        if(keyId.isArn()) {
            return clientSupplier.getClient(Arn.fromString(keyId.toString()).getRegion());
        }

        return clientSupplier.getClient(null);
    }

    /**
     * Builder to construct an AwsKmsClientSupplier that will create and cache clients
     * for any region. CredentialProvider and ClientConfiguration are optional and may
     * be configured if necessary.
     */
    class Builder {

        private AWSCredentialsProvider credentialsProvider;
        private ClientConfiguration clientConfiguration;
        private final Map<String, AWSKMS> clientsCache = new HashMap<>();
        private static final Set<String> AWSKMS_METHODS = new HashSet<>();
        private AWSKMSClientBuilder awsKmsClientBuilder;

        static {
            AWSKMS_METHODS.add("generateDataKey");
            AWSKMS_METHODS.add("encrypt");
            AWSKMS_METHODS.add("decrypt");
        }

        Builder(AWSKMSClientBuilder awsKmsClientBuilder) {
            this.awsKmsClientBuilder = awsKmsClientBuilder;
        }

        public AwsKmsClientSupplier build() {

            return regionId -> {

                if (clientsCache.containsKey(regionId)) {
                    return clientsCache.get(regionId);
                }

                if (credentialsProvider != null) {
                    awsKmsClientBuilder = awsKmsClientBuilder.withCredentials(credentialsProvider);
                }

                if (clientConfiguration != null) {
                    awsKmsClientBuilder = awsKmsClientBuilder.withClientConfiguration(clientConfiguration);
                }

                if (regionId != null) {
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
}
