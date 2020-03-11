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

import com.amazonaws.encryptionsdk.exception.UnsupportedRegionException;
import com.amazonaws.services.kms.AWSKMS;

import javax.annotation.Nullable;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static java.util.Objects.requireNonNull;
import static org.apache.commons.lang3.Validate.notEmpty;

/**
 * A client supplier that supplies clients for any region except the specified AWS regions.
 */
public class DenyRegionsAwsKmsClientSupplier implements AwsKmsClientSupplier {

    private final Set<String> deniedRegions;
    private final AwsKmsClientSupplier baseSupplier;

    /**
     * Constructs a client supplier that supplies clients for any region except the specified AWS regions.
     *
     * @param deniedRegions the AWS regions that the client supplier will not supply clients for
     */
    public DenyRegionsAwsKmsClientSupplier(Set<String> deniedRegions) {
        this(deniedRegions, AwsKmsClientSupplier.builder().build());
    }

    /**
     * Constructs a client supplier that supplies clients for any region except the specified AWS regions.
     * Client supplying is delegated to the given baseSupplier.
     *
     * @param deniedRegions the AWS regions that the client supplier will not supply clients for
     * @param baseSupplier the client supplier that will supply the client if the region is not denied
     */
    public DenyRegionsAwsKmsClientSupplier(Set<String> deniedRegions, AwsKmsClientSupplier baseSupplier) {
        notEmpty(deniedRegions, "At least one region is required");
        requireNonNull(baseSupplier, "baseSupplier is required");
        this.deniedRegions = Collections.unmodifiableSet(new HashSet<>(deniedRegions));
        this.baseSupplier = baseSupplier;
    }

    public AWSKMS getClient(@Nullable String regionId) {

        if (deniedRegions.contains(regionId)) {
            throw new UnsupportedRegionException(String.format("Region %s is in the set of denied regions %s",
                    regionId, deniedRegions));
        }

        return baseSupplier.getClient(regionId);
    }
}
