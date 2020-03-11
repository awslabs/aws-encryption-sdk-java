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
 * An AwsKmsClientSupplier that will only supply clients for a given set of AWS regions.
 */
public class AllowRegionsAwsKmsClientSupplier implements AwsKmsClientSupplier {

    private final Set<String> allowedRegions;
    private final AwsKmsClientSupplier baseSupplier;

    /**
     * Constructs a client supplier that only supplies clients for the specified AWS regions.
     *
     * @param allowedRegions the AWS regions that the client supplier is allowed to supply clients for
     */
    public AllowRegionsAwsKmsClientSupplier(Set<String> allowedRegions) {
        this(allowedRegions, AwsKmsClientSupplier.builder().build());
    }

    /**
     * Constructs a client supplier that only supplies clients for the specified AWS regions.
     * Client supplying is delegated to the given baseSupplier.
     *
     * @param allowedRegions the AWS regions that the client supplier is allowed to supply clients for
     * @param baseSupplier the client supplier that will supply the client if the region is allowed
     */
    public AllowRegionsAwsKmsClientSupplier(Set<String> allowedRegions, AwsKmsClientSupplier baseSupplier) {
        notEmpty(allowedRegions, "At least one region is required");
        requireNonNull(baseSupplier, "baseSupplier is required");
        this.allowedRegions = Collections.unmodifiableSet(new HashSet<>(allowedRegions));
        this.baseSupplier = baseSupplier;
    }

    public AWSKMS getClient(@Nullable String regionId) {

        if (!allowedRegions.contains(regionId)) {
            throw new UnsupportedRegionException(String.format("Region %s is not in the set of allowed regions %s",
                    regionId, allowedRegions));
        }

        return baseSupplier.getClient(regionId);
    }
}
