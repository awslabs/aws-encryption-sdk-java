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

import com.amazonaws.arn.Arn;
import com.amazonaws.encryptionsdk.exception.UnsupportedRegionException;
import com.amazonaws.services.kms.AWSKMS;

import javax.annotation.Nullable;

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
}
