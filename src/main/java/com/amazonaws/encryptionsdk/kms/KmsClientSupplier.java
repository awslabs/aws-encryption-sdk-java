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

import com.amazonaws.services.kms.AWSKMS;

import javax.annotation.Nullable;

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
     */
    AWSKMS getClient(@Nullable String regionId);
}
