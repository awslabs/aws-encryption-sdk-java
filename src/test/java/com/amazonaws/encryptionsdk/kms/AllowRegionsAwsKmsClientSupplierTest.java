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
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AllowRegionsAwsKmsClientSupplierTest {

    @Mock AWSKMSClientBuilder kmsClientBuilder;
    @Mock AWSKMS awskms;
    private static final String REGION_1 = "us-east-1";
    private static final String REGION_2 = "us-west-2";

    @Test
    void testAllowedRegions() {
        AwsKmsClientSupplier supplierWithDefaultValues = new AwsKmsClientSupplier.Builder(kmsClientBuilder)
                .build();

        when(kmsClientBuilder.withRegion(REGION_1)).thenReturn(kmsClientBuilder);
        when(kmsClientBuilder.build()).thenReturn(awskms);

        assertNotNull(supplierWithDefaultValues.getClient(REGION_1));

        AwsKmsClientSupplier supplierWithAllowed = new AllowRegionsAwsKmsClientSupplier(
                Collections.singleton(REGION_1),
                new AwsKmsClientSupplier.Builder(kmsClientBuilder).build());

        when(kmsClientBuilder.withRegion(REGION_1)).thenReturn(kmsClientBuilder);
        when(kmsClientBuilder.build()).thenReturn(awskms);

        assertNotNull(supplierWithAllowed.getClient(REGION_1));
        assertThrows(UnsupportedRegionException.class, () -> supplierWithAllowed.getClient(REGION_2));
    }
}
