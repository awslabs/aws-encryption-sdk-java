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
import com.amazonaws.encryptionsdk.kms.StandardAwsKmsClientSuppliers.DefaultAwsKmsClientSupplierBuilder;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.AWSKMSException;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.EncryptRequest;
import com.amazonaws.services.kms.model.EncryptResult;
import com.amazonaws.services.kms.model.GenerateDataKeyRequest;
import com.amazonaws.services.kms.model.KMSInvalidStateException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class StandardAwsKmsClientSuppliersTest {

    @Mock AWSKMSClientBuilder kmsClientBuilder;
    @Mock AWSKMS awskms;
    @Mock EncryptRequest encryptRequest;
    @Mock DecryptRequest decryptRequest;
    @Mock GenerateDataKeyRequest generateDataKeyRequest;
    @Mock AWSCredentialsProvider credentialsProvider;
    @Mock ClientConfiguration clientConfiguration;
    private static final String REGION_1 = "us-east-1";
    private static final String REGION_2 = "us-west-2";
    private static final String REGION_3 = "eu-west-1";

    @Test
    void testCredentialsAndClientConfiguration() {
        when(kmsClientBuilder.withClientConfiguration(clientConfiguration)).thenReturn(kmsClientBuilder);
        when(kmsClientBuilder.withCredentials(credentialsProvider)).thenReturn(kmsClientBuilder);
        when(kmsClientBuilder.build()).thenReturn(awskms);

        AwsKmsClientSupplier supplier = new DefaultAwsKmsClientSupplierBuilder(kmsClientBuilder)
                .credentialsProvider(credentialsProvider)
                .clientConfiguration(clientConfiguration)
                .build();

        supplier.getClient(null);

        verify(kmsClientBuilder).withClientConfiguration(clientConfiguration);
        verify(kmsClientBuilder).withCredentials(credentialsProvider);
        verify(kmsClientBuilder).build();
    }

    @Test
    void testClientCaching() {
        AwsKmsClientSupplier supplier = new DefaultAwsKmsClientSupplierBuilder(kmsClientBuilder)
                .build();

        when(kmsClientBuilder.withRegion(REGION_1)).thenReturn(kmsClientBuilder);
        when(kmsClientBuilder.withRegion(REGION_2)).thenReturn(kmsClientBuilder);
        when(kmsClientBuilder.withRegion(REGION_3)).thenReturn(kmsClientBuilder);
        when(kmsClientBuilder.build()).thenReturn(awskms);

        AWSKMS client = supplier.getClient(REGION_1);
        AWSKMS client2 = supplier.getClient(REGION_2);
        AWSKMS client3 = supplier.getClient(REGION_3);
        verify(kmsClientBuilder, times(3)).build();

        // No KMS methods have been called yet, so clients remain uncached
        supplier.getClient(REGION_1);
        supplier.getClient(REGION_2);
        supplier.getClient(REGION_3);
        verify(kmsClientBuilder, times(6)).build();

        when(awskms.encrypt(encryptRequest)).thenReturn(new EncryptResult());
        when(awskms.decrypt(decryptRequest)).thenThrow(new KMSInvalidStateException("test"));
        when(awskms.generateDataKey(generateDataKeyRequest)).thenThrow(new IllegalArgumentException("test"));

        // Successful KMS call, client is cached
        client.encrypt(encryptRequest);
        supplier.getClient(REGION_1);
        verify(kmsClientBuilder, times(6)).build();

        // KMS call resulted in KMS exception, client is cached
        assertThrows(AWSKMSException.class, () -> client2.decrypt(decryptRequest));
        supplier.getClient(REGION_2);
        verify(kmsClientBuilder, times(6)).build();

        // KMS call resulted in non-KMS exception, client is not cached
        assertThrows(IllegalArgumentException.class, () -> client3.generateDataKey(generateDataKeyRequest));
        supplier.getClient(REGION_3);
        verify(kmsClientBuilder, times(7)).build();

        // Non-KMS method, client is not cached
        client3.toString();
        supplier.getClient(REGION_3);
        verify(kmsClientBuilder, times(8)).build();
    }

    @Test
    void testGetClientByKeyId() {

        final String arn = "arn:aws:kms:us-east-1:999999999999:key/01234567-89ab-cdef-fedc-ba9876543210";
        final String aliasArn = "arn:aws:kms:us-east-1:999999999999:alias/MyCryptoKey";
        final String alias = "alias/MyCryptoKey";
        final String keyId = "01234567-89ab-cdef-fedc-ba9876543210";

        assertEquals(awskms, AwsKmsClientSupplier.getClientByKeyId(AwsKmsCmkId.fromString(arn), s -> awskms));
        assertEquals(awskms, AwsKmsClientSupplier.getClientByKeyId(AwsKmsCmkId.fromString(aliasArn), s -> awskms));
        assertEquals(awskms, AwsKmsClientSupplier.getClientByKeyId(AwsKmsCmkId.fromString(alias), s -> awskms));
        assertEquals(awskms, AwsKmsClientSupplier.getClientByKeyId(AwsKmsCmkId.fromString(keyId), s -> awskms));
    }

    @Test
    void testAllowedRegions() {
        AwsKmsClientSupplier supplierWithDefaultValues = new DefaultAwsKmsClientSupplierBuilder(kmsClientBuilder)
                .build();

        when(kmsClientBuilder.withRegion(REGION_1)).thenReturn(kmsClientBuilder);
        when(kmsClientBuilder.build()).thenReturn(awskms);

        assertNotNull(supplierWithDefaultValues.getClient(REGION_1));

        AwsKmsClientSupplier supplierWithAllowed = StandardAwsKmsClientSuppliers
                .allowRegionsBuilder(Collections.singleton(REGION_1))
                .baseClientSupplier(new DefaultAwsKmsClientSupplierBuilder(kmsClientBuilder).build()).build();

        when(kmsClientBuilder.withRegion(REGION_1)).thenReturn(kmsClientBuilder);
        when(kmsClientBuilder.build()).thenReturn(awskms);

        assertNotNull(supplierWithAllowed.getClient(REGION_1));
        assertThrows(UnsupportedRegionException.class, () -> supplierWithAllowed.getClient(REGION_2));
    }

    @Test
    void testDeniedRegions() {
        AwsKmsClientSupplier supplierWithDefaultValues = new DefaultAwsKmsClientSupplierBuilder(kmsClientBuilder)
                .build();

        when(kmsClientBuilder.withRegion(REGION_1)).thenReturn(kmsClientBuilder);
        when(kmsClientBuilder.build()).thenReturn(awskms);

        assertNotNull(supplierWithDefaultValues.getClient(REGION_1));

        AwsKmsClientSupplier supplierWithDenied = StandardAwsKmsClientSuppliers
                .denyRegionsBuilder(Collections.singleton(REGION_1))
                .baseClientSupplier(new DefaultAwsKmsClientSupplierBuilder(kmsClientBuilder).build()).build();

        when(kmsClientBuilder.withRegion(REGION_2)).thenReturn(kmsClientBuilder);
        when(kmsClientBuilder.build()).thenReturn(awskms);

        assertThrows(UnsupportedRegionException.class, () -> supplierWithDenied.getClient(REGION_1));
        assertNotNull(supplierWithDenied.getClient(REGION_2));
    }
}
