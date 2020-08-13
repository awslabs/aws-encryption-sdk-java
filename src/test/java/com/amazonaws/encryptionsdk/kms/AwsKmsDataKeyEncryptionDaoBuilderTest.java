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
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Arrays;
import java.util.List;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AwsKmsDataKeyEncryptionDaoBuilderTest {

    @Mock AWSKMSClientBuilder kmsClientBuilder;
    @Mock AWSKMS awskms;
    @Mock AWSCredentialsProvider credentialsProvider;
    @Mock ClientConfiguration clientConfiguration;

    private static final String REGION = "us-east-1";
    private static final List<String> GRANT_TOKENS = Arrays.asList("some", "grant", "tokens");

    @Test
    void testCredentialsClientAndRegionConfiguration() {
        when(kmsClientBuilder.withClientConfiguration(clientConfiguration)).thenReturn(kmsClientBuilder);
        when(kmsClientBuilder.withCredentials(credentialsProvider)).thenReturn(kmsClientBuilder);
        when(kmsClientBuilder.withRegion(REGION)).thenReturn(kmsClientBuilder);
        when(kmsClientBuilder.build()).thenReturn(awskms);

        DataKeyEncryptionDao builder = new AwsKmsDataKeyEncryptionDaoBuilder(kmsClientBuilder)
                .credentialsProvider(credentialsProvider)
                .clientConfiguration(clientConfiguration)
                .regionId(REGION)
                .grantTokens(GRANT_TOKENS)
                .build();

        verify(kmsClientBuilder).withCredentials(credentialsProvider);
        verify(kmsClientBuilder).withClientConfiguration(clientConfiguration);
        verify(kmsClientBuilder).withRegion(REGION);
        verify(kmsClientBuilder).build();
    }

    @Test
    void testDefaultConfiguration() {
        when(kmsClientBuilder.build()).thenReturn(awskms);

        DataKeyEncryptionDao builder = new AwsKmsDataKeyEncryptionDaoBuilder(kmsClientBuilder).build();

        verify(kmsClientBuilder).build();
    }

    @Test
    void testNullConfiguration() {
        when(kmsClientBuilder.build()).thenReturn(awskms);

        DataKeyEncryptionDao builder = new AwsKmsDataKeyEncryptionDaoBuilder(kmsClientBuilder)
            .credentialsProvider(null)
            .clientConfiguration(null)
            .regionId(null)
            .build();

        verify(kmsClientBuilder).build();
    }
}
