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

import com.amazonaws.encryptionsdk.exception.MalformedArnException;
import com.amazonaws.services.kms.AWSKMS;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class KmsUtilsTest {

    private static final String VALID_ARN = "arn:aws:kms:us-east-1:999999999999:key/01234567-89ab-cdef-fedc-ba9876543210";
    private static final String VALID_ALIAS_ARN = "arn:aws:kms:us-east-1:999999999999:alias/MyCryptoKey";
    private static final String VALID_ALIAS = "alias/MyCryptoKey";
    private static final String VALID_RAW_KEY_ID = "01234567-89ab-cdef-fedc-ba9876543210";

    @Mock
    private AWSKMS client;


    @Test
    void testGetClientByArn() {
        assertEquals(client, KmsUtils.getClientByArn(VALID_ARN, s -> client));
        assertEquals(client, KmsUtils.getClientByArn(VALID_ALIAS_ARN, s -> client));
        assertEquals(client, KmsUtils.getClientByArn(VALID_ALIAS, s -> client));
        assertThrows(MalformedArnException.class, () -> KmsUtils.getClientByArn("arn:invalid", s -> client));
        assertEquals(client, KmsUtils.getClientByArn(VALID_RAW_KEY_ID, s -> client));
    }

    @Test
    void testIsArnWellFormed() {
        assertTrue(KmsUtils.isArnWellFormed(VALID_ARN));
        assertTrue(KmsUtils.isArnWellFormed(VALID_ALIAS_ARN));
        assertTrue(KmsUtils.isArnWellFormed(VALID_ALIAS));
        assertFalse(KmsUtils.isArnWellFormed(VALID_RAW_KEY_ID));
        assertFalse(KmsUtils.isArnWellFormed("arn:invalid"));

    }
}
