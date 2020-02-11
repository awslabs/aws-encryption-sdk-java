/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AwsKmsCmkIdTest {
    private static final String VALID_ARN = "arn:aws:kms:us-east-1:999999999999:key/01234567-89ab-cdef-fedc-ba9876543210";
    private static final String VALID_ALIAS_ARN = "arn:aws:kms:us-east-1:999999999999:alias/MyCryptoKey";
    private static final String VALID_ALIAS = "alias/MyCryptoKey";
    private static final String VALID_RAW_KEY_ID = "01234567-89ab-cdef-fedc-ba9876543210";

    @Test
    void testFromString() {
        assertThrows(MalformedArnException.class, () -> AwsKmsCmkId.fromString("arn:invalid"));

        assertTrue(AwsKmsCmkId.fromString(VALID_ARN).isArn());
        assertTrue(AwsKmsCmkId.fromString(VALID_ALIAS_ARN).isArn());
        assertFalse(AwsKmsCmkId.fromString(VALID_ALIAS).isArn());
        assertFalse(AwsKmsCmkId.fromString(VALID_RAW_KEY_ID).isArn());
    }

    @Test
    void testIsKeyIdWellFormed() {
        assertTrue(AwsKmsCmkId.isKeyIdWellFormed(VALID_ARN));
        assertTrue(AwsKmsCmkId.isKeyIdWellFormed(VALID_ALIAS_ARN));
        assertTrue(AwsKmsCmkId.isKeyIdWellFormed(VALID_ALIAS));
        assertTrue(AwsKmsCmkId.isKeyIdWellFormed(VALID_RAW_KEY_ID));
        assertFalse(AwsKmsCmkId.isKeyIdWellFormed("arn:invalid"));
        assertFalse(AwsKmsCmkId.isKeyIdWellFormed("   "));
        assertFalse(AwsKmsCmkId.isKeyIdWellFormed(null));
    }

    @Test
    void testToString() {
        assertEquals(VALID_ARN, AwsKmsCmkId.fromString(VALID_ARN).toString());
    }

    @Test
    void testEquals() {
        assertEquals(AwsKmsCmkId.fromString(VALID_ARN), AwsKmsCmkId.fromString(VALID_ARN));
        assertNotEquals(AwsKmsCmkId.fromString(VALID_ALIAS), AwsKmsCmkId.fromString(VALID_ALIAS_ARN));
    }
}
