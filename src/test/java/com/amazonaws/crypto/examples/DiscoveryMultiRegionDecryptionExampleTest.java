// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples;

import com.amazonaws.encryptionsdk.kms.KMSTestFixtures;
import org.junit.Test;

public class DiscoveryMultiRegionDecryptionExampleTest {

    @Test
    public void testEncryptAndDecrypt() {
        DiscoveryMultiRegionDecryptionExample.encryptAndDecrypt(
          KMSTestFixtures.US_EAST_1_MULTI_REGION_KEY_ID,
          KMSTestFixtures.PARTITION,
          KMSTestFixtures.ACCOUNT_ID,
          KMSTestFixtures.US_WEST_2
        );
    }
}
