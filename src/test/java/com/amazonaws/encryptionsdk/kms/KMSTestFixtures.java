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

final public class KMSTestFixtures {
    private KMSTestFixtures() {
        throw new UnsupportedOperationException(
                "This class exists to hold static constants and cannot be instantiated."
        );
    }

    /**
     * These special test keys have been configured to allow Encrypt, Decrypt, and GenerateDataKey operations from any
     * AWS principal and should be used when adding new KMS tests.
     *
     * This should go without saying, but never use these keys for production purposes (as anyone in the world can
     * decrypt data encrypted using them).
     */
    public static final String[] TEST_KEY_IDS = new String[] {
            "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f",
            "arn:aws:kms:eu-central-1:658956600833:key/75414c93-5285-4b57-99c9-30c1cf0a22c2"
    };
}
