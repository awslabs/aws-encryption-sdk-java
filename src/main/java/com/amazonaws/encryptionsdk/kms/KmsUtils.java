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
import com.amazonaws.encryptionsdk.exception.MalformedArnException;
import com.amazonaws.services.kms.AWSKMS;

public class KmsUtils {

    private static final String ALIAS_PREFIX = "alias/";
    private static final String ARN_PREFIX = "arn:";
    /**
     * The provider ID used for the KmsKeyring
     */
    public static final String KMS_PROVIDER_ID = "aws-kms";

    /**
     * Parses region from the given arn (if possible) and passes that region to the
     * given clientSupplier to produce an {@code AWSKMS} client.
     *
     * @param arn            The Amazon Resource Name or Key Alias
     * @param clientSupplier The client supplier
     * @return AWSKMS The client
     * @throws MalformedArnException if the arn is malformed
     */
    public static AWSKMS getClientByArn(String arn, KmsClientSupplier clientSupplier) throws MalformedArnException {
        if (isKeyAlias(arn)) {
            return clientSupplier.getClient(null);
        }

        if(isArn(arn)) {
            try {
                return clientSupplier.getClient(Arn.fromString(arn).getRegion());
            } catch (IllegalArgumentException e) {
                throw new MalformedArnException(e);
            }
        }

        // Not an alias or an ARN, must be a raw Key ID
        return clientSupplier.getClient(null);
    }

    /**
     * Returns true if the given arn is a well formed Amazon Resource Name or Key Alias. Does
     * not return true for raw key IDs.
     *
     * @param arn The Amazon Resource Name or Key Alias
     * @return True if well formed, false otherwise
     */
    public static boolean isArnWellFormed(String arn) {
        if (isKeyAlias(arn)) {
            return true;
        }

        try {
            Arn.fromString(arn);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static boolean isKeyAlias(String arn) {
        return arn.startsWith(ALIAS_PREFIX);
    }

    private static boolean isArn(String arn) {
        return arn.startsWith(ARN_PREFIX);
    }
}
