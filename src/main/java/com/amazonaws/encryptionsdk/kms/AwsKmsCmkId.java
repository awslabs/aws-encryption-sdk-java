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

import com.amazonaws.arn.Arn;
import com.amazonaws.encryptionsdk.exception.MalformedArnException;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Validate;

import java.util.Objects;

/**
 * A representation of an AWS KMS Customer Master Key Identifier, which may be one either a
 * key ID, key Amazon Resource Name (ARN), alias name, or alias ARN.
 */
public final class AwsKmsCmkId {

    private static final String ARN_PREFIX = "arn:";
    private String keyId;

    private AwsKmsCmkId(String keyId) throws MalformedArnException {
        Validate.notBlank(keyId, "keyId must be neither null, empty nor whitespace");

        if (keyId.startsWith(ARN_PREFIX)) {
            try {
                Arn.fromString(keyId);
            } catch (IllegalArgumentException e) {
                throw new MalformedArnException(e);
            }
        }

        this.keyId = keyId;
    }

    /**
     * <p>
     * Constructs an {@code AwsKmsCmkId} from the given String id.
     * </p>
     * <p>
     * Valid identifiers must be either a key ID, key Amazon Resource Name (ARN), alias name, or alias ARN. When using
     * an alias name, prefix it with "alias/". To specify a CMK in a different AWS account, you must use the key ARN or
     * alias ARN. When using decryption operations, you must use the key ARN.
     * </p>
     * <p>
     * For example:
     * </p>
     * <ul>
     * <li>
     * <p>
     * Key ID: <code>1234abcd-12ab-34cd-56ef-1234567890ab</code>
     * </p>
     * </li>
     * <li>
     * <p>
     * Key ARN: <code>arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab</code>
     * </p>
     * </li>
     * <li>
     * <p>
     * Alias name: <code>alias/ExampleAlias</code>
     * </p>
     * </li>
     * <li>
     * <p>
     * Alias ARN: <code>arn:aws:kms:us-east-2:111122223333:alias/ExampleAlias</code>
     * </p>
     * </li>
     * </ul>
     *
     * @param keyId The key ID, key Amazon Resource Name (ARN), alias name, or alias ARN
     * @return The {@code AwsKmsCmkId}
     * @throws MalformedArnException if the given keyId is an ARN (starts with 'arn:') and cannot be parsed
     */
    public static AwsKmsCmkId fromString(String keyId) throws MalformedArnException {
        return new AwsKmsCmkId(keyId);
    }

    /**
     * Returns true if the given keyId is a well formed Amazon Resource Name or is a Key Alias or raw Key Id.
     *
     * @param keyId The key ID, key Amazon Resource Name (ARN), alias name, or alias ARN
     * @return True if well formed, false otherwise
     */
    public static boolean isKeyIdWellFormed(String keyId) {
        if (StringUtils.isBlank(keyId)) {
            return false;
        }

        if (!keyId.startsWith(ARN_PREFIX)) {
            return true;
        }

        try {
            Arn.fromString(keyId);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * Returns true if this AwsKmsCmkId is in the Amazon Resource Name (ARN) format.
     *
     * @return True if in the ARN format, false otherwise
     */
    public boolean isArn() {
        return keyId.startsWith(ARN_PREFIX);
    }

    @Override
    public String toString() {
        return keyId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AwsKmsCmkId that = (AwsKmsCmkId) o;
        return keyId.equals(that.keyId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(keyId);
    }
}
