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

package com.amazonaws.encryptionsdk.keyrings;

import com.amazonaws.encryptionsdk.kms.AwsKmsCmkId;
import com.amazonaws.encryptionsdk.kms.StandardAwsKmsClientSuppliers;

import java.util.Arrays;
import java.util.List;

/**
 * Factory methods for instantiating the standard {@code Keyring}s provided by the AWS Encryption SDK.
 */
public class StandardKeyrings {

    private StandardKeyrings() {
    }

    /**
     * Returns a {@link RawAesKeyringBuilder} for use in constructing a keyring which does local AES-GCM encryption
     * decryption of data keys using a provided wrapping key.
     *
     * @return The {@link RawAesKeyringBuilder}
     */
    public static RawAesKeyringBuilder rawAesBuilder() {
        return RawAesKeyringBuilder.standard();
    }

    /**
     * Constructs a {@code RawRsaKeyringBuilder} which does local RSA encryption and decryption of data keys using the
     * provided public and private keys. If {@code privateKey} is {@code null} then the returned {@code Keyring}
     * can only be used for encryption.
     *
     * @return The {@link RawRsaKeyringBuilder}
     */
    public static RawRsaKeyringBuilder rawRsaBuilder() {
        return RawRsaKeyringBuilder.standard();
    }
      
    /**  
     * Constructs a {@code Keyring} which interacts with AWS Key Management Service (KMS) to create,
     * encrypt, and decrypt data keys using the supplied AWS KMS defined Customer Master Key (CMK).
     * Use {@link #awsKmsBuilder()} for more advanced configuration using an {@link AwsKmsKeyringBuilder}
     *
     * @param generatorKeyId    An {@link AwsKmsCmkId} in ARN, CMK Alias, ARN Alias or Key Id format that identifies a
     *                          AWS KMS CMK responsible for generating a data key, as well as encrypting and
     *                          decrypting data keys .
     * @return The {@code Keyring}
     */
    public static Keyring awsKms(AwsKmsCmkId generatorKeyId) {
        return AwsKmsKeyringBuilder.standard()
                .generatorKeyId(generatorKeyId)
                .build();
    }

    /**
     * Returns a {@link AwsKmsKeyringBuilder} for use in constructing a keyring which interacts with
     * AWS Key Management Service (KMS) to create, encrypt, and decrypt data keys using AWS KMS defined
     * Customer Master Keys (CMKs).
     *
     * @return The {@link AwsKmsKeyringBuilder}
     */
    public static AwsKmsKeyringBuilder awsKmsBuilder() {
        return AwsKmsKeyringBuilder.standard();
    }

    /**
     * Returns an {@link AwsKmsKeyringBuilder} for use in constructing an AWS KMS Discovery keyring.
     * AWS KMS Discovery keyrings do not specify any CMKs to decrypt with, and thus will attempt to decrypt
     * using any encrypted data key in an encrypted message. AWS KMS Discovery keyrings do not perform encryption.
     * <p></p>
     * To create an AWS KMS Regional Discovery Keyring, use {@link StandardAwsKmsClientSuppliers#allowRegionsBuilder} or
     * {@link StandardAwsKmsClientSuppliers#denyRegionsBuilder} to specify which regions to include/exclude.
     * <p></p>
     * For example, to include only CMKs in the us-east-1 region:
     * <pre>
     * StandardKeyrings.awsKmsDiscovery()
     *             .awsKmsClientSupplier(
     *                     StandardAwsKmsClientSuppliers.allowRegionsBuilder(Collections.singleton("us-east-1")).build()
     *             .build();
     * </pre>
     *
     * @return The {@code AwsKmsKeyringBuilder}
     */
    public static AwsKmsKeyringBuilder awsKmsDiscoveryBuilder() {
        return AwsKmsKeyringBuilder.discovery();
    }

    /**
     * Constructs a {@code Keyring} which combines other keyrings, allowing one OnEncrypt or OnDecrypt call
     * to modify the encryption or decryption materials using more than one keyring.
     *
     * @param generatorKeyring A keyring that can generate data keys. Required if childKeyrings is empty.
     * @param childKeyrings A list of keyrings to be used to modify the encryption or decryption materials.
     *                         At least one is required if generatorKeyring is null.
     * @return The {@link Keyring}
     */
    public static Keyring multi(Keyring generatorKeyring, List<Keyring> childKeyrings) {
        return new MultiKeyring(generatorKeyring, childKeyrings);
    }

    /**
     * Constructs a {@code Keyring} which combines other keyrings, allowing one OnEncrypt or OnDecrypt call
     * to modify the encryption or decryption materials using more than one keyring.
     *
     * @param generatorKeyring A keyring that can generate data keys. Required if childKeyrings is empty.
     * @param childKeyrings Keyrings to be used to modify the encryption or decryption materials.
     *                         At least one is required if generatorKeyring is null.
     * @return The {@link Keyring}
     */
    public static Keyring multi(Keyring generatorKeyring, Keyring... childKeyrings) {
        return new MultiKeyring(generatorKeyring, Arrays.asList(childKeyrings));
    }
}
