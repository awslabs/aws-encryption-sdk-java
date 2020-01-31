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
    public static RawAesKeyringBuilder rawAes() {
        return new RawAesKeyringBuilder();
    }

    /**
     * Constructs a {@code RawRsaKeyringBuilder} which does local RSA encryption and decryption of data keys using the
     * provided public and private keys. If {@code privateKey} is {@code null} then the returned {@code Keyring}
     * can only be used for encryption.
     *
     * @return The {@link RawRsaKeyringBuilder}
     */
    public static RawRsaKeyringBuilder rawRsa() {
        return new RawRsaKeyringBuilder();
    }
      
    /**  
     * Constructs a {@code Keyring} which interacts with AWS Key Management Service (KMS) to create,
     * encrypt, and decrypt data keys using the supplied AWS KMS defined Customer Master Key (CMK).
     * Use {@link #awsKms()} for more advanced configuration using a {@link AwsKmsKeyringBuilder}/
     *
     * @param generatorKeyId    An {@link AwsKmsCmkId} in ARN, CMK Alias, ARN Alias or Key Id format that identifies a
     *                          AWS KMS CMK responsible for generating a data key, as well as encrypting and
     *                          decrypting data keys .
     * @return The {@code Keyring}
     */
    public static Keyring awsKms(AwsKmsCmkId generatorKeyId) {
        return new AwsKmsKeyringBuilder()
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
    public static AwsKmsKeyringBuilder awsKms() {
        return new AwsKmsKeyringBuilder();
    }

    /**
     * Constructs a {@code Keyring} which interacts with AWS Key Management Service (KMS) to attempt to
     * decrypt all data keys provided to it. AWS KMS Discovery keyrings do not perform encryption.
     *
     * @return The {@code Keyring}
     */
    public static Keyring awsKmsDiscovery() {
        return new AwsKmsKeyringBuilder().build();
    }

    /**
     * Constructs a {@code Keyring} which combines other keyrings, allowing one OnEncrypt or OnDecrypt call
     * to modify the encryption or decryption materials using more than one keyring.
     *
     * @param generatorKeyring A keyring that can generate data keys. Required if childrenKeyrings is empty.
     * @param childrenKeyrings A list of keyrings to be used to modify the encryption or decryption materials.
     *                         At least one is required if generatorKeyring is null.
     * @return The {@link Keyring}
     */
    public static Keyring multi(Keyring generatorKeyring, List<Keyring> childrenKeyrings) {
        return new MultiKeyring(generatorKeyring, childrenKeyrings);
    }

    /**
     * Constructs a {@code Keyring} which combines other keyrings, allowing one OnEncrypt or OnDecrypt call
     * to modify the encryption or decryption materials using more than one keyring.
     *
     * @param generatorKeyring A keyring that can generate data keys. Required if childrenKeyrings is empty.
     * @param childrenKeyrings Keyrings to be used to modify the encryption or decryption materials.
     *                         At least one is required if generatorKeyring is null.
     * @return The {@link Keyring}
     */
    public static Keyring multi(Keyring generatorKeyring, Keyring... childrenKeyrings) {
        return new MultiKeyring(generatorKeyring, Arrays.asList(childrenKeyrings));
    }
}
