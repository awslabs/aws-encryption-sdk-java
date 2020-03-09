/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package com.amazonaws.encryptionsdk.model;

public enum RsaPaddingScheme {

    PKCS1("RSA/ECB/PKCS1Padding"),
    OAEP_SHA1_MGF1("RSA/ECB/OAEPWithSHA-1AndMGF1Padding"),
    OAEP_SHA256_MGF1("RSA/ECB/OAEPWithSHA-256AndMGF1Padding"),
    OAEP_SHA384_MGF1("RSA/ECB/OAEPWithSHA-384AndMGF1Padding"),
    OAEP_SHA512_MGF1("RSA/ECB/OAEPWithSHA-512AndMGF1Padding");

    private final String transformation;

    RsaPaddingScheme(String transformation) {
        this.transformation = transformation;
    }

    /**
     * The Cipher transformation standard name as specified in
     * https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Cipher
     *
     * @return The transformation name
     */
    public String getTransformation() {
        return transformation;
    }
}
