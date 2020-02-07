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

package com.amazonaws.crypto.examples;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.AwsCryptoResult;
import com.amazonaws.encryptionsdk.DecryptRequest;
import com.amazonaws.encryptionsdk.EncryptRequest;
import com.amazonaws.encryptionsdk.keyrings.Keyring;
import com.amazonaws.encryptionsdk.keyrings.StandardKeyrings;
import com.amazonaws.encryptionsdk.kms.AwsKmsCmkId;

/**
 * <p>
 * Encrypts and then decrypts data using an AWS KMS customer master key.
 *
 * <p>
 * Arguments:
 * <ol>
 * <li>Key ARN: For help finding the Amazon Resource Name (ARN) of your KMS customer master
 *    key (CMK), see 'Viewing Keys' at http://docs.aws.amazon.com/kms/latest/developerguide/viewing-keys.html
 * </ol>
 */
public class BasicEncryptionExample {

    private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

    public static void main(final String[] args) {
        encryptAndDecrypt(AwsKmsCmkId.fromString(args[0]));
    }

    static void encryptAndDecrypt(final AwsKmsCmkId keyArn) {
        // 1. Instantiate the SDK
        final AwsCrypto crypto = new AwsCrypto();

        // 2. Instantiate an AWS KMS Keyring, supplying the key ARN as the generator for generating a data key. While
        //    using a key ARN is a best practice, for encryption operations it is also acceptable to use a CMK alias or
        //    an alias ARN.
        final Keyring keyring = StandardKeyrings.awsKms(keyArn);

        // 3. Create an encryption context
        //
        //    Most encrypted data should have an associated encryption context
        //    to protect integrity. This sample uses placeholder values.
        //
        //    For more information see:
        //    blogs.aws.amazon.com/security/post/Tx2LZ6WBJJANTNW/How-to-Protect-the-Integrity-of-Your-Encrypted-Data-by-Using-AWS-Key-Management
        final Map<String, String> encryptionContext = Collections.singletonMap("ExampleContextKey", "ExampleContextValue");

        // 4. Encrypt the data with the keyring and encryption context
        final AwsCryptoResult<byte[]> encryptResult = crypto.encrypt(
                EncryptRequest.builder()
                    .keyring(keyring)
                    .encryptionContext(encryptionContext)
                    .plaintext(EXAMPLE_DATA).build());
        final byte[] ciphertext = encryptResult.getResult();

        // 5. Decrypt the data. The same keyring may be used to encrypt and decrypt, but for decryption
        //    the key IDs must be in the key ARN format.
        final AwsCryptoResult<byte[]> decryptResult = crypto.decrypt(
                DecryptRequest.builder()
                        .keyring(keyring)
                        .ciphertext(ciphertext).build());

        // 6. The Keyring Trace may be inspected to verify which CMK was used for decryption.
        if(!decryptResult.getKeyringTrace().getEntries().get(0).getKeyName().equals(keyArn.toString())) {
            throw new IllegalStateException("Wrong key ID!");
        }

        // 7. Verify that the encryption context in the result contains the
        //    data that we expect. The SDK can add values to the encryption context,
        //    so there may be additional keys in the result context.
        assert decryptResult.getEncryptionContext().get("ExampleContextKey").equals("ExampleContextValue");

        // 8. Verify that the decrypted plaintext matches the original plaintext
        assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);
    }
}
