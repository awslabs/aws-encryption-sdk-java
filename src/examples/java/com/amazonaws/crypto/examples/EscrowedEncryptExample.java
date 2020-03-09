/*
 * Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.DecryptRequest;
import com.amazonaws.encryptionsdk.EncryptRequest;
import com.amazonaws.encryptionsdk.keyrings.Keyring;
import com.amazonaws.encryptionsdk.keyrings.RawRsaKeyringBuilder.RsaPaddingScheme;
import com.amazonaws.encryptionsdk.keyrings.StandardKeyrings;
import com.amazonaws.encryptionsdk.kms.AwsKmsCmkId;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

/**
 * <p>
 * Encrypts data using both KMS and an asymmetric key pair.
 *
 * <p>
 * Arguments:
 * <ol>
 * <li>Key ARN: For help finding the Amazon Resource Name (ARN) of your KMS customer master
 *    key (CMK), see 'Viewing Keys' at http://docs.aws.amazon.com/kms/latest/developerguide/viewing-keys.html
 * </ol>
 *
 * You might use AWS Key Management Service (KMS) for most encryption and decryption operations, but
 * still want the option of decrypting your data offline independently of KMS. This sample
 * demonstrates one way to do this.
 *
 * The sample encrypts data under both a KMS customer master key (CMK) and an "escrowed" RSA key pair
 * so that either key alone can decrypt it. You might commonly use the KMS CMK for decryption. However,
 * at any time, you can use the private RSA key to decrypt the ciphertext independent of KMS.
 *
 * This sample uses a RawRsaKeyring to generate a RSA public-private key pair
 * and saves the key pair in memory. In practice, you would store the private key in a secure offline
 * location, such as an offline HSM, and distribute the public key to your development team.
 *
 */
public class EscrowedEncryptExample {
    private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

    public static void main(final String[] args) throws GeneralSecurityException {
        escrowEncryptAndDecrypt(AwsKmsCmkId.fromString(args[0]));
    }

    static void escrowEncryptAndDecrypt(AwsKmsCmkId kmsArn) throws GeneralSecurityException {
        // This sample generates a new random key for each operation.
        // In practice, you would distribute the public key and save the private key in secure storage.
        final KeyPair escrowKeyPair = generateEscrowKeyPair();

        // Encrypt the data under both a KMS Key and an escrowed RSA Key
        byte[] encryptedData = standardEncrypt(kmsArn, escrowKeyPair.getPublic());

        // Decrypt the data using the KMS Key
        byte[] standardDecryptedData = standardDecrypt(kmsArn, encryptedData);

        // Decrypt the data using the escrowed RSA Key
        byte[] escrowedDecryptedData = escrowDecrypt(encryptedData, escrowKeyPair.getPrivate());

        // Verify both decrypted data instances are the same as the original plaintext
        assert Arrays.equals(standardDecryptedData, EXAMPLE_DATA);
        assert Arrays.equals(escrowedDecryptedData, EXAMPLE_DATA);
    }

    private static byte[] standardEncrypt(final AwsKmsCmkId kmsArn, final PublicKey publicEscrowKey) {
        // Encrypt with the KMS CMK and the escrowed public key

        // 1. Instantiate the SDK
        final AwsCrypto crypto = new AwsCrypto();

        // 2. Instantiate a KMS keyring, supplying the keyArn as the generator for generating a data key.
        final Keyring kmsKeyring = StandardKeyrings.awsKms(kmsArn);

        // 3. Instantiate a RawRsaKeyring
        //    Because the user does not have access to the private escrow key,
        //    they do not provide the private key parameter.
        final Keyring rsaKeyring = StandardKeyrings.rawRsaBuilder()
                .keyNamespace("Escrow")
                .keyName("Escrow")
                .publicKey(publicEscrowKey)
                .paddingScheme(RsaPaddingScheme.OAEP_SHA512_MGF1)
                .build();

        // 4. Combine the providers into a single MultiKeyring
        final Keyring keyring = StandardKeyrings.multi(kmsKeyring, rsaKeyring);

        // 5. Encrypt the data with the keyring.
        //    To simplify the code, we omit the encryption context. Production code should always
        //    use an encryption context. For an example, see the other SDK samples.
        return crypto.encrypt(EncryptRequest.builder()
                .keyring(keyring)
                .plaintext(EXAMPLE_DATA).build())
                .getResult();
    }

    private static byte[] standardDecrypt(final AwsKmsCmkId kmsArn, final byte[] cipherText) {
        // Decrypt with the KMS CMK

        // 1. Instantiate the SDK
        final AwsCrypto crypto = new AwsCrypto();

        // 2. Instantiate a KMS keyring, supplying the keyArn as the generator for generating a data key.
        final Keyring kmsKeyring = StandardKeyrings.awsKms(kmsArn);

        // 4. Decrypt the data with the keyring.
        //    To simplify the code, we omit the encryption context. Production code should always
        //    use an encryption context. For an example, see the other SDK samples.
        return crypto.decrypt(DecryptRequest.builder()
                .keyring(kmsKeyring)
                .ciphertext(cipherText).build()).getResult();
    }

    private static byte[] escrowDecrypt(final byte[] cipherText, final PrivateKey privateEscrowKey) {
        // You can decrypt the stream using only the private key.
        // This method does not call KMS.

        // 1. Instantiate the SDK
        final AwsCrypto crypto = new AwsCrypto();

        // 2. Instantiate a RawRsaKeyring using the escrowed private key
        final Keyring rsaKeyring = StandardKeyrings.rawRsaBuilder()
                .keyNamespace("Escrow")
                .keyName("Escrow")
                .privateKey(privateEscrowKey)
                .paddingScheme(RsaPaddingScheme.OAEP_SHA512_MGF1)
                .build();

        // 3. Decrypt the data with the keyring
        //    To simplify the code, we omit the encryption context. Production code should always
        //    use an encryption context. For an example, see the other SDK samples.
        return crypto.decrypt(DecryptRequest.builder()
                .keyring(rsaKeyring)
                .ciphertext(cipherText).build()).getResult();
    }

    private static KeyPair generateEscrowKeyPair() throws GeneralSecurityException {
        final KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA");
        kg.initialize(4096); // Escrow keys should be very strong
        return kg.generateKeyPair();
    }
}
