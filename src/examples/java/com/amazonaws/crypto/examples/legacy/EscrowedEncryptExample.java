// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.legacy;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoOutputStream;
import com.amazonaws.encryptionsdk.MasterKeyProvider;
import com.amazonaws.encryptionsdk.jce.JceMasterKey;
import com.amazonaws.encryptionsdk.kms.KmsMasterKeyProvider;
import com.amazonaws.encryptionsdk.multi.MultipleProviderFactory;
import com.amazonaws.util.IOUtils;

/**
 * <p>
 * Encrypts a file using both AWS KMS and an asymmetric key pair.
 * NOTE: Master key providers are deprecated and replaced by keyrings.
 *       We keep these older examples as reference material,
 *       but we recommend that you use the new examples in examples/keyring
 *       The new examples reflect our current guidance for using the library.
 *
 * <p>
 * Arguments:
 * <ol>
 * <li>Key ARN: For help finding the Amazon Resource Name (ARN) of your AWS KMS customer master
 *    key (CMK), see 'Viewing Keys' at http://docs.aws.amazon.com/kms/latest/developerguide/viewing-keys.html
 *
 * <li>Name of file containing plaintext data to encrypt
 * </ol>
 *
 * You might use AWS Key Management Service (AWS KMS) for most encryption and decryption operations, but
 * still want the option of decrypting your data offline independently of AWS KMS. This sample
 * demonstrates one way to do this.
 *
 * The sample encrypts data under both an AWS KMS customer master key (CMK) and an "escrowed" RSA key pair
 * so that either key alone can decrypt it. You might commonly use the AWS KMS CMK for decryption. However,
 * at any time, you can use the private RSA key to decrypt the ciphertext independent of AWS KMS.
 *
 * This sample uses the JCEMasterKey class to generate an RSA public-private key pair
 * and saves the key pair in memory. In practice, you would store the private key in a secure offline
 * location, such as an offline HSM, and distribute the public key to your development team.
 *
 */
public class EscrowedEncryptExample {
    private static PublicKey publicEscrowKey;
    private static PrivateKey privateEscrowKey;

    public static void main(final String[] args) throws Exception {
        // This sample generates a new random key for each operation.
        // In practice, you would distribute the public key and save the private key in secure
        // storage.
        generateEscrowKeyPair();

        final String kmsArn = args[0];
        final String fileName = args[1];

        standardEncrypt(kmsArn, fileName);
        standardDecrypt(kmsArn, fileName);

        escrowDecrypt(fileName);
    }

    private static void standardEncrypt(final String kmsArn, final String fileName) throws Exception {
        // Encrypt with the AWS KMS CMK and the escrowed public key
        // 1. Instantiate the AWS Encryption SDK.
        final AwsCrypto crypto = new AwsCrypto();

        // 2. Instantiate a KMS master key provider.
        final KmsMasterKeyProvider kms = new KmsMasterKeyProvider(kmsArn);

        // 3. Instantiate a JCE master key provider.
        // Because the user does not have access to the private escrow key,
        // they pass in "null" for the private key parameter.
        final JceMasterKey escrowPub = JceMasterKey.getInstance(publicEscrowKey, null, "Escrow", "Escrow",
                "RSA/ECB/OAEPWithSHA-512AndMGF1Padding");

        // 4. Combine the providers into a single master key provider.
        final MasterKeyProvider<?> provider = MultipleProviderFactory.buildMultiProvider(kms, escrowPub);

        // 5. Encrypt the file.
        // To simplify the code, we omit the encryption context. Production code should always
        // use an encryption context. For an example, see the other SDK samples.
        final FileInputStream in = new FileInputStream(fileName);
        final FileOutputStream out = new FileOutputStream(fileName + ".encrypted");
        final CryptoOutputStream<?> encryptingStream = crypto.createEncryptingStream(provider, out);

        IOUtils.copy(in, encryptingStream);
        in.close();
        encryptingStream.close();
    }

    private static void standardDecrypt(final String kmsArn, final String fileName) throws Exception {
        // Decrypt with the AWS KMS CMK and the escrow public key. You can use a combined provider,
        // as shown here, or just the KMS master key provider.

        // 1. Instantiate the AWS Encryption SDK.
        final AwsCrypto crypto = new AwsCrypto();

        // 2. Instantiate a KMS master key provider.
        final KmsMasterKeyProvider kms = new KmsMasterKeyProvider(kmsArn);

        // 3. Instantiate a JCE master key provider.
        // Because the user does not have access to the private
        // escrow key, they pass in "null" for the private key parameter.
        final JceMasterKey escrowPub = JceMasterKey.getInstance(publicEscrowKey, null, "Escrow", "Escrow",
                "RSA/ECB/OAEPWithSHA-512AndMGF1Padding");

        // 4. Combine the providers into a single master key provider.
        final MasterKeyProvider<?> provider = MultipleProviderFactory.buildMultiProvider(kms, escrowPub);

        // 5. Decrypt the file.
        // To simplify the code, we omit the encryption context. Production code should always
        // use an encryption context. For an example, see the other SDK samples.
        final FileInputStream in = new FileInputStream(fileName + ".encrypted");
        final FileOutputStream out = new FileOutputStream(fileName + ".decrypted");
        final CryptoOutputStream<?> decryptingStream = crypto.createDecryptingStream(provider, out);
        IOUtils.copy(in, decryptingStream);
        in.close();
        decryptingStream.close();
    }

    private static void escrowDecrypt(final String fileName) throws Exception {
        // You can decrypt the stream using only the private key.
        // This method does not call AWS KMS.

        // 1. Instantiate the AWS Encryption SDK.
        final AwsCrypto crypto = new AwsCrypto();

        // 2. Instantiate a JCE master key provider.
        // This method call uses the escrowed private key, not null.
        final JceMasterKey escrowPriv = JceMasterKey.getInstance(publicEscrowKey, privateEscrowKey, "Escrow", "Escrow",
                "RSA/ECB/OAEPWithSHA-512AndMGF1Padding");

        // 3. Decrypt the file.
        // To simplify the code, we omit the encryption context. Production code should always
        // use an encryption context. For an example, see the other SDK samples.
        final FileInputStream in = new FileInputStream(fileName + ".encrypted");
        final FileOutputStream out = new FileOutputStream(fileName + ".deescrowed");
        final CryptoOutputStream<?> decryptingStream = crypto.createDecryptingStream(escrowPriv, out);
        IOUtils.copy(in, decryptingStream);
        in.close();
        decryptingStream.close();

    }

    private static void generateEscrowKeyPair() throws GeneralSecurityException {
        final KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA");
        // The National Institute of Standards and Technology (NIST) recommends a minimum of 2048-bit keys for RSA.
        // https://www.nist.gov/publications/transitioning-use-cryptographic-algorithms-and-key-lengths
        kg.initialize(4096);
        final KeyPair keyPair = kg.generateKeyPair();
        publicEscrowKey = keyPair.getPublic();
        privateEscrowKey = keyPair.getPrivate();

    }
}
