// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.cryptomaterialsmanager.custom;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.AwsCryptoResult;
import com.amazonaws.encryptionsdk.CryptoMaterialsManager;
import com.amazonaws.encryptionsdk.DecryptRequest;
import com.amazonaws.encryptionsdk.DefaultCryptoMaterialsManager;
import com.amazonaws.encryptionsdk.EncryptRequest;
import com.amazonaws.encryptionsdk.keyrings.Keyring;
import com.amazonaws.encryptionsdk.keyrings.StandardKeyrings;
import com.amazonaws.encryptionsdk.kms.AwsKmsCmkId;
import com.amazonaws.encryptionsdk.model.DecryptionMaterials;
import com.amazonaws.encryptionsdk.model.DecryptionMaterialsRequest;
import com.amazonaws.encryptionsdk.model.EncryptionMaterials;
import com.amazonaws.encryptionsdk.model.EncryptionMaterialsRequest;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Encryption context is a powerful tool for access and audit controls
 * because it lets you tie *non-secret* metadata about a plaintext value to the encrypted message.
 * Within the AWS Encryption SDK,
 * you can use cryptographic materials managers to analyse the encryption context
 * to provide logical controls and additional metadata.
 * <p>
 * https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#encryption-context
 * <p>
 * If you are using the AWS Encryption SDK with AWS KMS,
 * you can use AWS KMS to provide additional powerful controls using the encryption context.
 * For more information on that, see the KMS developer guide:
 * <p>
 * https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#encrypt_context
 * <p>
 * This example shows how to create a custom cryptographic materials manager (CMM)
 * that requires a particular field in the encryption context.
 */
public class RequiringEncryptionContextFields {

    /**
     * Indicates that an encryption context was found that lacked a classification identifier.
     */
    static class MissingClassificationException extends RuntimeException {
        MissingClassificationException() {
            super("Encryption context does not contain classification!");
        }
    }

    /**
     * Only allow requests when the encryption context contains a classification identifier.
     */
    static class ClassificationRequiringCryptoMaterialsManager implements CryptoMaterialsManager {

        private final CryptoMaterialsManager cmm;
        private static final String CLASSIFICATION_KEY = "classification";

        ClassificationRequiringCryptoMaterialsManager(Keyring keyring) {
            // Wrap the provided keyring in the default cryptographic materials manager (CMM).
            //
            // This is the same thing that the encrypt and decrypt APIs, as well as the caching CMM,
            // do if you provide a keyring instead of a CMM.
            cmm = new DefaultCryptoMaterialsManager(keyring);
        }

        /**
         * Block any requests that do not contain a classification identifier in the encryption context.
         */
        @Override
        public EncryptionMaterials getMaterialsForEncrypt(EncryptionMaterialsRequest request) {
            if (!request.getContext().containsKey(CLASSIFICATION_KEY)) {
                throw new MissingClassificationException();
            }

            return cmm.getMaterialsForEncrypt(request);
        }

        /**
         * Block any requests that do not contain a classification identifier in the encryption context.
         */
        @Override
        public DecryptionMaterials decryptMaterials(DecryptionMaterialsRequest request) {
            if (!request.getEncryptionContext().containsKey(CLASSIFICATION_KEY)) {
                throw new MissingClassificationException();
            }

            return cmm.decryptMaterials(request);
        }
    }


    /**
     * Demonstrate an encrypt/decrypt cycle using a custom cryptographic materials manager that filters requests.
     *
     * @param awsKmsCmk       The ARN of an AWS KMS CMK that protects data keys
     * @param sourcePlaintext Plaintext to encrypt
     */
    public static void run(final AwsKmsCmkId awsKmsCmk, final byte[] sourcePlaintext) {
        // Instantiate the AWS Encryption SDK.
        final AwsCrypto awsEncryptionSdk = new AwsCrypto();

        // Prepare your encryption context.
        // https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#encryption-context
        final Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("encryption", "context");
        encryptionContext.put("is not", "secret");
        encryptionContext.put("but adds", "useful metadata");
        encryptionContext.put("that can help you", "be confident that");
        encryptionContext.put("the data you are handling", "is what you think it is");

        // Create the keyring that determines how your data keys are protected.
        final Keyring keyring = StandardKeyrings.awsKms(awsKmsCmk);

        // Create the classification requiring cryptographic materials manager using your keyring.
        final CryptoMaterialsManager cmm = new ClassificationRequiringCryptoMaterialsManager(keyring);

        // Demonstrate that the classification requiring CMM will not let you encrypt without a classification identifier.
        try {
            awsEncryptionSdk.encrypt(
                    EncryptRequest.builder()
                            .cryptoMaterialsManager(cmm)
                            .encryptionContext(encryptionContext)
                            .plaintext(sourcePlaintext).build());
            // The classification requiring CMM keeps this from happening.
            throw new AssertionError("The classification requiring CMM does not let this happen!");
        } catch (MissingClassificationException ex) {
            // Your encryption context did not contain a classification identifier.
            // Reaching this point means everything is working as expected.
        }

        // Create an encryption context with the required classification key.
        final Map<String, String> classifiedEncryptionContext = new HashMap<>(encryptionContext);
        classifiedEncryptionContext.put("classification", "secret");

        // Encrypt your plaintext data.
        final AwsCryptoResult<byte[]> encryptResult = awsEncryptionSdk.encrypt(
                EncryptRequest.builder()
                        .cryptoMaterialsManager(cmm)
                        .encryptionContext(classifiedEncryptionContext)
                        .plaintext(sourcePlaintext).build());
        final byte[] ciphertext = encryptResult.getResult();

        // Demonstrate that the ciphertext and plaintext are different.
        assert !Arrays.equals(ciphertext, sourcePlaintext);

        // Decrypt your encrypted data using the same cryptographic materials manager you used on encrypt.
        //
        // You do not need to specify the encryption context on decrypt because
        // the header of the encrypted message includes the encryption context.
        final AwsCryptoResult<byte[]> decryptResult = awsEncryptionSdk.decrypt(
                DecryptRequest.builder()
                        .cryptoMaterialsManager(cmm)
                        .ciphertext(ciphertext).build());
        final byte[] decrypted = decryptResult.getResult();

        // Demonstrate that the decrypted plaintext is identical to the original plaintext.
        assert Arrays.equals(decrypted, sourcePlaintext);

        // Verify that the encryption context used in the decrypt operation includes
        // the encryption context that you specified when encrypting.
        // The AWS Encryption SDK can add pairs, so don't require an exact match.
        //
        // In production, always use a meaningful encryption context.
        encryptionContext.forEach((k, v) -> {
            assert v.equals(decryptResult.getEncryptionContext().get(k));
        });

        // Now demonstrate the decrypt path of the classification requiring cryptographic materials manager.

        // Encrypt your plaintext using the keyring and do not include a classification identifier.
        final AwsCryptoResult<byte[]> unclassifiedEncryptResult = awsEncryptionSdk.encrypt(
                EncryptRequest.builder()
                        .keyring(keyring)
                        .encryptionContext(encryptionContext)
                        .plaintext(sourcePlaintext).build());
        final byte[] unclassifiedCiphertext = unclassifiedEncryptResult.getResult();

        assert !unclassifiedEncryptResult.getEncryptionContext().containsKey("classification");

        // Demonstrate that the classification requiring CMM
        // will not let you decrypt messages without classification identifiers.
        try {
            awsEncryptionSdk.decrypt(
                    DecryptRequest.builder()
                            .cryptoMaterialsManager(cmm)
                            .ciphertext(unclassifiedCiphertext).build());
            // The classification requiring CMM keeps this from happening.
            throw new AssertionError("The classification requiring CMM does not let this happen!");
        } catch (MissingClassificationException ex) {
            // Your encryption context did not contain a classification identifier.
            // Reaching this point means everything is working as expected.
        }
    }
}
