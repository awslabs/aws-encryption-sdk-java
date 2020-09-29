// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.cryptomaterialsmanager.custom;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.AwsCryptoResult;
import com.amazonaws.encryptionsdk.CryptoAlgorithm;
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
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * The AWS Encryption SDK supports several different algorithm suites
 * that offer different security properties.
 * <p>
 * https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/supported-algorithms.html
 * <p>
 * By default, the AWS Encryption SDK will let you use any of these,
 * but you might want to restrict that further.
 * <p>
 * We recommend that you use the default algorithm suite,
 * which uses AES-GCM with 256-bit keys, HKDF, and ECDSA message signing.
 * If your readers and writers have the same permissions,
 * you might want to omit the message signature for faster operation.
 * For more information about choosing a signed or unsigned algorithm suite,
 * see the AWS Encryption SDK developer guide:
 * <p>
 * https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/supported-algorithms.html#other-algorithms
 * <p>
 * This example shows how you can make a custom cryptographic materials manager (CMM)
 * that only allows encrypt requests that either specify one of these two algorithm suites
 * or do not specify an algorithm suite, in which case the default CMM uses the default algorithm suite.
 */
public class AlgorithmSuiteEnforcement {

    /**
     * Indicates that an unsupported algorithm suite was requested.
     */
    static class UnapprovedAlgorithmSuiteException extends RuntimeException {
        UnapprovedAlgorithmSuiteException() {
            super("Unapproved algorithm suite requested!");
        }
    }

    /**
     * Only allow encryption requests for approved algorithm suites.
     */
    static class RequireApprovedAlgorithmSuitesCryptoMaterialsManager implements CryptoMaterialsManager {

        private final CryptoMaterialsManager cmm;
        private final Set<CryptoAlgorithm> ALLOWED_ALGORITHM_SUITES = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
                CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,  // the default algorithm suite
                CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256)));          // the recommended unsigned algorithm suite

        /**
         * Set up the inner cryptographic materials manager using the provided keyring.
         *
         * @param keyring Keyring to use in the inner cryptographic materials manager
         */
        RequireApprovedAlgorithmSuitesCryptoMaterialsManager(Keyring keyring) {
            // Wrap the provided keyring in the default cryptographic materials manager (CMM).
            //
            // This is the same thing that the encrypt and decrypt APIs, as well as the caching CMM,
            // do if you provide a keyring instead of a CMM.
            cmm = new DefaultCryptoMaterialsManager(keyring);
        }

        /**
         * Block any requests that include an unapproved algorithm suite.
         */
        @Override
        public EncryptionMaterials getMaterialsForEncrypt(EncryptionMaterialsRequest request) {
            if (request.getRequestedAlgorithm() != null && !ALLOWED_ALGORITHM_SUITES.contains(request.getRequestedAlgorithm())) {
                throw new UnapprovedAlgorithmSuiteException();
            }

            return cmm.getMaterialsForEncrypt(request);
        }

        /**
         * Be more permissive on decrypt and just pass through.
         */
        @Override
        public DecryptionMaterials decryptMaterials(DecryptionMaterialsRequest request) {
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
        final AwsCrypto awsEncryptionSdk = AwsCrypto.standard();

        // Prepare your encryption context.
        // Remember that your encryption context is NOT SECRET.
        // https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#encryption-context
        final Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("encryption", "context");
        encryptionContext.put("is not", "secret");
        encryptionContext.put("but adds", "useful metadata");
        encryptionContext.put("that can help you", "be confident that");
        encryptionContext.put("the data you are handling", "is what you think it is");

        // Create the keyring that determines how your data keys are protected.
        final Keyring keyring = StandardKeyrings.awsKmsSymmetricMultiCmk(awsKmsCmk);

        // Create the algorithm suite restricting cryptographic materials manager using your keyring.
        final CryptoMaterialsManager cmm = new RequireApprovedAlgorithmSuitesCryptoMaterialsManager(keyring);

        // Demonstrate that the algorithm suite restricting CMM will not let you use an unapproved algorithm suite.
        awsEncryptionSdk.setEncryptionAlgorithm(CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF);

        try {
            awsEncryptionSdk.encrypt(
                    EncryptRequest.builder()
                            .cryptoMaterialsManager(cmm)
                            .encryptionContext(encryptionContext)
                            .plaintext(sourcePlaintext).build());
            // The algorithm suite restricting CMM keeps this from happening.
            throw new AssertionError("The algorithm suite restricting CMM does not let this happen!");
        } catch (UnapprovedAlgorithmSuiteException ex) {
            // You asked for an unapproved algorithm suite.
            // Reaching this point means everything is working as expected.
        }

        // Set an approved algorithm suite.
        awsEncryptionSdk.setEncryptionAlgorithm(CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384);

        // Encrypt your plaintext data.
        final AwsCryptoResult<byte[]> encryptResult = awsEncryptionSdk.encrypt(
                EncryptRequest.builder()
                        .cryptoMaterialsManager(cmm)
                        .encryptionContext(encryptionContext)
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
    }
}
