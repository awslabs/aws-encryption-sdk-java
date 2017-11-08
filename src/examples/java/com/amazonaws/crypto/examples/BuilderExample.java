package com.amazonaws.crypto.examples;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoResult;
import com.amazonaws.encryptionsdk.kms.KmsMasterKey;
import com.amazonaws.encryptionsdk.kms.KmsMasterKeyProvider;
import com.amazonaws.encryptionsdk.kms.KmsMasterKeyProviderBuilder;

import java.util.Collections;
import java.util.Map;

/**
 * <p>
 * Encrypts and then decrypts a string under a KMS key
 *
 * <p>
 * Arguments:
 * <ol>
 * <li>KMS Key Arn
 * <li>String to encrypt
 * </ol>
 */
public class BuilderExample {

    private static String keyArn;
    private static String data;

    public static void main(final String[] args) {
        keyArn = args[0];
        data = args[1];

        // Instantiate the SDK
        final AwsCrypto crypto = new AwsCrypto();

        // Set up the KmsMasterKeyProvider using the defaults provided by the KmsMasterKeyProviderBuilder
        final KmsMasterKeyProvider prov = KmsMasterKeyProviderBuilder.standard()
                .withKeyId(keyArn)
                .build();

        // Encrypt the data
        //
        // Most encrypted data should have associated encryption context
        // to protect integrity. Here, we'll just use a placeholder value.
        //
        // For more information see:
        // blogs.aws.amazon.com/security/post/Tx2LZ6WBJJANTNW/How-to-Protect-the-Integrity-of-Your-Encrypted-Data-by-Using-AWS-Key-Management
        final Map<String, String> context = Collections.singletonMap("Example", "String");

        final String ciphertext = crypto.encryptString(prov, data, context).getResult();
        System.out.println("Ciphertext: " + ciphertext);

        // Decrypt the data
        final CryptoResult<String, KmsMasterKey> decryptResult = crypto.decryptString(prov, ciphertext);
        // We need to check the encryption context (and ideally key) to ensure that
        // this was the ciphertext we expected
        if (!decryptResult.getMasterKeyIds().get(0).equals(keyArn)) {
            throw new IllegalStateException("Wrong key id!");
        }

        // The SDK may add information to the encryption context, so we check to ensure
        // that all of our values are present
        for (final Map.Entry<String, String> e : context.entrySet()) {
            if (!e.getValue().equals(decryptResult.getEncryptionContext().get(e.getKey()))) {
                throw new IllegalStateException("Wrong Encryption Context!");
            }
        }

        // Now that we know we have the correct data, we can output it.
        System.out.println("Decrypted: " + decryptResult.getResult());
    }
}
