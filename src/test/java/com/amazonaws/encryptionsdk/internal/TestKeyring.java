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

package com.amazonaws.encryptionsdk.internal;

import com.amazonaws.encryptionsdk.EncryptedDataKey;
import com.amazonaws.encryptionsdk.keyrings.Keyring;
import com.amazonaws.encryptionsdk.keyrings.KeyringTraceEntry;
import com.amazonaws.encryptionsdk.keyrings.KeyringTraceFlag;
import com.amazonaws.encryptionsdk.model.DecryptionMaterials;
import com.amazonaws.encryptionsdk.model.EncryptionMaterials;
import com.amazonaws.encryptionsdk.model.KeyBlob;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.NotThreadSafe;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;

import static com.amazonaws.encryptionsdk.EncryptedDataKey.PROVIDER_ENCODING;
import static java.util.Objects.requireNonNull;

/**
 * Implementation of the {@link Keyring} interface that should only
 * used for unit-tests.
 * <p>
 * Contains a statically defined asymmetric key-pair that can be used
 * to encrypt and decrypt (randomly generated) symmetric data key.
 * <p>
 * 
 * @author wesleyr
 */
@NotThreadSafe
public class TestKeyring implements Keyring {
    private static final String PROVIDER_ID = "static_provider";

    /**
     * Encryption algorithm for the key-pair
     */
    private static final String ENCRYPTION_ALGORITHM = "RSA/ECB/PKCS1Padding";

    /**
     * Encryption algorithm for the KeyFactory
     */
    private static final String KEY_FACTORY_ALGORITHM = "RSA";

    /**
     * The ID of the key
     */
    private final String keyId_;

    /**
     * The {@link Cipher} object created with the public part of
     * the key. It's used to encrypt data keys.
     */
    private final Cipher keyEncryptionCipher_;

    /**
     * The {@link Cipher} object created with the private part of
     * the key. It's used to decrypt encrypted data keys.
     */
    private final Cipher keyDecryptionCipher_;

    /**
     * Creates a new object that encrypts the data key with a key
     * whose id is {@code keyId}.
     * <p>
     * The value of {@code keyId} does not affect how the data key will be
     * generated or encrypted. The {@code keyId} forms part of the header
     * of the encrypted data, and is used to ensure that the header cannot
     * be tempered with.
     */
    public TestKeyring(@Nonnull final String keyId) {
        this.keyId_ = requireNonNull(keyId);
        
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_FACTORY_ALGORITHM);
            KeySpec publicKeySpec = new X509EncodedKeySpec(publicKey_v1);
            PublicKey pubKey = keyFactory.generatePublic(publicKeySpec);
            KeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKey_v1);
            PrivateKey privKey = keyFactory.generatePrivate(privateKeySpec);
            
            keyEncryptionCipher_ = Cipher.getInstance(ENCRYPTION_ALGORITHM);
            keyEncryptionCipher_.init(Cipher.ENCRYPT_MODE, pubKey);

            keyDecryptionCipher_ = Cipher.getInstance(ENCRYPTION_ALGORITHM);
            keyDecryptionCipher_.init(Cipher.DECRYPT_MODE, privKey);
            
        } catch (GeneralSecurityException ex) {
            throw new RuntimeException(ex);
        }
    }

    @Override
    public EncryptionMaterials onEncrypt(EncryptionMaterials encryptionMaterials) {
        if(!encryptionMaterials.hasCleartextDataKey()) {
            return generateDataKey(encryptionMaterials);
        } else {
            byte[] encryptedKey;
            try {
                encryptedKey = keyEncryptionCipher_.doFinal(encryptionMaterials.getCleartextDataKey().getEncoded());
            } catch (GeneralSecurityException ex) {
                throw new RuntimeException(ex);
            }
            return encryptionMaterials.withEncryptedDataKey(new KeyBlob(PROVIDER_ID, keyId_.getBytes(PROVIDER_ENCODING), encryptedKey),
                    new KeyringTraceEntry(PROVIDER_ID, keyId_, KeyringTraceFlag.ENCRYPTED_DATA_KEY));
        }
    }

    @Override
    public DecryptionMaterials onDecrypt(DecryptionMaterials decryptionMaterials, List<? extends EncryptedDataKey> encryptedDataKeys) {
        try {
            for (EncryptedDataKey edk :encryptedDataKeys) {
                if (keyId_.equals(new String(edk.getProviderInformation(), StandardCharsets.UTF_8))) {
                    byte[] unencryptedDataKey = keyDecryptionCipher_.doFinal(edk.getEncryptedDataKey());
                    SecretKey key = new SecretKeySpec(unencryptedDataKey, decryptionMaterials.getAlgorithm().getDataKeyAlgo());

                    return decryptionMaterials.withCleartextDataKey(key,
                            new KeyringTraceEntry(PROVIDER_ID, keyId_, KeyringTraceFlag.DECRYPTED_DATA_KEY));
                }
            }
        } catch (GeneralSecurityException ex) {
            throw new RuntimeException(ex);
        }

        return decryptionMaterials;
    }

    private EncryptionMaterials generateDataKey(EncryptionMaterials encryptionMaterials) {
        try {
            final byte[] rawKey = new byte[encryptionMaterials.getAlgorithm().getDataKeyLength()];
            Utils.getSecureRandom().nextBytes(rawKey);
            SecretKey key = new SecretKeySpec(rawKey, encryptionMaterials.getAlgorithm().getDataKeyAlgo());
            byte[] encryptedKey = keyEncryptionCipher_.doFinal(key.getEncoded());

            return encryptionMaterials
                    .withCleartextDataKey(key,
                        new KeyringTraceEntry(PROVIDER_ID, keyId_, KeyringTraceFlag.GENERATED_DATA_KEY))
                    .withEncryptedDataKey(new KeyBlob(PROVIDER_ID, keyId_.getBytes(PROVIDER_ENCODING), encryptedKey),
                        new KeyringTraceEntry(PROVIDER_ID, keyId_, KeyringTraceFlag.ENCRYPTED_DATA_KEY));
        } catch (GeneralSecurityException ex) {
            throw new RuntimeException(ex);
        }
    }

    /**
     * Statically configured private key.
     */
    private static final byte[] privateKey_v1 = Utils.decodeBase64String(
            "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAKLpwqjYtYExVilW/Hg0ogWv9xZ+"
    + "THj4IzvISLlPtK8W6KXMcqukfuxdYmndPv8UD1DbdHFYSSistdqoBN32vVQOQnJZyYm45i2TDOV0"
    + "M2DtHtR6aMMlBLGtdPeeaT88nQfI1ORjRDyR1byMwomvmKifZYga6FjLt/sgqfSE9BUnAgMBAAEC"
    + "gYAqnewGL2qLuVRIzDCPYXVg938zqyZmHsNYyDP+BhPGGcASX0FAFW/+dQ9hkjcAk0bOaBo17Fp3"
    + "AXcxE/Lx/bHY+GWZ0wOJfl3aJBVJOpW8J6kwu68BUCmuFtRgbLSFu5+fbey3pKafYSptbX1fAI+z"
    + "hTx+a9B8pnn79ad4ziJ2QQJBAM+YHPGAEbr5qcNkwyy0xZgR/TLlcW2NQUt8HZpmErdX6d328iBC"
    + "SPb8+whXxCXZC3Mr+35IZ1pxxf0go/zGQv0CQQDI5oH0z1CKxoT6ErswNzB0oHxq/wD5mhutyqHa"
    + "mxbG5G3fN7I2IclwaXEA2eutIKxFMQNZYsX5mNYsrveSKivzAkABiujUJpZ7JDXNvObyYxmAyslt"
    + "4mSYYs9UZ0S1DAMhl6amPpqIANYX98NJyZUsjtNV9MK2qoUSF/xXqDFvxG1lAkBhP5Ow2Zn3U1mT"
    + "Y/XQxSZjjjwr3vyt1neHjQsEMwa3iGPXJbLSmVBVZfUZoGOBDsvVQoCIiFOlGuKyBpA45MkZAkAH"
    + "ksUrS9xLrDIUOI2BzMNRsK0bH7KJ+PFxm2SBgJOF9+Uf2A9LIP4IvESZq+ufp6c8YaqgR6Id1vws"
    + "7rUyGoa5");

    /**
     * Statically configured public key.
     */
     private static final byte[] publicKey_v1 = Utils.decodeBase64String(
            "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCi6cKo2LWBMVYpVvx4NKIFr/cWfkx4+CM7yEi5"
    + "T7SvFuilzHKrpH7sXWJp3T7/FA9Q23RxWEkorLXaqATd9r1UDkJyWcmJuOYtkwzldDNg7R7UemjD"
    + "JQSxrXT3nmk/PJ0HyNTkY0Q8kdW8jMKJr5ion2WIGuhYy7f7IKn0hPQVJwIDAQAB");
}
