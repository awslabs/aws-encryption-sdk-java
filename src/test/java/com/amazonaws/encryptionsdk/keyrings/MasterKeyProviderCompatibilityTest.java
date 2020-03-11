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

package com.amazonaws.encryptionsdk.keyrings;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.AwsCryptoResult;
import com.amazonaws.encryptionsdk.CryptoResult;
import com.amazonaws.encryptionsdk.DecryptRequest;
import com.amazonaws.encryptionsdk.EncryptRequest;
import com.amazonaws.encryptionsdk.MasterKeyProvider;
import com.amazonaws.encryptionsdk.TestUtils;
import com.amazonaws.encryptionsdk.internal.RandomBytesGenerator;
import com.amazonaws.encryptionsdk.internal.Utils;
import com.amazonaws.encryptionsdk.jce.JceMasterKey;
import com.amazonaws.encryptionsdk.keyrings.RawRsaKeyringBuilder.RsaPaddingScheme;
import com.amazonaws.encryptionsdk.kms.AwsKmsCmkId;
import com.amazonaws.encryptionsdk.kms.KMSTestFixtures;
import com.amazonaws.encryptionsdk.kms.KmsMasterKey;
import com.amazonaws.encryptionsdk.kms.KmsMasterKeyProvider;
import com.amazonaws.encryptionsdk.multi.MultipleProviderFactory;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Collections;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

class MasterKeyProviderCompatibilityTest {

    private static final Map<String, String> ENCRYPTION_CONTEXT = Collections.singletonMap("myKey", "myValue");
    private static final String KEY_NAMESPACE = "TestKeyNamespace";
    private static final String KEY_NAME = "TestKeyName";
    private static final byte[] PLAINTEXT = RandomBytesGenerator.generate(1000);
    private final AwsCrypto awsCrypto = new AwsCrypto();

    @Tag(TestUtils.TAG_INTEGRATION)
    @Test
    void testAwsKmsKeyringCompatibility() {
        MasterKeyProvider<KmsMasterKey> mkp = KmsMasterKeyProvider.builder()
                .withKeysForEncryption(KMSTestFixtures.TEST_KEY_IDS[0]).build();
        Keyring keyring = StandardKeyrings.awsKms(AwsKmsCmkId.fromString(KMSTestFixtures.TEST_KEY_IDS[0]));

        testCompatibility(keyring, mkp);
    }

    @Test
    void testRawAesKeyringCompatibility() {
        SecretKey key = generateRandomKey();

        JceMasterKey mkp = JceMasterKey.getInstance(key, KEY_NAMESPACE, KEY_NAME, "AES/GCM/NoPadding");
        Keyring keyring = StandardKeyrings.rawAesBuilder()
                .keyNamespace(KEY_NAMESPACE)
                .keyName(KEY_NAME)
                .wrappingKey(key)
                .build();

        testCompatibility(keyring, mkp);
    }

    @Test
    void testRawRsaKeyringCompatibility() throws Exception {
        final RsaPaddingScheme paddingScheme = RsaPaddingScheme.OAEP_SHA512_MGF1;
        final KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA");
        kg.initialize(4096);
        KeyPair keyPair = kg.generateKeyPair();

        JceMasterKey mkp = JceMasterKey.getInstance(keyPair.getPublic(), keyPair.getPrivate(), KEY_NAMESPACE, KEY_NAME,
                paddingScheme.getTransformation());
        Keyring keyring = StandardKeyrings.rawRsaBuilder()
                .keyNamespace(KEY_NAMESPACE)
                .keyName(KEY_NAME)
                .publicKey(keyPair.getPublic())
                .privateKey(keyPair.getPrivate())
                .paddingScheme(paddingScheme)
                .build();

        testCompatibility(keyring, mkp);
    }

    @Tag(TestUtils.TAG_INTEGRATION)
    @Test
    void testMultiKeyringCompatibility() {
        SecretKey key = generateRandomKey();
        MasterKeyProvider<KmsMasterKey> mkp1 = KmsMasterKeyProvider.builder()
                .withKeysForEncryption(KMSTestFixtures.TEST_KEY_IDS[0]).build();
        JceMasterKey mkp2 = JceMasterKey.getInstance(key, KEY_NAMESPACE, KEY_NAME, "AES/GCM/NoPadding");

        MasterKeyProvider<?> mkp = MultipleProviderFactory.buildMultiProvider(mkp1, mkp2);

        Keyring keyring1 = StandardKeyrings.awsKms(AwsKmsCmkId.fromString(KMSTestFixtures.TEST_KEY_IDS[0]));
        Keyring keyring2 = StandardKeyrings.rawAesBuilder()
                .keyNamespace(KEY_NAMESPACE)
                .keyName(KEY_NAME)
                .wrappingKey(key)
                .build();

        Keyring keyring = StandardKeyrings.multi(keyring1, keyring2);

        testCompatibility(keyring, mkp);
    }

    private void testCompatibility(Keyring keyring, MasterKeyProvider<?> masterKeyProvider) {
        CryptoResult<byte[], ?> mkpResult = awsCrypto.encryptData(masterKeyProvider, PLAINTEXT, ENCRYPTION_CONTEXT);
        AwsCryptoResult<byte[]> keyringResult = awsCrypto.decrypt(DecryptRequest.builder()
                        .keyring(keyring)
                        .ciphertext(mkpResult.getResult()).build());

        assertArrayEquals(PLAINTEXT, keyringResult.getResult());

        keyringResult = awsCrypto.encrypt(EncryptRequest.builder()
                .keyring(keyring)
                .encryptionContext(ENCRYPTION_CONTEXT)
                .plaintext(PLAINTEXT).build());
        mkpResult = awsCrypto.decryptData(masterKeyProvider, keyringResult.getResult());

        assertArrayEquals(PLAINTEXT, mkpResult.getResult());
    }

    private static SecretKey generateRandomKey() {
        byte[] rawKey = new byte[16]; // 128 bits
        Utils.getSecureRandom().nextBytes(rawKey);
        return new SecretKeySpec(rawKey, "AES");
    }
}
