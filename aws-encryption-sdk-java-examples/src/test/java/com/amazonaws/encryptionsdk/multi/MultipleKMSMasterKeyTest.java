/*
 * Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package com.amazonaws.encryptionsdk.multi;

import static com.amazonaws.encryptionsdk.internal.RandomBytesGenerator.generate;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import javax.crypto.spec.SecretKeySpec;

import org.junit.Test;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoResult;
import com.amazonaws.encryptionsdk.MasterKey;
import com.amazonaws.encryptionsdk.MasterKeyProvider;
import com.amazonaws.encryptionsdk.internal.MockKmsProvider;
import com.amazonaws.encryptionsdk.jce.JceMasterKey;
import com.amazonaws.encryptionsdk.kms.KmsMasterKey;
import com.amazonaws.encryptionsdk.kms.KmsMasterKeyProvider;
import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.kms.MockKMSClient;

public class MultipleKMSMasterKeyTest {
    private static final String WRAPPING_ALG = "AES/GCM/NoPadding";
    private static final byte[] PLAINTEXT = generate(1024);

    @Test
    public void testMultipleKmsKeys() {
        final MockKMSClient kms = new MockKMSClient();
        final String arn1 = kms.createKey().getKeyMetadata().getArn();
        final String arn2 = kms.createKey().getKeyMetadata().getArn();
        MasterKeyProvider<KmsMasterKey> prov = new MockKmsProvider(kms, arn1, arn2);
        KmsMasterKey mk1 = prov.getMasterKey(arn1);

        AwsCrypto crypto = new AwsCrypto();
        CryptoResult<byte[], KmsMasterKey> ct = crypto.encryptData(prov, PLAINTEXT);
        assertEquals(2, ct.getMasterKeyIds().size());
        CryptoResult<byte[], KmsMasterKey> result = crypto.decryptData(prov, ct.getResult());
        assertArrayEquals(PLAINTEXT, result.getResult());
        // Only the first found key should be used
        assertEquals(1, result.getMasterKeys().size());
        assertEquals(mk1, result.getMasterKeys().get(0));
    }

    @Test
    public void testMultipleKmsKeysSingleDecrypt() {
        final MockKMSClient kms = new MockKMSClient();
        final String arn1 = kms.createKey().getKeyMetadata().getArn();
        final String arn2 = kms.createKey().getKeyMetadata().getArn();
        MasterKeyProvider<KmsMasterKey> prov = new MockKmsProvider(kms, arn1, arn2);
        KmsMasterKey mk1 = prov.getMasterKey(arn1);
        KmsMasterKey mk2 = prov.getMasterKey(arn2);

        AwsCrypto crypto = new AwsCrypto();
        CryptoResult<byte[], KmsMasterKey> ct = crypto.encryptData(prov, PLAINTEXT);
        assertEquals(2, ct.getMasterKeyIds().size());

        CryptoResult<byte[], KmsMasterKey> result = crypto.decryptData(mk1, ct.getResult());
        assertArrayEquals(PLAINTEXT, result.getResult());
        assertEquals(1, result.getMasterKeys().size());
        assertEquals(mk1, result.getMasterKeys().get(0));

        result = crypto.decryptData(mk2, ct.getResult());
        assertArrayEquals(PLAINTEXT, result.getResult());
        assertEquals(1, result.getMasterKeys().size());
        assertEquals(mk2, result.getMasterKeys().get(0));

        // Delete one of the two keys and ensure it's still decryptable
        kms.deleteKey(arn1);

        result = crypto.decryptData(prov, ct.getResult());
        assertArrayEquals(PLAINTEXT, result.getResult());
        // Only the first found key should be used
        assertEquals(1, result.getMasterKeys().size());
        assertEquals(mk2, result.getMasterKeys().get(0));
    }

    @Test
    public void testMultipleRegionKmsKeys() {
        final MockKMSClient us_east_1 = new MockKMSClient();
        us_east_1.setRegion(Region.getRegion(Regions.US_EAST_1));
        final MockKMSClient eu_west_1 = new MockKMSClient();
        eu_west_1.setRegion(Region.getRegion(Regions.EU_WEST_1));
        final String arn1 = us_east_1.createKey().getKeyMetadata().getArn();
        final String arn2 = eu_west_1.createKey().getKeyMetadata().getArn();
        KmsMasterKeyProvider provE = new MockKmsProvider(us_east_1);
        provE.setRegion(Region.getRegion(Regions.US_EAST_1));
        KmsMasterKeyProvider provW = new MockKmsProvider(eu_west_1);
        provW.setRegion(Region.getRegion(Regions.EU_WEST_1));
        KmsMasterKey mk1 = provE.getMasterKey(arn1);
        KmsMasterKey mk2 = provW.getMasterKey(arn2);

        final MasterKeyProvider<KmsMasterKey> mkp = MultipleProviderFactory.buildMultiProvider(KmsMasterKey.class,
                mk1, mk2);
        AwsCrypto crypto = new AwsCrypto();
        CryptoResult<byte[], KmsMasterKey> ct = crypto.encryptData(mkp, PLAINTEXT);
        assertEquals(2, ct.getMasterKeyIds().size());

        CryptoResult<byte[], KmsMasterKey> result = crypto.decryptData(mk1, ct.getResult());
        assertArrayEquals(PLAINTEXT, result.getResult());
        assertEquals(1, result.getMasterKeys().size());
        assertEquals(mk1, result.getMasterKeys().get(0));

        result = crypto.decryptData(mk2, ct.getResult());
        assertArrayEquals(PLAINTEXT, result.getResult());
        assertEquals(1, result.getMasterKeys().size());
        assertEquals(mk2, result.getMasterKeys().get(0));

        assertMultiReturnsKeys(mkp, mk1, mk2);

        // Delete one of the two keys and ensure it's still decryptable
        us_east_1.deleteKey(arn1);

        result = crypto.decryptData(mkp, ct.getResult());
        assertArrayEquals(PLAINTEXT, result.getResult());
        // Only the first found key should be used
        assertEquals(1, result.getMasterKeys().size());
        assertEquals(mk2, result.getMasterKeys().get(0));
    }

    @Test
    public void testMixedKeys() {
        final SecretKeySpec k1 = new SecretKeySpec(generate(32), "AES");
        final JceMasterKey mk1 = JceMasterKey.getInstance(k1, "jce", "1", WRAPPING_ALG);
        final MockKMSClient kms = new MockKMSClient();
        final String arn2 = kms.createKey().getKeyMetadata().getArn();
        MasterKeyProvider<KmsMasterKey> prov = new MockKmsProvider(kms);
        KmsMasterKey mk2 = prov.getMasterKey(arn2);
        final MasterKeyProvider<?> mkp = MultipleProviderFactory.buildMultiProvider(mk1, mk2);

        AwsCrypto crypto = new AwsCrypto();
        CryptoResult<byte[], ?> ct = crypto.encryptData(mkp, PLAINTEXT);
        assertEquals(2, ct.getMasterKeyIds().size());
        CryptoResult<byte[], ?> result = crypto.decryptData(mkp, ct.getResult());
        assertArrayEquals(PLAINTEXT, result.getResult());
        // Only the first found key should be used
        assertEquals(1, result.getMasterKeys().size());
        assertEquals(mk1, result.getMasterKeys().get(0));

        assertMultiReturnsKeys(mkp, mk1, mk2);
    }

    @Test
    public void testMixedKeysSingleDecrypt() {
        final SecretKeySpec k1 = new SecretKeySpec(generate(32), "AES");
        final JceMasterKey mk1 = JceMasterKey.getInstance(k1, "jce", "1", WRAPPING_ALG);
        final MockKMSClient kms = new MockKMSClient();
        final String arn2 = kms.createKey().getKeyMetadata().getArn();
        MasterKeyProvider<KmsMasterKey> prov = new MockKmsProvider(kms);
        KmsMasterKey mk2 = prov.getMasterKey(arn2);
        final MasterKeyProvider<?> mkp = MultipleProviderFactory.buildMultiProvider(mk1, mk2);

        AwsCrypto crypto = new AwsCrypto();
        CryptoResult<byte[], ?> ct = crypto.encryptData(mkp, PLAINTEXT);
        assertEquals(2, ct.getMasterKeyIds().size());

        CryptoResult<byte[], ?> result = crypto.decryptData(mk1, ct.getResult());
        assertArrayEquals(PLAINTEXT, result.getResult());
        // Only the first found key should be used
        assertEquals(1, result.getMasterKeys().size());
        assertEquals(mk1, result.getMasterKeys().get(0));

        result = crypto.decryptData(mk2, ct.getResult());
        assertArrayEquals(PLAINTEXT, result.getResult());
        // Only the first found key should be used
        assertEquals(1, result.getMasterKeys().size());
        assertEquals(mk2, result.getMasterKeys().get(0));
    }

    private void assertMultiReturnsKeys(MasterKeyProvider<?> mkp, MasterKey<?>... mks) {
        for (MasterKey<?> mk : mks) {
            assertEquals(mk, mkp.getMasterKey(mk.getKeyId()));
            assertEquals(mk, mkp.getMasterKey(mk.getProviderId(), mk.getKeyId()));
        }
    }
}