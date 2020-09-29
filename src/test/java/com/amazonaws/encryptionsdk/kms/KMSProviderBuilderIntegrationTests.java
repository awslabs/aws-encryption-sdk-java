// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk.kms;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.HashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

import com.amazonaws.encryptionsdk.TestUtils;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.Before;
import org.mockito.ArgumentCaptor;

import com.amazonaws.AbortedException;
import com.amazonaws.ClientConfiguration;
import com.amazonaws.Request;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.CryptoResult;
import com.amazonaws.encryptionsdk.EncryptedDataKey;
import com.amazonaws.encryptionsdk.MasterKeyProvider;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.CannotUnwrapDataKeyException;
import com.amazonaws.encryptionsdk.internal.VersionInfo;
import com.amazonaws.encryptionsdk.model.KeyBlob;
import com.amazonaws.encryptionsdk.kms.KmsMasterKeyProvider.RegionalClientSupplier;
import com.amazonaws.handlers.RequestHandler2;
import com.amazonaws.http.exception.HttpRequestTimeoutException;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;

@Tag(TestUtils.TAG_INTEGRATION)
class KMSProviderBuilderIntegrationTests {

    private static final String AWS_KMS_PROVIDER_ID = "aws-kms";

    private AWSKMS testUSWestClient__;
    private AWSKMS testEUCentralClient__;
    private RegionalClientSupplier testClientSupplier__;

    @Before
    void setup() {
        testUSWestClient__ = spy(AWSKMSClientBuilder.standard().withRegion("us-west-2").build());
        testEUCentralClient__ = spy(AWSKMSClientBuilder.standard().withRegion("eu-central-1").build());
        testClientSupplier__ = regionName -> {
            if (regionName.equals("us-west-2")) {
                return testUSWestClient__;
            } else if (regionName.equals("eu-central-1")) {
                return testEUCentralClient__;
            } else {
                throw new AwsCryptoException("test supplier only configured for us-west-2 and eu-central-1");
            }
        };
    }

    @Test
    void whenBogusRegionsDecrypted_doesNotLeakClients() {
        AtomicReference<ConcurrentHashMap<String, AWSKMS>> kmsCache = new AtomicReference<>();

        KmsMasterKeyProvider mkp = (new KmsMasterKeyProvider.Builder() {
            @Override protected void snoopClientCache(
                final ConcurrentHashMap<String, AWSKMS> map
            ) {
                kmsCache.set(map);
            }
        }).buildDiscovery();

        try {
            mkp.decryptDataKey(
                CryptoAlgorithm.ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256,
                Collections.singleton(
                    new KeyBlob("aws-kms",
                        "arn:aws:kms:us-bogus-1:123456789010:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f"
                            .getBytes(StandardCharsets.UTF_8),
                        new byte[40]
                    )
                ),
                new HashMap<>()
            );
            fail("Expected CannotUnwrapDataKeyException");
        } catch (CannotUnwrapDataKeyException e) {
            // ok
        }

        assertTrue(kmsCache.get().isEmpty());
    }

    @Test
    void whenOperationSuccessful_clientIsCached() {
        AtomicReference<ConcurrentHashMap<String, AWSKMS>> kmsCache = new AtomicReference<>();

        KmsMasterKeyProvider mkp = (new KmsMasterKeyProvider.Builder() {
            @Override protected void snoopClientCache(
                final ConcurrentHashMap<String, AWSKMS> map
            ) {
                kmsCache.set(map);
            }
        }).buildStrict(KMSTestFixtures.TEST_KEY_IDS[0]);

        AwsCrypto.standard().encryptData(mkp, new byte[1]);

        AWSKMS kms = kmsCache.get().get("us-west-2");
        assertNotNull(kms);

        AwsCrypto.standard().encryptData(mkp, new byte[1]);

        // Cache entry should stay the same
        assertEquals(kms, kmsCache.get().get("us-west-2"));
    }

    @Test
    void whenConstructedWithoutArguments_canUseMultipleRegions() {
        KmsMasterKeyProvider mkp = KmsMasterKeyProvider.builder().buildDiscovery();

        for (String key : KMSTestFixtures.TEST_KEY_IDS) {
            byte[] ciphertext =
                AwsCrypto.standard().encryptData(
                    KmsMasterKeyProvider.builder()
                        .buildStrict(key),
                    new byte[1]
                ).getResult();

            AwsCrypto.standard().decryptData(mkp, ciphertext);
        }
    }

    @Test
    void whenConstructedInStrictMode_encryptDecrypt() {
        KmsMasterKeyProvider mkp = KmsMasterKeyProvider.builder()
            .withCustomClientFactory(testClientSupplier__)
            .buildStrict(KMSTestFixtures.TEST_KEY_IDS[0]);

        byte[] ciphertext = AwsCrypto.standard().encryptData(mkp, new byte[1]).getResult();
        verify(testUSWestClient__, times(1)).generateDataKey(any());

        AwsCrypto.standard().decryptData(mkp, ciphertext);
        verify(testUSWestClient__, times(1)).decrypt(any());
    }

    @Test
    void whenConstructedInStrictMode_encryptDecryptMultipleCmks() {
        KmsMasterKeyProvider mkp = KmsMasterKeyProvider.builder()
            .withCustomClientFactory(testClientSupplier__)
            .buildStrict(
                KMSTestFixtures.US_WEST_2_KEY_ID,
                KMSTestFixtures.EU_CENTRAL_1_KEY_ID);

        byte[] ciphertext = AwsCrypto.standard().encryptData(mkp, new byte[1]).getResult();
        verify(testUSWestClient__, times(1)).generateDataKey(any());
        verify(testEUCentralClient__, times(1)).encrypt(any());

        AwsCrypto.standard().decryptData(mkp, ciphertext);
        verify(testUSWestClient__, times(1)).decrypt(any());
    }

    @Test
    void whenConstructedInStrictMode_encryptSingleBadKeyIdFails() {
        KmsMasterKeyProvider mkp = KmsMasterKeyProvider.builder()
            .withCustomClientFactory(testClientSupplier__)
            .withDefaultRegion("us-west-2")
            .buildStrict(
                KMSTestFixtures.US_WEST_2_KEY_ID,
                "badKeyId");

        assertThrows(AwsCryptoException.class, () -> AwsCrypto.standard().encryptData(mkp, new byte[1]).getResult());
        verify(testUSWestClient__, times(1)).generateDataKey(any());
        verify(testUSWestClient__, times(1)).encrypt(any());
    }

    @Test
    void whenConstructedInStrictMode_decryptBadEDKFails() {
        KmsMasterKeyProvider mkp = KmsMasterKeyProvider.builder()
            .withCustomClientFactory(testClientSupplier__)
            .withDefaultRegion("us-west-2")
            .buildStrict("badKeyId");

        final CryptoAlgorithm algSuite = CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;
        final Map<String, String> encCtx = Collections.singletonMap("myKey", "myValue");
        final EncryptedDataKey badEDK = new KeyBlob(AWS_KMS_PROVIDER_ID,
            "badKeyId".getBytes(StandardCharsets.UTF_8), new byte[algSuite.getDataKeyLength()]);

        assertThrows(CannotUnwrapDataKeyException.class, () ->
            mkp.decryptDataKey(algSuite, Collections.singletonList(badEDK), encCtx));
        verify(testUSWestClient__, times(1)).decrypt(any());
    }

    @Test
    void whenConstructedInDiscoveryMode_decrypt() {
        KmsMasterKeyProvider singleCmkMkp = KmsMasterKeyProvider.builder()
            .withCustomClientFactory(testClientSupplier__)
            .buildStrict(KMSTestFixtures.TEST_KEY_IDS[0]);
        byte[] singleCmkCiphertext = AwsCrypto.standard().encryptData(singleCmkMkp, new byte[1]).getResult();

        KmsMasterKeyProvider mkpToTest = KmsMasterKeyProvider.builder()
            .withCustomClientFactory(testClientSupplier__)
            .buildDiscovery();
        AwsCrypto.standard().decryptData(mkpToTest, singleCmkCiphertext);
        verify(testUSWestClient__, times(1)).decrypt(any());
    }

    @Test
    void whenConstructedInDiscoveryMode_decryptBadEDKFails() {
        KmsMasterKeyProvider mkp = KmsMasterKeyProvider.builder()
            .withCustomClientFactory(testClientSupplier__)
            .withDefaultRegion("us-west-2")
            .buildDiscovery();

        final CryptoAlgorithm algSuite = CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;
        final Map<String, String> encCtx = Collections.singletonMap("myKey", "myValue");
        final EncryptedDataKey badEDK = new KeyBlob(AWS_KMS_PROVIDER_ID,
            "badKeyId".getBytes(StandardCharsets.UTF_8), new byte[algSuite.getDataKeyLength()]);

        assertThrows(CannotUnwrapDataKeyException.class, () ->
            mkp.decryptDataKey(algSuite, Collections.singletonList(badEDK), encCtx));
        verify(testUSWestClient__, times(1)).decrypt(any());
    }


    @Test
    void whenConstructedWithDiscoveryFilter_decrypt() {
        KmsMasterKeyProvider singleCmkMkp = KmsMasterKeyProvider.builder()
            .withCustomClientFactory(testClientSupplier__)
            .buildStrict(KMSTestFixtures.TEST_KEY_IDS[0]);

        byte[] singleCmkCiphertext = AwsCrypto.standard().encryptData(singleCmkMkp, new byte[1]).getResult();

        KmsMasterKeyProvider mkpToTest = KmsMasterKeyProvider.builder()
            .withCustomClientFactory(testClientSupplier__)
            .buildDiscovery(new DiscoveryFilter(
                KMSTestFixtures.PARTITION,
                Arrays.asList(KMSTestFixtures.ACCOUNT_ID)));

        AwsCrypto.standard().decryptData(mkpToTest, singleCmkCiphertext);
        verify(testUSWestClient__, times(1)).decrypt(any());
    }

    @Test
    void whenConstructedWithDiscoveryFilter_decryptBadEDKFails() {
        KmsMasterKeyProvider mkp = KmsMasterKeyProvider.builder()
            .withCustomClientFactory(testClientSupplier__)
            .withDefaultRegion("us-west-2")
            .buildDiscovery(new DiscoveryFilter(
                KMSTestFixtures.PARTITION,
                Arrays.asList(KMSTestFixtures.ACCOUNT_ID)));

        final CryptoAlgorithm algSuite = CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;
        final Map<String, String> encCtx = Collections.singletonMap("myKey", "myValue");
        final String badARN = "arn:aws:kms:us-west-2:658956600833:key/badID";
        final EncryptedDataKey badEDK = new KeyBlob(AWS_KMS_PROVIDER_ID,
            badARN.getBytes(StandardCharsets.UTF_8), new byte[algSuite.getDataKeyLength()]);

        assertThrows(CannotUnwrapDataKeyException.class, () ->
            mkp.decryptDataKey(algSuite, Collections.singletonList(badEDK), encCtx));
        verify(testUSWestClient__, times(1)).decrypt(any());
    }

    @Test
    void whenHandlerConfigured_handlerIsInvoked() {
        RequestHandler2 handler = spy(new RequestHandler2() {});
        KmsMasterKeyProvider mkp =
            KmsMasterKeyProvider.builder()
                .withClientBuilder(
                    AWSKMSClientBuilder.standard()
                        .withRequestHandlers(handler)
                )
                .buildStrict(KMSTestFixtures.TEST_KEY_IDS[0]);

        AwsCrypto.standard().encryptData(mkp, new byte[1]);

        verify(handler).beforeRequest(any());
    }

    @Test
    void whenShortTimeoutSet_timesOut() {
        // By setting a timeout of 1ms, it's not physically possible to complete both the us-west-2 and eu-central-1
        // requests due to speed of light limits.
        KmsMasterKeyProvider mkp = KmsMasterKeyProvider.builder()
            .withClientBuilder(
                AWSKMSClientBuilder.standard()
                    .withClientConfiguration(
                        new ClientConfiguration()
                            .withRequestTimeout(1)
                    )
            )
            .buildStrict(Arrays.asList(KMSTestFixtures.TEST_KEY_IDS));

        try {
            AwsCrypto.standard().encryptData(mkp, new byte[1]);
            fail("Expected exception");
        } catch (Exception e) {
            if (e instanceof AbortedException) {
                // ok - one manifestation of a timeout
            } else if (e.getCause() instanceof HttpRequestTimeoutException) {
                // ok - another kind of timeout
            } else {
                throw e;
            }
        }
    }

    @Test
    void whenCustomCredentialsSet_theyAreUsed() {
        AWSCredentialsProvider customProvider = spy(new DefaultAWSCredentialsProviderChain());

        KmsMasterKeyProvider mkp = KmsMasterKeyProvider.builder()
            .withCredentials(customProvider)
            .buildStrict(KMSTestFixtures.TEST_KEY_IDS[0]);

        AwsCrypto.standard().encryptData(mkp, new byte[1]);

        verify(customProvider, atLeastOnce()).getCredentials();

        AWSCredentials customCredentials = spy(customProvider.getCredentials());

        mkp = KmsMasterKeyProvider.builder()
            .withCredentials(customCredentials)
            .buildStrict(KMSTestFixtures.TEST_KEY_IDS[0]);

        AwsCrypto.standard().encryptData(mkp, new byte[1]);

        verify(customCredentials, atLeastOnce()).getAWSSecretKey();
    }

    @Test
    void whenBuilderCloned_configurationIsRetained() {
        AWSCredentialsProvider customProvider1 = spy(new DefaultAWSCredentialsProviderChain());
        AWSCredentialsProvider customProvider2 = spy(new DefaultAWSCredentialsProviderChain());

        KmsMasterKeyProvider.Builder builder = KmsMasterKeyProvider.builder()
            .withCredentials(customProvider1);

        KmsMasterKeyProvider.Builder builder2 = builder.clone();

        // This will mutate the first builder to change the creds, but leave the clone unchanged.
        MasterKeyProvider<?> mkp2 = builder.withCredentials(customProvider2)
            .buildStrict(KMSTestFixtures.TEST_KEY_IDS[0]);
        MasterKeyProvider<?> mkp1 = builder2.buildStrict(KMSTestFixtures.TEST_KEY_IDS[0]);

        CryptoResult<byte[], ?> result = AwsCrypto.standard().encryptData(mkp1, new byte[0]);

        verify(customProvider1, atLeastOnce()).getCredentials();
        verify(customProvider2, never()).getCredentials();

        reset(customProvider1, customProvider2);

        result = AwsCrypto.standard().encryptData(mkp2, new byte[0]);

        verify(customProvider1, never()).getCredentials();
        verify(customProvider2, atLeastOnce()).getCredentials();
    }

    @Test
    void whenBuilderCloned_clientBuilderCustomizationIsRetained() {
        RequestHandler2 handler = spy(new RequestHandler2() {});

        KmsMasterKeyProvider mkp = KmsMasterKeyProvider.builder()
            .withClientBuilder(
                AWSKMSClientBuilder.standard().withRequestHandlers(handler)
            )
            .clone().buildStrict(KMSTestFixtures.TEST_KEY_IDS[0]);

        AwsCrypto.standard().encryptData(mkp, new byte[0]);

        verify(handler, atLeastOnce()).beforeRequest(any());
    }

    @Test
    void whenBogusEndpointIsSet_constructionFails() {
        assertThrows(IllegalArgumentException.class, () -> KmsMasterKeyProvider.builder()
            .withClientBuilder(
                AWSKMSClientBuilder.standard()
                    .withEndpointConfiguration(
                        new AwsClientBuilder.EndpointConfiguration(
                            "https://this.does.not.exist.example.com",
                            "bad-region")
                    )
            ));
    }

    @Test
    void whenUserAgentsOverridden_originalUAsPreserved() {
        RequestHandler2 handler = spy(new RequestHandler2() {});

        KmsMasterKeyProvider mkp = KmsMasterKeyProvider.builder()
            .withClientBuilder(
                AWSKMSClientBuilder.standard().withRequestHandlers(handler)
                    .withClientConfiguration(
                        new ClientConfiguration()
                            .withUserAgentPrefix("TEST-UA-PREFIX")
                            .withUserAgentSuffix("TEST-UA-SUFFIX")
                    )
            )
            .clone().buildStrict(KMSTestFixtures.TEST_KEY_IDS[0]);

        AwsCrypto.standard().encryptData(mkp, new byte[0]);

        ArgumentCaptor<Request> captor = ArgumentCaptor.forClass(Request.class);
        verify(handler, atLeastOnce()).beforeRequest(captor.capture());

        String ua = (String)captor.getValue().getHeaders().get("User-Agent");

        assertTrue(ua.contains("TEST-UA-PREFIX"));
        assertTrue(ua.contains("TEST-UA-SUFFIX"));
        assertTrue(ua.contains(VersionInfo.USER_AGENT));
    }

    @Test
    void whenDefaultRegionSet_itIsUsedForBareKeyIds() {
        // TODO: Need to set up a role to assume as bare key IDs are relative to the caller account
    }
}
