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
import static org.mockito.Mockito.verify;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

import com.amazonaws.encryptionsdk.TestUtils;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
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
import com.amazonaws.encryptionsdk.MasterKeyProvider;
import com.amazonaws.encryptionsdk.exception.CannotUnwrapDataKeyException;
import com.amazonaws.encryptionsdk.internal.VersionInfo;
import com.amazonaws.encryptionsdk.model.KeyBlob;
import com.amazonaws.handlers.RequestHandler2;
import com.amazonaws.http.exception.HttpRequestTimeoutException;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;

@Tag(TestUtils.TAG_INTEGRATION)
class KMSProviderBuilderIntegrationTests {
    @Test
    void whenBogusRegionsDecrypted_doesNotLeakClients() {
        AtomicReference<ConcurrentHashMap<String, AWSKMS>> kmsCache = new AtomicReference<>();

        KmsMasterKeyProvider mkp = (new KmsMasterKeyProvider.Builder() {
            @Override protected void snoopClientCache(
                    final ConcurrentHashMap<String, AWSKMS> map
            ) {
                kmsCache.set(map);
            }
        }).build();

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
        }).withKeysForEncryption(KMSTestFixtures.TEST_KEY_IDS[0])
          .build();

        new AwsCrypto().encryptData(mkp, new byte[1]);

        AWSKMS kms = kmsCache.get().get("us-west-2");
        assertNotNull(kms);

        new AwsCrypto().encryptData(mkp, new byte[1]);

        // Cache entry should stay the same
        assertEquals(kms, kmsCache.get().get("us-west-2"));
    }

    @Test
    void whenConstructedWithoutArguments_canUseMultipleRegions() {
        KmsMasterKeyProvider mkp = KmsMasterKeyProvider.builder().build();

        for (String key : KMSTestFixtures.TEST_KEY_IDS) {
            byte[] ciphertext =
                    new AwsCrypto().encryptData(
                            KmsMasterKeyProvider.builder()
                                .withKeysForEncryption(key)
                                .build(),
                            new byte[1]
                    ).getResult();

            new AwsCrypto().decryptData(mkp, ciphertext);
        }
    }

    @SuppressWarnings("deprecation") @Test
    void whenLegacyConstructorsUsed_multiRegionDecryptIsNotSupported() {
        KmsMasterKeyProvider mkp = new KmsMasterKeyProvider();

        assertThrows(CannotUnwrapDataKeyException.class, () -> {
            for (String key : KMSTestFixtures.TEST_KEY_IDS) {
                byte[] ciphertext =
                        new AwsCrypto().encryptData(
                                KmsMasterKeyProvider.builder()
                                        .withKeysForEncryption(key)
                                        .build(),
                                new byte[1]
                        ).getResult();

                new AwsCrypto().decryptData(mkp, ciphertext);
            }
        });
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
                                    .withKeysForEncryption(KMSTestFixtures.TEST_KEY_IDS[0])
                                    .build();

        new AwsCrypto().encryptData(mkp, new byte[1]);

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
                                                       .withKeysForEncryption(Arrays.asList(KMSTestFixtures.TEST_KEY_IDS))
                                                       .build();

        try {
            new AwsCrypto().encryptData(mkp, new byte[1]);
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
                                                       .withKeysForEncryption(KMSTestFixtures.TEST_KEY_IDS[0])
                                                       .build();

        new AwsCrypto().encryptData(mkp, new byte[1]);

        verify(customProvider, atLeastOnce()).getCredentials();

        AWSCredentials customCredentials = spy(customProvider.getCredentials());

        mkp = KmsMasterKeyProvider.builder()
                                                       .withCredentials(customCredentials)
                                                       .withKeysForEncryption(KMSTestFixtures.TEST_KEY_IDS[0])
                                                       .build();

        new AwsCrypto().encryptData(mkp, new byte[1]);

        verify(customCredentials, atLeastOnce()).getAWSSecretKey();
    }

    @Test
    void whenBuilderCloned_credentialsAndConfigurationAreRetained() {
        AWSCredentialsProvider customProvider1 = spy(new DefaultAWSCredentialsProviderChain());
        AWSCredentialsProvider customProvider2 = spy(new DefaultAWSCredentialsProviderChain());

        KmsMasterKeyProvider.Builder builder = KmsMasterKeyProvider.builder()
                .withCredentials(customProvider1)
                .withKeysForEncryption(KMSTestFixtures.TEST_KEY_IDS[0]);

        KmsMasterKeyProvider.Builder builder2 = builder.clone();

        // This will mutate the first builder to add the new key and change the creds, but leave the clone unchanged.
        MasterKeyProvider<?> mkp2 = builder.withKeysForEncryption(KMSTestFixtures.TEST_KEY_IDS[1]).withCredentials(customProvider2).build();
        MasterKeyProvider<?> mkp1 = builder2.build();

        CryptoResult<byte[], ?> result = new AwsCrypto().encryptData(mkp1, new byte[0]);

        assertEquals(KMSTestFixtures.TEST_KEY_IDS[0], result.getMasterKeyIds().get(0));
        assertEquals(1, result.getMasterKeyIds().size());
        verify(customProvider1, atLeastOnce()).getCredentials();
        verify(customProvider2, never()).getCredentials();

        reset(customProvider1, customProvider2);

        result = new AwsCrypto().encryptData(mkp2, new byte[0]);

        assertTrue(result.getMasterKeyIds().contains(KMSTestFixtures.TEST_KEY_IDS[0]));
        assertTrue(result.getMasterKeyIds().contains(KMSTestFixtures.TEST_KEY_IDS[1]));
        assertEquals(2, result.getMasterKeyIds().size());
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
                .withKeysForEncryption(KMSTestFixtures.TEST_KEY_IDS[0])
                .clone().build();

        new AwsCrypto().encryptData(mkp, new byte[0]);

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
                                                       .withKeysForEncryption(KMSTestFixtures.TEST_KEY_IDS[0])
                                                       .clone().build();

        new AwsCrypto().encryptData(mkp, new byte[0]);

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

