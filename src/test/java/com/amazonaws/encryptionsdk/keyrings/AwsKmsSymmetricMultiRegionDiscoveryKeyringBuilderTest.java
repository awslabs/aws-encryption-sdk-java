package com.amazonaws.encryptionsdk.keyrings;

import com.amazonaws.ClientConfiguration;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.encryptionsdk.kms.AwsKmsDataKeyEncryptionDao;
import com.amazonaws.encryptionsdk.kms.AwsKmsDataKeyEncryptionDaoBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Arrays;
import java.util.List;

import static com.amazonaws.encryptionsdk.TestUtils.assertThrows;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class AwsKmsSymmetricMultiRegionDiscoveryKeyringBuilderTest {

    @Mock
    AWSCredentialsProvider credentialsProvider;
    @Mock
    ClientConfiguration clientConfiguration;
    @Mock(lenient = true)
    AwsKmsDataKeyEncryptionDaoBuilder daoBuilder;
    @Mock
    AwsKmsDataKeyEncryptionDao doa;

    private static final List<String> GRANT_TOKENS = Arrays.asList("some", "grant", "tokens");
    private static final List<String> REGIONS = Arrays.asList("us-west-2", "us-east-1");
    private static final String AWS_ACCOUNT_ID = "999999999999";

    private AwsKmsSymmetricMultiRegionDiscoveryKeyringBuilder builder;

    @BeforeEach
    void setup() {
        when(daoBuilder.clientConfiguration(clientConfiguration)).thenReturn(daoBuilder);
        when(daoBuilder.credentialsProvider(credentialsProvider)).thenReturn(daoBuilder);
        when(daoBuilder.grantTokens(GRANT_TOKENS)).thenReturn(daoBuilder);
        for (String region : REGIONS) {
            when(daoBuilder.regionId(region)).thenReturn(daoBuilder);
        }
        when(daoBuilder.build()).thenReturn(doa);
        builder = new AwsKmsSymmetricMultiRegionDiscoveryKeyringBuilder(daoBuilder);
    }

    @Test
    void testBuildFullyConfigured() {
        MultiKeyring keyring = builder.credentialsProvider(credentialsProvider)
            .clientConfiguration(clientConfiguration)
            .grantTokens(GRANT_TOKENS)
            .regions(REGIONS)
            .awsAccountId(AWS_ACCOUNT_ID)
            .build();

        assertNull(keyring.generatorKeyring);
        assertNotNull(keyring.childKeyrings);
        assertEquals(2, keyring.childKeyrings.size());

        verify(daoBuilder, times(REGIONS.size())).clientConfiguration(clientConfiguration);
        verify(daoBuilder, times(REGIONS.size())).credentialsProvider(credentialsProvider);
        verify(daoBuilder, times(REGIONS.size())).grantTokens(GRANT_TOKENS);
        for (String region : REGIONS) {
            verify(daoBuilder).regionId(region);
        }
        verify(daoBuilder, times(REGIONS.size())).build();
    }

    @Test
    void testBuildMultipleSameRegion() {
        MultiKeyring keyring = builder.credentialsProvider(credentialsProvider)
            .clientConfiguration(clientConfiguration)
            .grantTokens(GRANT_TOKENS)
            .regions(Arrays.asList("us-west-2", "us-east-1", "us-west-2"))
            .build();

        assertNull(keyring.generatorKeyring);
        assertNotNull(keyring.childKeyrings);
        // Regions are not de-duplicated
        assertEquals(3, keyring.childKeyrings.size());

        verify(daoBuilder, times(2)).clientConfiguration(clientConfiguration);
        verify(daoBuilder, times(2)).credentialsProvider(credentialsProvider);
        verify(daoBuilder, times(2)).grantTokens(GRANT_TOKENS);
        verify(daoBuilder).regionId("us-west-2");
        verify(daoBuilder).regionId("us-east-1");
        verify(daoBuilder, times(REGIONS.size())).build();
    }

    @Test
    void testBuildNullRegions() {
        when(daoBuilder.clientConfiguration(null)).thenReturn(daoBuilder);
        when(daoBuilder.credentialsProvider(null)).thenReturn(daoBuilder);
        when(daoBuilder.grantTokens(null)).thenReturn(daoBuilder);

        builder = builder.regions(Arrays.asList("us-west-2", null));
        assertThrows(IllegalArgumentException.class, () -> builder.build());
    }

    @Test
    void testBuildEmptyRegions() {
        when(daoBuilder.clientConfiguration(null)).thenReturn(daoBuilder);
        when(daoBuilder.credentialsProvider(null)).thenReturn(daoBuilder);
        when(daoBuilder.grantTokens(null)).thenReturn(daoBuilder);

        builder = builder.regions(Arrays.asList("us-west-2", " "));
        assertThrows(IllegalArgumentException.class, () -> builder.build());
    }

    @Test
    void testBuildNoRegions() {
        assertThrows(IllegalArgumentException.class, () -> builder.build());
    }

    @Test
    void testBuildNoCustomization() {
        when(daoBuilder.clientConfiguration(null)).thenReturn(daoBuilder);
        when(daoBuilder.credentialsProvider(null)).thenReturn(daoBuilder);
        when(daoBuilder.grantTokens(null)).thenReturn(daoBuilder);

        MultiKeyring keyring = builder
            .regions(REGIONS)
            .build();

        assertNull(keyring.generatorKeyring);
        assertNotNull(keyring.childKeyrings);
        assertEquals(2, keyring.childKeyrings.size());

        verify(daoBuilder, times(REGIONS.size())).clientConfiguration(null);
        verify(daoBuilder, times(REGIONS.size())).credentialsProvider(null);
        verify(daoBuilder, times(REGIONS.size())).grantTokens(null);
        verify(daoBuilder).regionId("us-west-2");
        verify(daoBuilder).regionId("us-east-1");
        verify(daoBuilder, times(REGIONS.size())).build();
    }
}
