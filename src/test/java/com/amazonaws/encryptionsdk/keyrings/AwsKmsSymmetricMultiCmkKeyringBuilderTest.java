package com.amazonaws.encryptionsdk.keyrings;

import com.amazonaws.ClientConfiguration;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.encryptionsdk.kms.AwsKmsCmkId;
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
public class AwsKmsSymmetricMultiCmkKeyringBuilderTest {

    @Mock
    AWSCredentialsProvider credentialsProvider;
    @Mock
    ClientConfiguration clientConfiguration;
    @Mock(lenient = true)
    AwsKmsDataKeyEncryptionDaoBuilder daoBuilder;
    @Mock
    AwsKmsDataKeyEncryptionDao doa;

    private static final List<String> GRANT_TOKENS = Arrays.asList("some", "grant", "tokens");
    private static final String GENERATOR = "arn:aws:kms:us-east-1:999999999999:key/generator-89ab-cdef-fedc-ba9876543210";
    private static final String US_EAST_1_ARN = "arn:aws:kms:us-east-1:999999999999:key/key1-23bv-sdfs-werw-234323nfdsf";
    private static final String US_WEST_2_ARN_1 = "arn:aws:kms:us-west-2:999999999999:key/key2-02ds-wvjs-aswe-a4923489273";
    private static final String US_WEST_2_ARN_2 = "arn:aws:kms:us-west-2:999999999999:key/key2-02ds-wvjs-aswe-a4923489273";
    private static final String NON_ARN = "key1-23bv-sdfs-werw-234323nfdsf";

    private static final AwsKmsCmkId GENERATOR_KEY_NAME = AwsKmsCmkId.fromString(GENERATOR);
    private static final AwsKmsCmkId KEY_NAME_US_EAST_1 = AwsKmsCmkId.fromString(US_EAST_1_ARN);
    private static final AwsKmsCmkId KEY_NAME_US_WEST_2_ARN_1 = AwsKmsCmkId.fromString(US_WEST_2_ARN_1);
    private static final AwsKmsCmkId KEY_NAME_US_WEST_2_ARN_2 = AwsKmsCmkId.fromString(US_WEST_2_ARN_2);
    private static final AwsKmsCmkId KEY_NAME_NON_ARN = AwsKmsCmkId.fromString(NON_ARN);

    private static final List<AwsKmsCmkId> CHILD_KEY_NAMES = Arrays.asList(
        KEY_NAME_US_EAST_1,
        KEY_NAME_US_WEST_2_ARN_1,
        KEY_NAME_US_WEST_2_ARN_2,
        KEY_NAME_NON_ARN);

    private static final List<String> REGIONS = Arrays.asList("us-east-1", "us-west-2", null);

    private AwsKmsSymmetricMultiCmkKeyringBuilder builder;

    @BeforeEach
    void setup() {
        when(daoBuilder.clientConfiguration(clientConfiguration)).thenReturn(daoBuilder);
        when(daoBuilder.credentialsProvider(credentialsProvider)).thenReturn(daoBuilder);
        when(daoBuilder.grantTokens(GRANT_TOKENS)).thenReturn(daoBuilder);
        for (String region : REGIONS) {
            when(daoBuilder.regionId(region)).thenReturn(daoBuilder);
        }
        when(daoBuilder.build()).thenReturn(doa);
        builder = new AwsKmsSymmetricMultiCmkKeyringBuilder(daoBuilder);
    }

    @Test
    void testBuildFullyConfigured() {
        MultiKeyring keyring = builder.credentialsProvider(credentialsProvider)
            .clientConfiguration(clientConfiguration)
            .grantTokens(GRANT_TOKENS)
            .keyNames(CHILD_KEY_NAMES)
            .generator(GENERATOR_KEY_NAME)
            .build();

        assertNotNull(keyring.generatorKeyring);
        assertNotNull(keyring.childKeyrings);
        assertEquals(4, keyring.childKeyrings.size());

        verify(daoBuilder, times(REGIONS.size())).clientConfiguration(clientConfiguration);
        verify(daoBuilder, times(REGIONS.size())).credentialsProvider(credentialsProvider);
        verify(daoBuilder, times(REGIONS.size())).grantTokens(GRANT_TOKENS);
        for (String region : REGIONS) {
            verify(daoBuilder).regionId(region);
        }
        verify(daoBuilder, times(REGIONS.size())).build();
    }

    @Test
    void testBuildNoGenerator() {
        MultiKeyring keyring = builder.credentialsProvider(credentialsProvider)
            .clientConfiguration(clientConfiguration)
            .grantTokens(GRANT_TOKENS)
            .keyNames(CHILD_KEY_NAMES)
            .build();

        assertNull(keyring.generatorKeyring);
        assertNotNull(keyring.childKeyrings);
        assertEquals(4, keyring.childKeyrings.size());

        verify(daoBuilder, times(REGIONS.size())).clientConfiguration(clientConfiguration);
        verify(daoBuilder, times(REGIONS.size())).credentialsProvider(credentialsProvider);
        verify(daoBuilder, times(REGIONS.size())).grantTokens(GRANT_TOKENS);
        for (String region : REGIONS) {
            verify(daoBuilder).regionId(region);
        }
        verify(daoBuilder, times(REGIONS.size())).build();
    }

    @Test
    void testBuildNoChildren() {
        MultiKeyring keyring = builder.credentialsProvider(credentialsProvider)
            .clientConfiguration(clientConfiguration)
            .grantTokens(GRANT_TOKENS)
            .generator(GENERATOR_KEY_NAME)
            .build();

        assertNotNull(keyring.generatorKeyring);
        assertNotNull(keyring.childKeyrings);
        assertEquals(0, keyring.childKeyrings.size());

        verify(daoBuilder, times(1)).clientConfiguration(clientConfiguration);
        verify(daoBuilder, times(1)).credentialsProvider(credentialsProvider);
        verify(daoBuilder, times(1)).grantTokens(GRANT_TOKENS);
        verify(daoBuilder).regionId("us-east-1");
        verify(daoBuilder, times(1)).build();
    }

    @Test
    void testBuildNullKeyNames() {
        when(daoBuilder.clientConfiguration(null)).thenReturn(daoBuilder);
        when(daoBuilder.credentialsProvider(null)).thenReturn(daoBuilder);
        when(daoBuilder.grantTokens(null)).thenReturn(daoBuilder);

        builder = builder.keyNames(Arrays.asList(KEY_NAME_US_EAST_1, null));
        assertThrows(IllegalArgumentException.class, () -> builder.build());
    }

    @Test
    void testBuildNoKeys() {
        assertThrows(IllegalArgumentException.class, () -> builder.build());
    }

    @Test
    void testBuildNoCustomization() {
        when(daoBuilder.clientConfiguration(null)).thenReturn(daoBuilder);
        when(daoBuilder.credentialsProvider(null)).thenReturn(daoBuilder);
        when(daoBuilder.grantTokens(null)).thenReturn(daoBuilder);

        MultiKeyring keyring = builder.keyNames(CHILD_KEY_NAMES)
            .generator(GENERATOR_KEY_NAME)
            .build();

        assertNotNull(keyring.generatorKeyring);
        assertNotNull(keyring.childKeyrings);
        assertEquals(4, keyring.childKeyrings.size());

        verify(daoBuilder, times(REGIONS.size())).clientConfiguration(null);
        verify(daoBuilder, times(REGIONS.size())).credentialsProvider(null);
        verify(daoBuilder, times(REGIONS.size())).grantTokens(null);
        verify(daoBuilder).regionId("us-west-2");
        verify(daoBuilder).regionId("us-east-1");
        verify(daoBuilder, times(REGIONS.size())).build();
    }
}
