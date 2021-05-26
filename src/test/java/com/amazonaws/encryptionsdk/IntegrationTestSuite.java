package com.amazonaws.encryptionsdk;

import com.amazonaws.encryptionsdk.kms.MaxEncryptedDataKeysIntegrationTest;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

import com.amazonaws.encryptionsdk.kms.KMSProviderBuilderIntegrationTests;
import com.amazonaws.encryptionsdk.kms.XCompatKmsDecryptTest;

@RunWith(Suite.class)
@Suite.SuiteClasses({
        XCompatKmsDecryptTest.class,
        KMSProviderBuilderIntegrationTests.class,
        MaxEncryptedDataKeysIntegrationTest.class,
})
public class IntegrationTestSuite {
}
