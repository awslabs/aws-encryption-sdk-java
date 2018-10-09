package com.amazonaws.encryptionsdk;

import com.amazonaws.encryptionsdk.jce.JceMasterKeyTest;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

import com.amazonaws.encryptionsdk.caching.CacheIdentifierTests;
import com.amazonaws.encryptionsdk.caching.CachingCryptoMaterialsManagerTest;
import com.amazonaws.encryptionsdk.caching.LocalCryptoMaterialsCacheTest;
import com.amazonaws.encryptionsdk.caching.LocalCryptoMaterialsCacheThreadStormTest;
import com.amazonaws.encryptionsdk.caching.NullCryptoMaterialsCacheTest;
import com.amazonaws.encryptionsdk.internal.BlockDecryptionHandlerTest;
import com.amazonaws.encryptionsdk.internal.BlockEncryptionHandlerTest;
import com.amazonaws.encryptionsdk.internal.CipherHandlerTest;
import com.amazonaws.encryptionsdk.internal.DecryptionHandlerTest;
import com.amazonaws.encryptionsdk.internal.EncContextSerializerTest;
import com.amazonaws.encryptionsdk.internal.EncryptionHandlerTest;
import com.amazonaws.encryptionsdk.internal.FrameDecryptionHandlerTest;
import com.amazonaws.encryptionsdk.internal.FrameEncryptionHandlerTest;
import com.amazonaws.encryptionsdk.internal.PrimitivesParserTest;
import com.amazonaws.encryptionsdk.jce.KeyStoreProviderTest;
import com.amazonaws.encryptionsdk.model.CipherBlockHeadersTest;
import com.amazonaws.encryptionsdk.model.CipherFrameHeadersTest;
import com.amazonaws.encryptionsdk.model.KeyBlobTest;
import com.amazonaws.encryptionsdk.model.DecryptionMaterialsRequestTest;
import com.amazonaws.encryptionsdk.multi.MultipleMasterKeyTest;
import com.amazonaws.encryptionsdk.kms.KMSProviderBuilderMockTests;

@RunWith(Suite.class)
@Suite.SuiteClasses({
        BlockDecryptionHandlerTest.class,
        BlockEncryptionHandlerTest.class,
        CipherHandlerTest.class,
        DecryptionHandlerTest.class,
        EncContextSerializerTest.class,
        EncryptionHandlerTest.class,
        FrameDecryptionHandlerTest.class,
        FrameEncryptionHandlerTest.class,
        PrimitivesParserTest.class,
        KeyStoreProviderTest.class,
        CipherBlockHeadersTest.class,
        CipherFrameHeadersTest.class,
        KeyBlobTest.class,
        DecryptionMaterialsRequestTest.class,
        MultipleMasterKeyTest.class,
        AwsCryptoTest.class,
        CryptoInputStreamTest.class,
        CryptoOutputStreamTest.class,
        XCompatDecryptTest.class,
        DefaultCryptoMaterialsManagerTest.class,
        NullCryptoMaterialsCacheTest.class,
        CacheIdentifierTests.class,
        CachingCryptoMaterialsManagerTest.class,
        LocalCryptoMaterialsCacheTest.class,
        LocalCryptoMaterialsCacheThreadStormTest.class,
        UtilsTest.class,
        MultipleMasterKeyTest.class,
        KMSProviderBuilderMockTests.class,
        JceMasterKeyTest.class
})
public class AllTestsSuite {
}
