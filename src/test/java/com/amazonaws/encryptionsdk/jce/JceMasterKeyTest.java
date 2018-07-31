package com.amazonaws.encryptionsdk.jce;

import org.junit.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class JceMasterKeyTest {

    private static final SecretKey SECRET_KEY = new SecretKeySpec(new byte[1], "AES");

    @Test(expected = IllegalArgumentException.class)
    public void testGetInstanceInvalidWrappingAlgorithm() {
        JceMasterKey.getInstance(SECRET_KEY, "mockProvider", "mockKey",
                "blatently/unsupported/algorithm");
    }

    /**
     * Calls JceMasterKey.getInstance with differently cased wrappingAlgorithm names.
     * Passes if no Exception is thrown.
     * Relies on passing an invalid algorithm name to result in an Exception.
     */
    @Test
    public void testGetInstanceCaseInsensitive() {
        JceMasterKey.getInstance(SECRET_KEY, "mockProvider", "mockKey",
                "aes/gcm/nopadding");
        JceMasterKey.getInstance(SECRET_KEY, "mockProvider", "mockKey",
                "AES/GCM/NoPadding");
    }
}
