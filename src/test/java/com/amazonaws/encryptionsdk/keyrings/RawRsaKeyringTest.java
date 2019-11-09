/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

import com.amazonaws.encryptionsdk.model.KeyBlob;
import org.apache.commons.lang3.ArrayUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;

import static com.amazonaws.encryptionsdk.keyrings.RawKeyringTest.KEYNAME;
import static com.amazonaws.encryptionsdk.keyrings.RawKeyringTest.KEYNAMESPACE;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@RunWith(MockitoJUnitRunner.class)
public class RawRsaKeyringTest {

    @Mock
    PublicKey publicKey;
    @Mock
    PrivateKey privateKey;
    private static final String TRANSFORMATION = "RSA/ECB/PKCS1Padding";

    @Test
    public void testValidToDecrypt() {
        RawRsaKeyring rawRsaKeyring = new RawRsaKeyring(KEYNAMESPACE, KEYNAME, publicKey, privateKey, TRANSFORMATION);

        assertTrue(rawRsaKeyring.validToDecrypt(new KeyBlob(
                KEYNAMESPACE, KEYNAME.getBytes(StandardCharsets.UTF_8), new byte[]{})));
        //Provider info has extra data
        assertFalse(rawRsaKeyring.validToDecrypt(new KeyBlob(
                KEYNAMESPACE, ArrayUtils.add(KEYNAME.getBytes(StandardCharsets.UTF_8), (byte)5), new byte[]{})));
        //Bad namespace
        assertFalse(rawRsaKeyring.validToDecrypt(new KeyBlob(
                "WrongNamespace", KEYNAME.getBytes(StandardCharsets.UTF_8), new byte[]{})));
    }

    @Test
    public void testTraceOnEncrypt() {
        RawRsaKeyring rawRsaKeyring = new RawRsaKeyring(KEYNAMESPACE, KEYNAME, publicKey, privateKey, TRANSFORMATION);

        KeyringTrace trace = new KeyringTrace();

        rawRsaKeyring.traceOnEncrypt(trace);
        assertEquals(1, trace.getEntries().size());
        assertEquals(KEYNAME, trace.getEntries().get(0).getKeyName());
        assertEquals(KEYNAMESPACE, trace.getEntries().get(0).getKeyNamespace());
        assertEquals(1, trace.getEntries().get(0).getFlags().size());
        assertTrue(trace.getEntries().get(0).getFlags().contains(KeyringTraceFlag.ENCRYPTED_DATA_KEY));
    }

    @Test
    public void testTraceOnDecrypt() {
        RawRsaKeyring rawRsaKeyring = new RawRsaKeyring(KEYNAMESPACE, KEYNAME, publicKey, privateKey, TRANSFORMATION);

        KeyringTrace trace = new KeyringTrace();

        rawRsaKeyring.traceOnDecrypt(trace);
        assertEquals(1, trace.getEntries().size());
        assertEquals(KEYNAME, trace.getEntries().get(0).getKeyName());
        assertEquals(KEYNAMESPACE, trace.getEntries().get(0).getKeyNamespace());
        assertEquals(1, trace.getEntries().get(0).getFlags().size());
        assertTrue(trace.getEntries().get(0).getFlags().contains(KeyringTraceFlag.DECRYPTED_DATA_KEY));
    }

}
