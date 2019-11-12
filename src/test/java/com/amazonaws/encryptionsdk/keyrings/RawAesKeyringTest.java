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

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

import static com.amazonaws.encryptionsdk.keyrings.RawKeyringTest.KEYNAME;
import static com.amazonaws.encryptionsdk.keyrings.RawKeyringTest.KEYNAMESPACE;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@RunWith(MockitoJUnitRunner.class)
public class RawAesKeyringTest {

    @Mock
    private SecretKey wrappingKey;

    @Test
    public void testValidToDecrypt() {
        RawAesKeyring rawAesKeyring = new RawAesKeyring(KEYNAMESPACE, KEYNAME, wrappingKey);

        assertTrue(rawAesKeyring.validToDecrypt(new KeyBlob(
                KEYNAMESPACE, KEYNAME.getBytes(StandardCharsets.UTF_8), new byte[]{})));
        assertTrue(rawAesKeyring.validToDecrypt(new KeyBlob(
                KEYNAMESPACE, ArrayUtils.add(KEYNAME.getBytes(StandardCharsets.UTF_8), (byte)5), new byte[]{})));
        //Bad namespace
        assertFalse(rawAesKeyring.validToDecrypt(new KeyBlob(
                "WrongNamespace", KEYNAME.getBytes(StandardCharsets.UTF_8), new byte[]{})));
        //Bad provider info
        assertFalse(rawAesKeyring.validToDecrypt(new KeyBlob(
                KEYNAMESPACE, new byte[]{1,2,3}, new byte[]{})));
    }

    @Test
    public void testTraceOnEncrypt() {
        RawAesKeyring rawAesKeyring = new RawAesKeyring(KEYNAMESPACE, KEYNAME, wrappingKey);

        KeyringTrace trace = new KeyringTrace();

        rawAesKeyring.traceOnEncrypt(trace);
        assertEquals(1, trace.getEntries().size());
        assertEquals(KEYNAME, trace.getEntries().get(0).getKeyName());
        assertEquals(KEYNAMESPACE, trace.getEntries().get(0).getKeyNamespace());
        assertEquals(2, trace.getEntries().get(0).getFlags().size());
        assertTrue(trace.getEntries().get(0).getFlags().contains(KeyringTraceFlag.ENCRYPTED_DATA_KEY));
        assertTrue(trace.getEntries().get(0).getFlags().contains(KeyringTraceFlag.SIGNED_ENCRYPTION_CONTEXT));
    }

    @Test
    public void testTraceOnDecrypt() {
        RawAesKeyring rawAesKeyring = new RawAesKeyring(KEYNAMESPACE, KEYNAME, wrappingKey);

        KeyringTrace trace = new KeyringTrace();

        rawAesKeyring.traceOnDecrypt(trace);
        assertEquals(1, trace.getEntries().size());
        assertEquals(KEYNAME, trace.getEntries().get(0).getKeyName());
        assertEquals(KEYNAMESPACE, trace.getEntries().get(0).getKeyNamespace());
        assertEquals(2, trace.getEntries().get(0).getFlags().size());
        assertTrue(trace.getEntries().get(0).getFlags().contains(KeyringTraceFlag.DECRYPTED_DATA_KEY));
        assertTrue(trace.getEntries().get(0).getFlags().contains(KeyringTraceFlag.VERIFIED_ENCRYPTION_CONTEXT));
    }

}
