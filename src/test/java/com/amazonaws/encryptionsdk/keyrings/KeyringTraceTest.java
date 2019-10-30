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

import org.junit.Test;

import static java.util.Collections.singleton;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

public class KeyringTraceTest {

    @Test
    public void testOrderMaintained() {
        KeyringTraceEntry entry1 = new KeyringTraceEntry("ns1", "name1",
                singleton(KeyringTraceFlag.GENERATED_DATA_KEY));
        KeyringTraceEntry entry2 = new KeyringTraceEntry("ns2", "name2",
                singleton(KeyringTraceFlag.DECRYPTED_DATA_KEY));
        KeyringTraceEntry entry3 = new KeyringTraceEntry("ns3", "name3",
                singleton(KeyringTraceFlag.ENCRYPTED_DATA_KEY));

        KeyringTrace trace = new KeyringTrace();
        trace.add(entry1.getKeyNamespace(), entry1.getKeyName(), entry1.getFlags().iterator().next());
        trace.add(entry2.getKeyNamespace(), entry2.getKeyName(), entry2.getFlags().iterator().next());
        trace.add(entry3.getKeyNamespace(), entry3.getKeyName(), entry3.getFlags().iterator().next());

        assertEquals(entry1, trace.getEntries().get(0));
        assertEquals(entry2, trace.getEntries().get(1));
        assertEquals(entry3, trace.getEntries().get(2));
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testImmutable() {
        KeyringTrace trace = new KeyringTrace();
        trace.add("namespace", "name", KeyringTraceFlag.GENERATED_DATA_KEY);

        trace.getEntries().add(new KeyringTraceEntry("ns1", "name1",
                singleton(KeyringTraceFlag.GENERATED_DATA_KEY)));
    }

    @Test
    public void testKeyringTraceEntryEquals() {
        KeyringTraceEntry entry1 = new KeyringTraceEntry("namespace", "name",
                singleton(KeyringTraceFlag.GENERATED_DATA_KEY));
        KeyringTraceEntry entry2 = new KeyringTraceEntry(entry1.getKeyNamespace(), entry1.getKeyName(),
                entry1.getFlags());
        KeyringTraceEntry entry3 = new KeyringTraceEntry("othernamespace", "name",
                singleton(KeyringTraceFlag.GENERATED_DATA_KEY));

        assertEquals(entry1, entry1);
        assertEquals(entry1, entry2);
        assertNotEquals(entry2, entry3);
    }
}
