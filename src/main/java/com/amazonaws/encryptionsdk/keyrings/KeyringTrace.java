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

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * A keyring trace containing all of the actions that keyrings have taken on a set of encryption materials.
 */
public class KeyringTrace {

    private final List<KeyringTraceEntry> entries = new ArrayList<>();

    /**
     * Add a new entry to the keyring trace.
     *
     * @param keyNamespace The namespace for the key.
     * @param keyName      The name of the key.
     * @param flags        A set of one or more KeyringTraceFlag enums
     *                     indicating what actions were taken by a keyring.
     */
    public void add(String keyNamespace, String keyName, KeyringTraceFlag... flags) {
        add(new KeyringTraceEntry(keyNamespace, keyName, flags));
    }

    /**
     * Add a new entry to the keyring trace.
     *
     * @param entry The entry to add.
     */
    public void add(KeyringTraceEntry entry) {
        entries.add(entry);
    }

    /**
     * Gets an unmodifiable list of `KeyringTraceEntry`s ordered sequentially
     * according to the order the actions were taken, with the earliest action
     * corresponding to the first `KeyringTraceEntry` in the list.
     *
     * @return An unmodifiable list of `KeyringTraceEntry`s
     */
    public List<KeyringTraceEntry> getEntries() {
        return Collections.unmodifiableList(entries);
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE)
                .append("entries", entries)
                .toString();
    }
}
