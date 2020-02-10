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
import java.util.List;
import java.util.Objects;

import static java.util.Collections.emptyList;
import static java.util.Collections.unmodifiableList;

/**
 * A keyring trace containing all of the actions that keyrings have taken on a set of encryption materials.
 */
public final class KeyringTrace {

    private final List<KeyringTraceEntry> entries;
    public static final KeyringTrace EMPTY_TRACE = new KeyringTrace(emptyList());

    public KeyringTrace(final List<KeyringTraceEntry> entries) {
        this.entries = unmodifiableList(new ArrayList<>(entries));
    }

    /**
     * Creates a new instance of {@code KeyringTrace} with the provided {@link KeyringTraceEntry}.
     *
     * @param entry The entry to include in the new {@code KeyringTrace}.
     * @return The new {@code KeyringTrace} instance.
     */
    public KeyringTrace with(KeyringTraceEntry entry) {
        final List<KeyringTraceEntry> newEntries = new ArrayList<>(entries);
        newEntries.add(entry);
        return new KeyringTrace(newEntries);
    }

    /**
     * Gets an unmodifiable list of `KeyringTraceEntry`s ordered sequentially
     * according to the order the actions were taken, with the earliest action
     * corresponding to the first `KeyringTraceEntry` in the list.
     *
     * @return An unmodifiable list of `KeyringTraceEntry`s
     */
    public List<KeyringTraceEntry> getEntries() {
        return entries;
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE)
                .append("entries", entries)
                .toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        KeyringTrace that = (KeyringTrace) o;
        return Objects.equals(entries, that.entries);
    }

    @Override
    public int hashCode() {
        return Objects.hash(entries);
    }
}
