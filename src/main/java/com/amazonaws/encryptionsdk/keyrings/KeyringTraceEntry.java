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

import java.util.Collections;
import java.util.Objects;
import java.util.Set;

import static org.apache.commons.lang3.Validate.notBlank;
import static org.apache.commons.lang3.Validate.notEmpty;

/**
 * A representation of an action that a keyring has taken on a data key.
 */
public class KeyringTraceEntry {

    private final String keyNamespace;
    private final String keyName;
    private final Set<KeyringTraceFlag> flags;

    /**
     * Constructs a new `KeyringTraceEntry`.
     *
     * @param keyNamespace The namespace for the key.
     * @param keyName      The name of the key.
     * @param flags        A set of one or more KeyringTraceFlag enums
     *                     indicating what actions were taken by a keyring.
     */
    KeyringTraceEntry(final String keyNamespace, final String keyName, final Set<KeyringTraceFlag> flags) {
        notBlank(keyNamespace, "keyNamespace is required");
        notBlank(keyName, "keyName is required");
        notEmpty(flags, "At least one flag is required");

        this.keyNamespace = keyNamespace;
        this.keyName = keyName;
        this.flags = Collections.unmodifiableSet(flags);
    }

    /**
     * Returns the key namespace.
     *
     * @return The key namespace.
     */
    public String getKeyNamespace() {
        return this.keyNamespace;
    }

    /**
     * Returns the key name.
     *
     * @return The key name.
     */
    public String getKeyName() {
        return this.keyName;
    }

    /**
     * Returns an unmodifiable set of flags that indicate
     * which actions were taken by a keyring.
     *
     * @return The unmodifiable set of flags.
     */
    public Set<KeyringTraceFlag> getFlags() {
        return this.flags;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        KeyringTraceEntry that = (KeyringTraceEntry) o;
        return Objects.equals(keyNamespace, that.keyNamespace) &&
                Objects.equals(keyName, that.keyName) &&
                Objects.equals(flags, that.flags);
    }

    @Override
    public int hashCode() {
        return Objects.hash(keyNamespace, keyName, flags);
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE)
                .append("keyNamespace", this.keyNamespace)
                .append("keyName", this.keyName)
                .append("flags", this.flags)
                .toString();
    }
}
