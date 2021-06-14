// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk.internal;

import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.jupiter.api.DisplayName;
import org.junit.runner.RunWith;

import static com.amazonaws.encryptionsdk.TestUtils.assertThrows;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class VersionInfoTest {

  @Test
  public void basic_use() {
    final String userAgent = VersionInfo.loadUserAgent();
    assertTrue(userAgent.startsWith(VersionInfo.USER_AGENT_PREFIX));
    assertTrue(!userAgent.equals(VersionInfo.USER_AGENT_PREFIX + VersionInfo.UNKNOWN_VERSION));
  }
}



