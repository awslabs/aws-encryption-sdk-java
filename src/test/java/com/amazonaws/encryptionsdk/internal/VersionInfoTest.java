// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk.internal;

import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class VersionInfoTest {

  @Test
  public void basic_use() {
    final String userAgent = VersionInfo.loadUserAgent();
    assertTrue(userAgent.startsWith(VersionInfo.USER_AGENT_PREFIX));
    assertTrue(!userAgent.equals(VersionInfo.USER_AGENT_PREFIX + VersionInfo.UNKNOWN_VERSION));
  }
}
