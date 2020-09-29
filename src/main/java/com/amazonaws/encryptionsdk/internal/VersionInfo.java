// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk.internal;

/**
 * This class specifies the versioning system for the AWS KMS encryption client.
 */
public class VersionInfo {
    // incremented for major changes to the implementation
    public static final String MAJOR_REVISION_NUM = "2";
    // incremented for minor changes to the implementation
    public static final String MINOR_REVISION_NUM = "1";
    // incremented for releases containing an immediate bug fix.
    public static final String BUGFIX_REVISION_NUM = "0";

    public static final String RELEASE_VERSION = MAJOR_REVISION_NUM + "." + MINOR_REVISION_NUM
            + "." + BUGFIX_REVISION_NUM;

    public static final String USER_AGENT = "AwsCrypto/" + RELEASE_VERSION;
}
