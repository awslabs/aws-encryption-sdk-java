/*
 * Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package com.amazonaws.encryptionsdk.internal;
import java.util.Properties;
import java.io.IOException;

/**
 * This class specifies the versioning system for the AWS KMS encryption client.
 */
public class VersionInfo {
    public static final String USER_AGENT_PREFIX = "AwsCrypto/";
    public static final String UNKNOWN_VERSION = "unknown";
    /*
     * Loads the version of the library
     */
    public static String loadUserAgent() {
        try {
            final Properties properties = new Properties();
            properties.load(ClassLoader.getSystemResourceAsStream("project.properties"));
            return USER_AGENT_PREFIX + properties.getProperty("version");
        } catch (final IOException ex) {
            return USER_AGENT_PREFIX + UNKNOWN_VERSION;
        }
    }
}
