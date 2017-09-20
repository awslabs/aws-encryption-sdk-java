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

public final class Constants {
    /**
     * Default length of the message identifier used to uniquely identify every
     * ciphertext created by this library.
     */
    public final static int MESSAGE_ID_LEN = 16;

    private Constants() {
        // Prevent instantiation
    }

    /**
     * Marker for identifying the final frame.
     */
    public final static int ENDFRAME_SEQUENCE_NUMBER = ~0; // is 0xFFFFFFFF

    /**
     * The identifier for non-final frames in the framing content type. This value is used as part
     * of the additional authenticated data (AAD) when encryption of content in a frame.
     */
    public final static String FRAME_STRING_ID = "AWSKMSEncryptionClient Frame";

    /**
     * The identifier for the final frame in the framing content type. This value is used as part of
     * the additional authenticated data (AAD) when encryption of content in a frame.
     */
    public final static String FINAL_FRAME_STRING_ID = "AWSKMSEncryptionClient Final Frame";

    /**
     * The identifier for the single block content type. This value is used as part of the
     * additional authenticated data (AAD) when encryption of content in a single block.
     */
    public final static String SINGLE_BLOCK_STRING_ID = "AWSKMSEncryptionClient Single Block";

    /**
     * Maximum length of the content that can be encrypted in GCM mode.
     */
    public final static long GCM_MAX_CONTENT_LEN = (1L << 36) - 32;

    public final static int MAX_NONCE_LENGTH = (1 << 8) - 1;

    /**
     * Maximum value of an unsigned short.
     */
    public final static int UNSIGNED_SHORT_MAX_VAL = (1 << 16) - 1;

    public final static long MAX_FRAME_NUMBER = (1L << 32) - 1;

    public static final String EC_PUBLIC_KEY_FIELD = "aws-crypto-public-key";
}
