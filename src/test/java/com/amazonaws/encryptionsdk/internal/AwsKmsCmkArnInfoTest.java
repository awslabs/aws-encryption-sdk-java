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

@RunWith(Enclosed.class)
public class AwsKmsCmkArnInfoTest {

    public static class splitArn {
        @Test
        public void basic_use() {
            String[] test = AwsKmsCmkArnInfo.AwsKmsArnParts.splitArn("arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574");
            assertEquals(test.length, 6);
        }

        @Test
        public void with_fewer_elements() {
            String[] test = AwsKmsCmkArnInfo.AwsKmsArnParts.splitArn("arn:aws:kms:us-west-2");
            assertEquals(test.length, 4);
        }

        @Test
        public void with_valid_arn_but_not_kms_valid() {
            String[] test = AwsKmsCmkArnInfo.AwsKmsArnParts.splitArn("arn:aws:kms:us-west-2:111122223333:key:mrk-edb7fe6942894d32ac46dbb1c922d574");
            assertEquals(test.length, 6);
        }
    }

    public static class splitResourceParts {
        @Test
        public void basic_use() {
            String[] test = AwsKmsCmkArnInfo.AwsKmsArnParts.Resource.splitResourceParts("key/mrk-edb7fe6942894d32ac46dbb1c922d574");
            assertEquals(test.length, 2);
        }
    }

    public static class parseInfoFromKeyArn {
        @Test
        public void basic_use() {
            AwsKmsCmkArnInfo test = AwsKmsCmkArnInfo.parseInfoFromKeyArn("arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574");
            assertNotNull(test);
            assertEquals(test.getPartition(), "aws");
            assertEquals(test.getRegion(), "us-west-2");
            assertEquals(test.getAccountId(), "111122223333");
            assertEquals(test.getAccountId(), "111122223333");
            assertEquals(test.getResourceType(), "key");
            assertEquals(test.getResource(), "mrk-edb7fe6942894d32ac46dbb1c922d574");
        }

        @Test
        @DisplayName("Precondition: keyArn must be a string.")
        public void keyArn_must_be_string_with_content() {
            assertEquals(
              AwsKmsCmkArnInfo.parseInfoFromKeyArn(""),
              null
            );
            assertEquals(
              AwsKmsCmkArnInfo.parseInfoFromKeyArn(null),
              null
            );
        }

        @Test
        //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
        //= type=test
        //# MUST start with string "arn"
        public void not_well_formed() {
            assertEquals(
                    AwsKmsCmkArnInfo.parseInfoFromKeyArn("key/mrk-edb7fe6942894d32ac46dbb1c922d574"),
                    null
            );
            assertEquals(
                    AwsKmsCmkArnInfo.parseInfoFromKeyArn("alias/my-key"),
                    null
            );
            assertEquals(
                    AwsKmsCmkArnInfo.parseInfoFromKeyArn("not-an-arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574"),
                    null
            );
        }

        @Test
        //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
        //= type=test
        //# The service MUST be the string "kms"
        public void not_kms_service() {
            assertEquals(
                    AwsKmsCmkArnInfo.parseInfoFromKeyArn("arn:aws:sqs:us-east-2:444455556666:queue1"),
                    null
            );
        }

        @Test
        //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
        //= type=test
        //# The partition MUST be a non-empty
        public void partition_non_empty() {
            assertEquals(
                    AwsKmsCmkArnInfo.parseInfoFromKeyArn("arn::kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574"),
                    null
            );
        }

        @Test
        //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
        //= type=test
        //# The region MUST be a non-empty string
        public void region_non_empty() {
            assertEquals(
              AwsKmsCmkArnInfo.parseInfoFromKeyArn("arn:aws:kms::111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574"),
              null
            );
        }

        @Test
        //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
        //= type=test
        //# The account MUST be a non-empty string
        public void account_non_empty() {
            assertEquals(
              AwsKmsCmkArnInfo.parseInfoFromKeyArn("arn:aws:kms:us-west-2::key/mrk-edb7fe6942894d32ac46dbb1c922d574"),
              null
            );
        }

        @Test
        //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
        //= type=test
        //# The resource section MUST be non-empty and MUST be split by a
        //# single "/" any additional "/" are included in the resource id
        public void resource_non_empty() {
            //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
            //= type=test
            //# The resource id MUST be a non-empty string
            assertEquals(
              AwsKmsCmkArnInfo.parseInfoFromKeyArn("arn:aws:kms:us-west-2:111122223333:"),
              null
            );
            assertEquals(
              // This is a valid ARN but not valid for AWS KMS
              AwsKmsCmkArnInfo.parseInfoFromKeyArn("arn:aws:kms:us-west-2:111122223333:key:mrk-edb7fe6942894d32ac46dbb1c922d574"),
              null
            );
            final AwsKmsCmkArnInfo arn = AwsKmsCmkArnInfo.parseInfoFromKeyArn("arn:aws:kms:us-west-2:111122223333:alias/has/slashes");
            assertNotNull(arn);
            assertEquals(arn.getResource(), "has/slashes");
        }

        //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
        //= type=test
        //# The resource type MUST be either "alias" or "key"
        public void resource_type_key_or_alias() {
            assertEquals(
              AwsKmsCmkArnInfo.parseInfoFromKeyArn("arn:aws:kms:us-west-2:111122223333:not-key/mrk-edb7fe6942894d32ac46dbb1c922d574"),
              null
            );
        }
    }

    public static class validAwsKmsIdentifier {

        @Test
        public void basic_use() {
            AwsKmsCmkArnInfo.validAwsKmsIdentifier("mrk-edb7fe6942894d32ac46dbb1c922d574");
            AwsKmsCmkArnInfo.validAwsKmsIdentifier("alias/my-alias");
            AwsKmsCmkArnInfo.validAwsKmsIdentifier("arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574");
            AwsKmsCmkArnInfo.validAwsKmsIdentifier("arn:aws:kms:us-west-2:111122223333:alias/my-alias");
        }

        @Test
        @DisplayName("Exceptional Postcondition: Null or empty string is not a valid identifier.")
        public void must_have_content() {
            assertThrows(
              IllegalArgumentException.class,
              "Null or empty string is not a valid Aws KMS identifier.",
              () -> AwsKmsCmkArnInfo.validAwsKmsIdentifier(""));
            assertThrows(
              IllegalArgumentException.class,
              "Null or empty string is not a valid Aws KMS identifier.",
              () -> AwsKmsCmkArnInfo.validAwsKmsIdentifier(null));
        }

        @Test
        @DisplayName("Exceptional Postcondition: Things that start with `arn:` MUST be ARNs.")
        public void arn_must_be_arn() {
            assertThrows(
              IllegalArgumentException.class,
              "Invalid ARN used as an identifier.",
              () -> AwsKmsCmkArnInfo.validAwsKmsIdentifier("arn:aws:dynamodb:us-east-2:123456789012:table/myDynamoDBTable"));
        }

        @Test
        @DisplayName("Postcondition: Raw alias starts with `alias/`.")
        public void alias_is_valid() {
            AwsKmsCmkArnInfo.validAwsKmsIdentifier("alias/some/kind/of/alias");
        }

        @Test
        @DisplayName("Postcondition: There are no requirements on key ids.")
        public void anything_else_is_key_id() {
            AwsKmsCmkArnInfo.validAwsKmsIdentifier("mrk-edb7fe6942894d32ac46dbb1c922d574");
            AwsKmsCmkArnInfo.validAwsKmsIdentifier("b3537ef1-d8dc-4780-9f5a-55776cbb2f7f");
        }
    }

    public static class isMRK {
        @Test
        //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.9
        //= type=test
        //# This function MUST take a single AWS KMS identifier
        public void basic_use() {
            //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.9
            //= type=test
            //# If the input starts
            //# with "mrk-", this is a multi-Region key id and MUST return true.
            assertEquals(
                    AwsKmsCmkArnInfo.isMRK("mrk-edb7fe6942894d32ac46dbb1c922d574"),
                    true
            );
            //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.9
            //= type=test
            //# If the input starts with "alias/", this an AWS KMS alias and
            //# not a multi-Region key id and MUST return false.
            assertEquals(
                    AwsKmsCmkArnInfo.isMRK("alias/mrk-1234"),
                    false
            );
            //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.9
            //= type=test
            //# If
            //# the input does not start with any of the above, this is not a multi-
            //# Region key id and MUST return false.
            assertEquals(
                    AwsKmsCmkArnInfo.isMRK("64339c87-2ae4-42b1-8875-c83fc47acc97"),
                    false
            );
            //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.9
            //= type=test
            //# If the input starts with "arn:", this MUST return the output of
            //# identifying an an AWS KMS multi-Region ARN (aws-kms-key-
            //# arn.md#identifying-an-an-aws-kms-multi-region-arn) called with this
            //# input.
            assertEquals(
              AwsKmsCmkArnInfo.isMRK("arn:aws:kms:us-west-2:111122223333:alias/mrk-edb7fe6942894d32ac46dbb1c922d574"),
              false
            );
        }

        @Test
        //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.8
        //= type=test
        //# If the input is an invalid AWS KMS ARN this function MUST error.
        public void invalid_arn() {
            assertThrows(
              () -> AwsKmsCmkArnInfo.isMRK(AwsKmsCmkArnInfo.parseInfoFromKeyArn("arn:aws:kms:us-west-2:111122223333:not-key/mrk-edb7fe6942894d32ac46dbb1c922d574"))
            );
        }

        @Test
        //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.8
        //= type=test
        //# If resource type is "alias", this is an AWS KMS alias ARN and MUST
        //# return false.
        public void with_an_alias_AwsKmsCmkArnInfo() {
            assertEquals(
              AwsKmsCmkArnInfo.isMRK(AwsKmsCmkArnInfo.parseInfoFromKeyArn("arn:aws:kms:us-west-2:111122223333:alias/mrk-edb7fe6942894d32ac46dbb1c922d574")),
              false
            );
        }

        @Test
        //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.8
        //= type=test
        //# This function MUST take a single AWS KMS ARN
        public void with_an_mrk_AwsKmsCmkArnInfo() {
            //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.8
            //= type=test
            //# If resource type is "key" and resource ID starts with
            //# "mrk-", this is a AWS KMS multi-Region key ARN and MUST return true.
            assertEquals(
              AwsKmsCmkArnInfo.isMRK(AwsKmsCmkArnInfo.parseInfoFromKeyArn("arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574")),
              true
            );
        }

        @Test
        //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.8
        //= type=test
        //# If resource type is "key" and resource ID does not start with "mrk-",
        //# this is a (single-region) AWS KMS key ARN and MUST return false.
        public void with_an_srk_AwsKmsCmkArnInfo() {
            assertEquals(
              AwsKmsCmkArnInfo.isMRK(AwsKmsCmkArnInfo.parseInfoFromKeyArn("arn:aws:kms:us-west-2:111122223333:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f")),
              false
            );
        }
    }

    public static class awsKmsArnMatchForDecrypt {
        @Test
        //= compliance/framework/aws-kms/aws-kms-mrk-match-for-decrypt.txt#2.5
        //= type=test
        //# The caller MUST provide:
        public void basic_use() {
            assertEquals(
                    AwsKmsCmkArnInfo.awsKmsArnMatchForDecrypt(
                            "arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574",
                            "arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574"
                    ),
                    true
            );
            assertEquals(
                    AwsKmsCmkArnInfo.awsKmsArnMatchForDecrypt(
                            "arn:aws:kms:us-east-1:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574",
                            "arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574"
                    ),
                    true
            );
        }

        @Test
        //= compliance/framework/aws-kms/aws-kms-mrk-match-for-decrypt.txt#2.5
        //= type=test
        //# If both identifiers are identical, this function MUST return "true".
        public void string_match_cases() {

            assertEquals(
              AwsKmsCmkArnInfo.awsKmsArnMatchForDecrypt(
                "arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574",
                "arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574"
              ),
              true
            );

            assertEquals(
              AwsKmsCmkArnInfo.awsKmsArnMatchForDecrypt(
                "arn:aws:kms:us-west-2:111122223333:key/64339c87-2ae4-42b1-8875-c83fc47acc97",
                "arn:aws:kms:us-west-2:111122223333:key/64339c87-2ae4-42b1-8875-c83fc47acc97"
              ),
              true
            );

            assertEquals(
              AwsKmsCmkArnInfo.awsKmsArnMatchForDecrypt(
                "arn:aws:kms:us-west-2:111122223333:alias/my-name",
                "arn:aws:kms:us-west-2:111122223333:alias/my-name"
              ),
              true
            );

            assertEquals(
              AwsKmsCmkArnInfo.awsKmsArnMatchForDecrypt(
                "alias/my-raw-alias",
                "alias/my-raw-alias"
              ),
              true
            );

            assertEquals(
              AwsKmsCmkArnInfo.awsKmsArnMatchForDecrypt(
                "64339c87-2ae4-42b1-8875-c83fc47acc97",
                "64339c87-2ae4-42b1-8875-c83fc47acc97"
              ),
              true
            );

            assertEquals(
              AwsKmsCmkArnInfo.awsKmsArnMatchForDecrypt(
                "c83fc47acc97",
                "64339c87-2ae4-42b1-8875-c83fc47acc97"
              ),
              false
            );
        }

        @Test
        @DisplayName("Check for early return (Postcondition): Both identifiers are not ARNs and not equal, therefore they can not match.")
        public void flexibility_for_only_arns() {
            assertEquals(
              AwsKmsCmkArnInfo.awsKmsArnMatchForDecrypt(
                "arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574",
                "mrk-edb7fe6942894d32ac46dbb1c922d574"
              ),
              false
            );
            assertEquals(
              AwsKmsCmkArnInfo.awsKmsArnMatchForDecrypt(
                "mrk-edb7fe6942894d32ac46dbb1c922d574",
                "arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574"
              ),
              false
            );
        }


        @Test
        //= compliance/framework/aws-kms/aws-kms-mrk-match-for-decrypt.txt#2.5
        //= type=test
        //# Otherwise if either input is not identified as a multi-Region key
        //# (aws-kms-key-arn.md#identifying-an-aws-kms-multi-region-key), then
        //# this function MUST return "false".
        public void no_flexibility_for_non_mrks() {
            assertEquals(
              AwsKmsCmkArnInfo.awsKmsArnMatchForDecrypt(
                "arn:aws:kms:us-west-2:111122223333:key/64339c87-2ae4-42b1-8875-c83fc47acc97",
                "arn:aws:kms:us-east-1:111122223333:key/64339c87-2ae4-42b1-8875-c83fc47acc97"
              ),
              false
            );
            assertEquals(
              AwsKmsCmkArnInfo.awsKmsArnMatchForDecrypt(
                "arn:aws:kms:us-west-2:111122223333:alias/mrk-someOtherName",
                "arn:aws:kms:us-east-1:111122223333:alias/mrk-someOtherName"
              ),
              false
            );
        }

        @Test
        //= compliance/framework/aws-kms/aws-kms-mrk-match-for-decrypt.txt#2.5
        //= type=test
        //# Otherwise if both inputs are
        //# identified as a multi-Region keys (aws-kms-key-arn.md#identifying-an-
        //# aws-kms-multi-region-key), this function MUST return the result of
        //# comparing the "partition", "service", "accountId", "resourceType",
        //# and "resource" parts of both ARN inputs.
        public void all_elements_must_match() {
            // Different partition
            assertEquals(
                    AwsKmsCmkArnInfo.awsKmsArnMatchForDecrypt(
                            "arn:not-aws:kms:us-east-1:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574",
                            "arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574"
                    ),
                    false
            );
            // Different account
            assertEquals(
                    AwsKmsCmkArnInfo.awsKmsArnMatchForDecrypt(
                            "arn:aws:kms:us-east-1:333322221111:key/mrk-edb7fe6942894d32ac46dbb1c922d574",
                            "arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574"
                    ),
                    false
            );
            // Different resource type
            assertEquals(
                    AwsKmsCmkArnInfo.awsKmsArnMatchForDecrypt(
                            "arn:not-aws:kms:us-east-1:111122223333:not-key/mrk-edb7fe6942894d32ac46dbb1c922d574",
                            "arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574"
                    ),
                    false
            );
            // Different resource
            assertEquals(
                    AwsKmsCmkArnInfo.awsKmsArnMatchForDecrypt(
                            "arn:aws:kms:us-east-1:111122223333:key/mrk-475d229c1bbd64ca23d4982496ef7bde",
                            "arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574"
                    ),
                    false
            );
        }
    }

    public static class to_string_tests {
        @Test
        public void basic_use() {
            final String arn = "arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574";
            final String region = "us-east-1";
            final AwsKmsCmkArnInfo test = AwsKmsCmkArnInfo.parseInfoFromKeyArn(arn);

            assertEquals(arn, test.toString());
            assertEquals(
                    "arn:aws:kms:us-east-1:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574",
                    test.toString("us-east-1")
            );
        }
    }

}
