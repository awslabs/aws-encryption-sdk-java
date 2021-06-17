package com.amazonaws.encryptionsdk.internal;

import java.util.Arrays;


/**
 * A class to parse and handle AWS KMS identifiers.
 * Mostly AWS KMS ARNs but raw resources
 * are also used in the AWS Encryption SDK.
 */
public final class AwsKmsCmkArnInfo {
    final private static String arnLiteral = "arn";
    final private static String kmsServiceName = "kms";

    /**
     * Takes an AWS KMS identifier that may or may not be an ARN
     * and attempts to parse the identifier as an ARN.
     * If the identifier is not an ARN, it returns
     * null. This is an expected condition, not an error.
     *
     * @param keyArn The string to parse
     */
    public static AwsKmsCmkArnInfo parseInfoFromKeyArn(final String keyArn) {
        /* Precondition: keyArn must be a string. */
        if (keyArn == null || keyArn.isEmpty()) return null;

        final String[] parts = AwsKmsArnParts.splitArn(keyArn);

        //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
        //# MUST start with string "arn"
        if (!arnLiteral.equals(parts[AwsKmsArnParts.ArnLiteral.index()])) {
            return null;
        }

        //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
        //# The service MUST be the string "kms"
        if (!kmsServiceName.equals(parts[AwsKmsArnParts.Service.index()])) {
            return null;
        }

        //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
        //# The partition MUST be a non-empty
        //
        //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
        //# The region MUST be a non-empty string
        //
        //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
        //# The account MUST be a non-empty string
        //
        final boolean emptyParts = Arrays.stream(parts).anyMatch(String::isEmpty);
        if (emptyParts || AwsKmsArnParts.values().length != parts.length) return null;

        //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
        //# The resource section MUST be non-empty and MUST be split by a
        //# single "/" any additional "/" are included in the resource id
        String[] resourceParts = AwsKmsArnParts
                .Resource
                .splitResourceParts(parts[AwsKmsArnParts.ResourceParts.index()]);

        //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
        //# The resource id MUST be a non-empty string
        if (Arrays.stream(resourceParts).anyMatch(String::isEmpty)
        || AwsKmsArnParts.Resource.values().length > resourceParts.length
        ) {
            return null;
        }

        //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
        //# The resource type MUST be either "alias" or "key"
        if (!("key".equals(resourceParts[AwsKmsArnParts.Resource.ResourceType.index()])
        || "alias".equals(resourceParts[AwsKmsArnParts.Resource.ResourceType.index()]))) {
            return null;
        }

        return new AwsKmsCmkArnInfo(
                parts[AwsKmsArnParts.Partition.index()],
                parts[AwsKmsArnParts.Region.index()],
                parts[AwsKmsArnParts.Account.index()],
                resourceParts[AwsKmsArnParts.Resource.ResourceType.index()],
                resourceParts[AwsKmsArnParts.Resource.Resource.index()]
        );
    }

    /** Takes a string an will throw if this identifier is invalid
     * Raw resources like a key ID or alias
     * `mrk-edb7fe6942894d32ac46dbb1c922d574`, `alias/my-alias`
     * or ARNs like
     * arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574
     * arn:aws:kms:us-west-2:111122223333:alias/my-alias
     *
     * @param identifier an identifier that is an ARN or raw resource
     */
    public static void validAwsKmsIdentifier(final String identifier) {
        /* Exceptional Postcondition: Null or empty string is not a valid identifier. */
        if (identifier == null || identifier.isEmpty()) {
            throw new IllegalArgumentException("Null or empty string is not a valid Aws KMS identifier.");
        }

        /* Exceptional Postcondition: Things that start with `arn:` MUST be ARNs. */
        if (identifier.startsWith("arn:") && parseInfoFromKeyArn(identifier) == null) {
            throw new IllegalArgumentException("Invalid ARN used as an identifier.");
        };
        /* Postcondition: Raw alias starts with `alias/`. */
        if (identifier.startsWith("alias/")) return;

        /* Postcondition: There are no requirements on key ids.
         * Even thought they look like UUID, this is not required.
         * Take multi region keys: mrk-edb7fe6942894d32ac46dbb1c922d574
         */
        return;
    }

    //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.9
    //# This function MUST take a single AWS KMS identifier
    /**
     * Identifies Multi Region AWS KMS keys.
     * This can misidentify an alias that starts with "mrk-".
     *
     */
    public static boolean isMRK(final String resource) {
        //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.9
        //# If the input starts with "arn:", this MUST return the output of
        //# identifying an an AWS KMS multi-Region ARN (aws-kms-key-
        //# arn.md#identifying-an-an-aws-kms-multi-region-arn) called with this
        //# input.
        if (resource.startsWith("arn:")) return isMRK(parseInfoFromKeyArn(resource));
        //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.9
        //# If the input starts with "alias/", this an AWS KMS alias and
        //# not a multi-Region key id and MUST return false.
        if (resource.startsWith("alias/")) return false;
        //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.9
        //# If the input starts
        //# with "mrk-", this is a multi-Region key id and MUST return true.
        //
        //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.9
        //# If
        //# the input does not start with any of the above, this is not a multi-
        //# Region key id and MUST return false.
        return resource.startsWith("mrk-");
    }

    //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.8
    //# This function MUST take a single AWS KMS ARN
    /**
     * Identifies Multi Region AWS KMS keys.
     * The resource type check is to protect against the edge case where an alias starts with
     * `mrk-` * e.g. arn:aws:kms:us-west-2:111122223333:alias/mrk-someOtherName
     *
     */
    public static boolean isMRK(final AwsKmsCmkArnInfo arn) {

        //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.8
        //# If the input is an invalid AWS KMS ARN this function MUST error.
        if (arn == null) throw new Error("Invalid Arn");

        //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.8
        //# If resource type is "alias", this is an AWS KMS alias ARN and MUST
        //# return false.
        //
        //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.8
        //# If resource type is "key" and resource ID starts with
        //# "mrk-", this is a AWS KMS multi-Region key ARN and MUST return true.
        //
        //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.8
        //# If resource type is "key" and resource ID does not start with "mrk-",
        //# this is a (single-region) AWS KMS key ARN and MUST return false.
        return isMRK(arn.getResource()) && arn.getResourceType().equals("key");
    }

    //= compliance/framework/aws-kms/aws-kms-mrk-match-for-decrypt.txt#2.5
    //# The caller MUST provide:
    /**
     * Tell if two different AWS KMS ARNs match.
     * For identical keys this is trivial,
     * but multi-Region keys can match across regions.
     *
     */
    public static boolean awsKmsArnMatchForDecrypt(
            final String configuredKeyIdentifier,
            final String providerInfoKeyIdentifier
    ) {
        //= compliance/framework/aws-kms/aws-kms-mrk-match-for-decrypt.txt#2.5
        //# If both identifiers are identical, this function MUST return "true".
        if (configuredKeyIdentifier.equals(providerInfoKeyIdentifier)) return true;

        final AwsKmsCmkArnInfo configuredArnInfo = parseInfoFromKeyArn(configuredKeyIdentifier);
        final AwsKmsCmkArnInfo providerInfoKeyArnInfo = parseInfoFromKeyArn(providerInfoKeyIdentifier);

        /* Check for early return (Postcondition): Both identifiers are not ARNs and not equal, therefore they can not match. */
        if (providerInfoKeyArnInfo == null || configuredArnInfo == null) return false;

        //= compliance/framework/aws-kms/aws-kms-mrk-match-for-decrypt.txt#2.5
        //# Otherwise if either input is not identified as a multi-Region key
        //# (aws-kms-key-arn.md#identifying-an-aws-kms-multi-region-key), then
        //# this function MUST return "false".
        if (!isMRK(configuredArnInfo) || !isMRK(providerInfoKeyArnInfo)) return false;

        //= compliance/framework/aws-kms/aws-kms-mrk-match-for-decrypt.txt#2.5
        //# Otherwise if both inputs are
        //# identified as a multi-Region keys (aws-kms-key-arn.md#identifying-an-
        //# aws-kms-multi-region-key), this function MUST return the result of
        //# comparing the "partition", "service", "accountId", "resourceType",
        //# and "resource" parts of both ARN inputs.
        //Service is not matched because AwsKmsCmkArnInfo only allows a service of `kms`.
        return configuredArnInfo.getPartition().equals(providerInfoKeyArnInfo.getPartition()) &&
                configuredArnInfo.getAccountId().equals(providerInfoKeyArnInfo.getAccountId()) &&
                configuredArnInfo.getResourceType().equals(providerInfoKeyArnInfo.getResourceType()) &&
                configuredArnInfo.getResource().equals(providerInfoKeyArnInfo.getResource());
    }

    private final String partition_;
    private final String accountId_;
    private final String region_;
    private final String resource_;
    private final String resourceType_;

    /**
     * Data structure to hold the parts of an AWS KMS ARN
     *
     */
    AwsKmsCmkArnInfo(
        String partition,
        String region,
        String accountId,
        String resourceType,
        String resource
    ) {
        partition_ = partition;
        region_ = region;
        accountId_ = accountId;
        resourceType_ = resourceType;
        resource_ = resource;
    }

    public String getPartition() {
        return partition_;
    }

    public String getAccountId() {
        return accountId_;
    }

    public String getRegion() {
        return region_;
    }

    public String getResourceType() { return resourceType_; }

    public String getResource() { return resource_; }


    /**
     * Returns the well-formed ARN this object describes.
     *
     */
    @Override
    public String toString() {
        return toString(region_);
    }

    /**
     * AWS KMS multi-Region keys can have replicas in other region.
     * A compatible ARN in a different Region may be required.
     *
     * @param mrkRegion The region to use instead of the region in the ARN
     */
    public String toString(String mrkRegion) {
        return String.join(
                AwsKmsArnParts.Delimiter,
                arnLiteral,
                partition_,
                kmsServiceName,
                mrkRegion,
                accountId_,
                String.join(
                        AwsKmsArnParts.Resource.ResourceDelimiter,
                        resourceType_,
                        resource_));
    }

    /**
     * Structure information about an ARN.
     * This structure is only expecting
     * to process AWS KMS ARNs
     * see https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html
     * for more details.
     *
     */
    enum AwsKmsArnParts {
        ArnLiteral(0),
        Partition(1),
        Service(2),
        Region(3),
        Account(4),
        ResourceParts(5);

        int index_;
        AwsKmsArnParts(int i) {
            index_ = i;
        }
        int index() {
            return index_;
        }

        public static String[] splitArn(String arn) {
            return arn.split(
                    AwsKmsArnParts.Delimiter,
                    AwsKmsArnParts.values().length);
        }

        static String Delimiter = ":";

        /**
         * Structure information about the resource part of an ARN
         * This structure is only expecting
         * to process AWS KMS ARNs
         * see https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html
         * for more details.
         *
         * Of note, is that the ARN specification lets the `/` also be a `:`
         * however AWS KMS does not support this.
         * AWS KMS _only_ uses `/` to delimit the resource type and resource.
         *
         */
        enum Resource {
            ResourceType(0),
            Resource(1);

            static String ResourceDelimiter = "/";

            int index_;
            Resource(int i) {
                index_ = i;
            }
            int index() {
                return index_;
            }

            public static String[] splitResourceParts(String resource) {
                return resource.split(
                        ResourceDelimiter,
                        2);
            }
        }
    }
}
