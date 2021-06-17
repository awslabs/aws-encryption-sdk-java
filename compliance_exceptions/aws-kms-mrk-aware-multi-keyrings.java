// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// The AWS Encryption SDK - Java does not implement
// any of the Keyring interface at this time.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.5
//= type=exception
//# The caller MUST provide:
//#
//# *  A set of Region strings
//#
//# *  An optional discovery filter that is an AWS partition and a set of
//#    AWS accounts
//#
//# *  An optional method that can take a region string and return an AWS
//#    KMS client e.g. a regional client supplier
//#
//# *  An optional list of AWS KMS grant tokens
//#
//# If an empty set of Region is provided this function MUST fail.  If
//# any element of the set of regions is null or an empty string this
//# function MUST fail.  If a regional client supplier is not passed,
//# then a default MUST be created that takes a region string and
//# generates a default AWS SDK client for the given region.
//#
//# A set of AWS KMS clients MUST be created by calling regional client
//# supplier for each region in the input set of regions.
//#
//# Then a set of AWS KMS MRK Aware Symmetric Region Discovery Keyring
//# (aws-kms-mrk-aware-symmetric-region-discovery-keyring.md) MUST be
//# created for each AWS KMS client by initializing each keyring with
//#
//# *  The AWS KMS client
//#
//# *  The input discovery filter
//#
//# *  The input AWS KMS grant tokens
//#
//# Then a Multi-Keyring (../multi-keyring.md#inputs) MUST be initialize
//# by using this set of discovery keyrings as the child keyrings
//# (../multi-keyring.md#child-keyrings).  This Multi-Keyring MUST be
//# this functions output.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
//= type=exception
//# The caller MUST provide:
//#
//# *  An optional AWS KMS key identifiers to use as the generator.
//#
//# *  An optional set of AWS KMS key identifiers to us as child
//#    keyrings.
//#
//# *  An optional method that can take a region string and return an AWS
//#    KMS client e.g. a regional client supplier
//#
//# *  An optional list of AWS KMS grant tokens
//#
//# If any of the AWS KMS key identifiers is null or an empty string this
//# function MUST fail.  At least one non-null or non-empty string AWS
//# KMS key identifiers exists in the input this function MUST fail.  All
//# AWS KMS identifiers are passed to Assert AWS KMS MRK are unique (aws-
//# kms-mrk-are-unique.md#Implementation) and the function MUST return
//# success otherwise this MUST fail.  If a regional client supplier is
//# not passed, then a default MUST be created that takes a region string
//# and generates a default AWS SDK client for the given region.
//#
//# If there is a generator input then the generator keyring MUST be a
//# AWS KMS MRK Aware Symmetric Keyring (aws-kms-mrk-aware-symmetric-
//# keyring.md) initialized with
//#
//# *  The generator input.
//#
//# *  The AWS KMS client that MUST be created by the regional client
//#    supplier when called with the region part of the generator ARN or
//#    a signal for the AWS SDK to select the default region.
//#
//# *  The input list of AWS KMS grant tokens
//#
//# If there is a set of child identifiers then a set of AWS KMS MRK
//# Aware Symmetric Keyring (aws-kms-mrk-aware-symmetric-keyring.md) MUST
//# be created for each AWS KMS key identifier by initialized each
//# keyring with
//#
//# *  AWS KMS key identifier.
//#
//# *  The AWS KMS client that MUST be created by the regional client
//#    supplier when called with the region part of the AWS KMS key
//#    identifier or a signal for the AWS SDK to select the default
//#    region.
//#
//# *  The input list of AWS KMS grant tokens
//#
//# NOTE: The AWS Encryption SDK SHOULD NOT attempt to evaluate its own
//# default region.
//#
//# Then a Multi-Keyring (../multi-keyring.md#inputs) MUST be initialize
//# by using this generator keyring as the generator keyring (../multi-
//# keyring.md#generator-keyring) and this set of child keyrings as the
//# child keyrings (../multi-keyring.md#child-keyrings).  This Multi-
//# Keyring MUST be this functions output.



