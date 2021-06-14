// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// The AWS Encryption SDK - Java does not implement
// any of the Keyring interface at this time.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.5
//= type=exception
//# MUST implement that AWS Encryption SDK Keyring interface (../keyring-
//# interface.md#interface)

//= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.6
//= type=exception
//# On initialization the caller MUST provide:
//#
//# *  An AWS KMS client
//#
//# *  An optional discovery filter that is an AWS partition and a set of
//#    AWS accounts
//#
//# *  An optional list of AWS KMS grant tokens
//#
//# The keyring MUST know what Region the AWS KMS client is in.  It
//# SHOULD obtain this information directly from the client as opposed to
//# having an additional parameter.  However if it can not, then it MUST
//# NOT create the client itself.  It SHOULD have a Region parameter and
//# SHOULD try to identify mismatched configurations. i.e. The client is
//# in Region A and the Region parameter is B.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.7
//= type=exception
//# This function MUST fail.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
//= type=exception
//# OnDecrypt MUST take decryption materials (structures.md#decryption-
//# materials) and a list of encrypted data keys
//# (structures.md#encrypted-data-key) as input.
//#
//# If the decryption materials (structures.md#decryption-materials)
//# already contained a valid plaintext data key OnDecrypt MUST
//# immediately return the unmodified decryption materials
//# (structures.md#decryption-materials).
//#
//# The set of encrypted data keys MUST first be filtered to match this
//# keyring's configuration.  For the encrypted data key to match
//#
//# *  Its provider ID MUST exactly match the value "aws-kms".
//#
//# *  The provider info MUST be a valid AWS KMS ARN (aws-kms-key-
//#    arn.md#a-valid-aws-kms-arn) with a resource type of "key" or
//#    OnDecrypt MUST fail.
//#
//# *  If a discovery filter is configured, its partition and the
//#    provider info partition MUST match.
//#
//# *  If a discovery filter is configured, its set of accounts MUST
//#    contain the provider info account.
//#
//# *  If the provider info is not identified as a multi-Region key (aws-
//#    kms-key-arn.md#identifying-an-aws-kms-multi-region-key), then the
//#    provider info's Region MUST match the AWS KMS client region.
//#
//# For each encrypted data key in the filtered set, one at a time, the
//# OnDecrypt MUST attempt to decrypt the data key.  If this attempt
//# results in an error, then these errors are collected.
//#
//# To attempt to decrypt a particular encrypted data key
//# (structures.md#encrypted-data-key), OnDecrypt MUST call AWS KMS
//# Decrypt (https://docs.aws.amazon.com/kms/latest/APIReference/
//# API_Decrypt.html) with the configured AWS KMS client.
//#
//# When calling AWS KMS Decrypt
//# (https://docs.aws.amazon.com/kms/latest/APIReference/
//# API_Decrypt.html), the keyring MUST call with a request constructed
//# as follows:
//#
//# *  "KeyId": If the provider info's resource type is "key" and its
//#    resource is a multi-Region key then a new ARN MUST be created
//#    where the region part MUST equal the AWS KMS client region and
//#    every other part MUST equal the provider info.  Otherwise it MUST
//#    be the provider info.
//#
//# *  "CiphertextBlob": The encrypted data key ciphertext
//#    (structures.md#ciphertext).
//#
//# *  "EncryptionContext": The encryption context
//#    (structures.md#encryption-context) included in the input
//#    decryption materials (structures.md#decryption-materials).
//#
//# *  "GrantTokens": this keyring's grant tokens
//#    (https://docs.aws.amazon.com/kms/latest/developerguide/
//#    concepts.html#grant_token)
//#
//# If the call to AWS KMS Decrypt
//# (https://docs.aws.amazon.com/kms/latest/APIReference/
//# API_Decrypt.html) succeeds OnDecrypt verifies
//#
//# *  The "KeyId" field in the response MUST equal the requested "KeyId"
//#
//# *  The length of the response's "Plaintext" MUST equal the key
//#    derivation input length (algorithm-suites.md#key-derivation-input-
//#    length) specified by the algorithm suite (algorithm-suites.md)
//#    included in the input decryption materials
//#    (structures.md#decryption-materials).
//#
//# If the response does not satisfies these requirements then an error
//# is collected and the next encrypted data key in the filtered set MUST
//# be attempted.
//#
//# Since the response does satisfies these requirements then OnDecrypt
//# MUST do the following with the response:
//#
//# *  set the plaintext data key on the decryption materials
//#    (structures.md#decryption-materials) as the response "Plaintext".
//#
//# *  immediately return the modified decryption materials
//#    (structures.md#decryption-materials).
//#
//# If OnDecrypt fails to successfully decrypt any encrypted data key
//# (structures.md#encrypted-data-key), then it MUST yield an error that
//# includes all collected errors.



