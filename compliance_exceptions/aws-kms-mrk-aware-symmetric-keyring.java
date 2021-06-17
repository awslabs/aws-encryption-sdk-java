// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// The AWS Encryption SDK - Java does not implement
// any of the Keyring interface at this time.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.5
//= type=exception
//# MUST implement the AWS Encryption SDK Keyring interface (../keyring-
//# interface.md#interface)

//= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.6
//= type=exception
//# On initialization the caller MUST provide:
//#
//# *  An AWS KMS key identifier
//#
//# *  An AWS KMS SDK client
//#
//# *  An optional list of Grant Tokens
//#
//# The AWS KMS key identifier MUST NOT be null or empty.  The AWS KMS
//# key identifier MUST be a valid identifier (aws-kms-key-arn.md#a-
//# valid-aws-kms-identifier).  The AWS KMS SDK client MUST NOT be null.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
//= type=exception
//# OnEncrypt MUST take encryption materials (structures.md#encryption-
//# materials) as input.
//#
//# If the input encryption materials (structures.md#encryption-
//# materials) do not contain a plaintext data key OnEncrypt MUST attempt
//# to generate a new plaintext data key by calling AWS KMS
//# GenerateDataKey (https://docs.aws.amazon.com/kms/latest/APIReference/
//# API_GenerateDataKey.html).
//#
//# If the keyring calls AWS KMS GenerateDataKeys, it MUST use the
//# configured AWS KMS client to make the call.  The keyring MUST call
//# AWS KMS GenerateDataKeys with a request constructed as follows:
//#
//# *  "KeyId": this keyring's KMS key identifier.
//#
//# *  "NumberOfBytes": the key derivation input length (algorithm-
//#    suites.md#key-derivation-input-length) specified by the algorithm
//#    suite (algorithm-suites.md) included in the input encryption
//#    materials (structures.md#encryption-materials).
//#
//# *  "EncryptionContext": the encryption context
//#    (structures.md#encryption-context) included in the input
//#    encryption materials (structures.md#encryption-materials).
//#
//# *  "GrantTokens": this keyring's grant tokens
//#    (https://docs.aws.amazon.com/kms/latest/developerguide/
//#    concepts.html#grant_token)
//#
//# If the call to AWS KMS GenerateDataKey
//# (https://docs.aws.amazon.com/kms/latest/APIReference/
//# API_GenerateDataKey.html) does not succeed, OnEncrypt MUST NOT modify
//# the encryption materials (structures.md#encryption-materials) and
//# MUST fail.
//#
//# If the Generate Data Key call succeeds, OnEncrypt MUST verify that
//# the response "Plaintext" length matches the specification of the
//# algorithm suite (algorithm-suites.md)'s Key Derivation Input Length
//# field.  The Generate Data Key response's "KeyId" MUST be A valid AWS
//# KMS key ARN (aws-kms-key-arn.md#identifying-an-aws-kms-multi-region-
//# key).  If verified, OnEncrypt MUST do the following with the response
//# from AWS KMS GenerateDataKey
//# (https://docs.aws.amazon.com/kms/latest/APIReference/
//# API_GenerateDataKey.html):
//#
//# *  set the plaintext data key on the encryption materials
//#    (structures.md#encryption-materials) as the response "Plaintext".
//#
//# *  append a new encrypted data key (structures.md#encrypted-data-key)
//#    to the encrypted data key list in the encryption materials
//#    (structures.md#encryption-materials), constructed as follows:
//#
//#    -  the ciphertext (structures.md#ciphertext) is the response
//#       "CiphertextBlob".
//#
//#    -  the key provider id (structures.md#key-provider-id) is "aws-
//#       kms".
//#
//#    -  the key provider information (structures.md#key-provider-
//#       information) is the response "KeyId".
//#
//# *  OnEncrypt MUST output the modified encryption materials
//#    (structures.md#encryption-materials)
//#
//# Given a plaintext data key in the encryption materials
//# (structures.md#encryption-materials), OnEncrypt MUST attempt to
//# encrypt the plaintext data key using the configured AWS KMS key
//# identifier.
//#
//# The keyring MUST call AWS KMS Encrypt
//# (https://docs.aws.amazon.com/kms/latest/APIReference/
//# API_Encrypt.html) using the configured AWS KMS client.  The keyring
//# MUST AWS KMS Encrypt call with a request constructed as follows:
//#
//# *  "KeyId": The configured AWS KMS key identifier.
//#
//# *  "PlaintextDataKey": the plaintext data key in the encryption
//#    materials (structures.md#encryption-materials).
//#
//# *  "EncryptionContext": the encryption context
//#    (structures.md#encryption-context) included in the input
//#    encryption materials (structures.md#encryption-materials).
//#
//# *  "GrantTokens": this keyring's grant tokens
//#    (https://docs.aws.amazon.com/kms/latest/developerguide/
//#    concepts.html#grant_token)
//#
//# If the call to AWS KMS Encrypt
//# (https://docs.aws.amazon.com/kms/latest/APIReference/
//# API_Encrypt.html) does not succeed, OnEncrypt MUST fail.
//#
//# If the Encrypt call succeeds The response's "KeyId" MUST be A valid
//# AWS KMS key ARN (aws-kms-key-arn.md#identifying-an-aws-kms-multi-
//# region-key).  If verified, OnEncrypt MUST do the following with the
//# response from AWS KMS Encrypt
//# (https://docs.aws.amazon.com/kms/latest/APIReference/
//# API_Encrypt.html):
//#
//# *  append a new encrypted data key (structures.md#encrypted-data-key)
//#    to the encrypted data key list in the encryption materials
//#    (structures.md#encryption-materials), constructed as follows:
//#
//#    -  The ciphertext (structures.md#ciphertext) is the response
//#       "CiphertextBlob".
//#
//#    -  The key provider id (structures.md#key-provider-id) is "aws-
//#       kms".
//#
//#    -  The key provider information (structures.md#key-provider-
//#       information) is the response "KeyId".  Note that the "KeyId" in
//#       the response is always in key ARN format.
//#
//# If all Encrypt calls succeed, OnEncrypt MUST output the modified
//# encryption materials (structures.md#encryption-materials).

//= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
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
//# *  The the function AWS KMS MRK Match for Decrypt (aws-kms-mrk-match-
//#    for-decrypt.md#implementation) called with the configured AWS KMS
//#    key identifier and the provider info MUST return "true".
//#
//# For each encrypted data key in the filtered set, one at a time, the
//# OnDecrypt MUST attempt to decrypt the data key.  If this attempt
//# results in an error, then these errors MUST be collected.
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
//# *  "KeyId": The configured AWS KMS key identifier.
//#
//# *  "CiphertextBlob": the encrypted data key ciphertext
//#    (structures.md#ciphertext).
//#
//# *  "EncryptionContext": the encryption context
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
//# *  The "KeyId" field in the response MUST equal the configured AWS
//#    KMS key identifier.
//#
//# *  The length of the response's "Plaintext" MUST equal the key
//#    derivation input length (algorithm-suites.md#key-derivation-input-
//#    length) specified by the algorithm suite (algorithm-suites.md)
//#    included in the input decryption materials
//#    (structures.md#decryption-materials).
//#
//# If the response does not satisfies these requirements then an error
//# MUST be collected and the next encrypted data key in the filtered set
//# MUST be attempted.
//#
//# If the response does satisfies these requirements then OnDecrypt MUST
//# do the following with the response:
//#
//# *  set the plaintext data key on the decryption materials
//#    (structures.md#decryption-materials) as the response "Plaintext".
//#
//# *  immediately return the modified decryption materials
//#    (structures.md#decryption-materials).
//#
//# If OnDecrypt fails to successfully decrypt any encrypted data key
//# (structures.md#encrypted-data-key), then it MUST yield an error that
//# includes all the collected errors.





