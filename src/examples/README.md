# AWS Encryption SDK Examples

This section features examples that show you
how to use the AWS Encryption SDK.
We demonstrate how to use the encryption and decryption APIs
and how to set up some common configuration patterns.

## APIs

The AWS Encryption SDK provides two high-level APIs:
one-step APIs that process the entire operation in memory
and streaming APIs.

You can find examples that demonstrate these APIs
in the [`examples`](./java/com/amazonaws/crypto/examples) directory.

## Configuration

To use the encryption and decryption APIs,
you need to describe how you want the library to protect your data keys.
You can do this by configuring
[keyrings](#keyrings) or [cryptographic materials managers](#cryptographic-materials-managers),
or by configuring [master key providers](#master-key-providers).
These examples will show you how to use the configuration tools that we include for you 
and how to create some of your own.
We start with AWS KMS examples, then show how to use other wrapping keys.

* Using AWS Key Management Service (AWS KMS)
    * How to use one AWS KMS CMK
        * [with keyrings](./java/com/amazonaws/crypto/examples/keyring/awskms/SingleCmk.java)
        * [with master key providers](./java/com/amazonaws/crypto/examples/masterkeyprovider/awskms/SingleCmk.java)
    * How to use multiple AWS KMS CMKs in different regions
        * [with keyrings](./java/com/amazonaws/crypto/examples/keyring/awskms/MultipleRegions.java)
        * [with master key providers](./java/com/amazonaws/crypto/examples/masterkeyprovider/awskms/MultipleRegions.java)
    * How to decrypt when you don't know the CMK
        * [with keyrings](./java/com/amazonaws/crypto/examples/keyring/awskms/DiscoveryDecrypt.java)
        * [with master key providers](./java/com/amazonaws/crypto/examples/masterkeyprovider/awskms/DiscoveryDecrypt.java)
    * How to decrypt within a region
        * [with keyrings](./java/com/amazonaws/crypto/examples/keyring/awskms/DiscoveryDecryptInRegionOnly.java)
    * How to decrypt with a preferred region but failover to others
        * [with keyrings](./java/com/amazonaws/crypto/examples/keyring/awskms/DiscoveryDecryptWithPreferredRegions.java)
    * How to reproduce the behavior of an AWS KMS master key provider
        * [with keyrings](./java/com/amazonaws/crypto/examples/keyring/awskms/ActLikeAwsKmsMasterKeyProvider.java)
    * How to use AWS KMS clients with custom configuration
        * [with keyrings](./java/com/amazonaws/crypto/examples/keyring/awskms/CustomKmsClientConfig.java)
    * How to use different AWS KMS client for different regions
        * [with keyrings](./java/com/amazonaws/crypto/examples/keyring/awskms/CustomClientSupplier.java)
* Using raw wrapping keys
    * How to use a raw AES wrapping key
        * [with keyrings](./java/com/amazonaws/crypto/examples/keyring/rawaes/RawAes.java)
        * [with master key providers](./java/com/amazonaws/crypto/examples/masterkeyprovider/rawaes/RawAes.java)
    * How to use a raw RSA wrapping key
        * [with keyrings](./java/com/amazonaws/crypto/examples/keyring/rawrsa/RawRsa.java)
        * [with master key providers](./java/com/amazonaws/crypto/examples/masterkeyprovider/rawrsa/RawRsa.java)
    * How to encrypt with a raw RSA public key wrapping key without access to the private key
        * [with keyrings](./java/com/amazonaws/crypto/examples/keyring/rawrsa/PublicPrivateKeySeparate.java)
    * How to use a raw RSA wrapping key when the key is DER encoded
        * [with keyrings](./java/com/amazonaws/crypto/examples/keyring/rawrsa/RawRsaDerEncoded.java)
* Combining wrapping keys
    * How to combine AWS KMS with an offline escrow key
        * [with keyrings](./java/com/amazonaws/crypto/examples/keyring/multi/AwsKmsWithEscrow.java)
        * [with master key providers](./java/com/amazonaws/crypto/examples/masterkeyprovider/multi/AwsKmsWithEscrow.java)
* How to reuse data keys across multiple messages
    * [with the caching cryptographic materials manager](./java/com/amazonaws/crypto/examples/cryptomaterialsmanager/caching/SimpleCache.java)
* How to restrict algorithm suites
    * [with a custom cryptographic materials manager](./java/com/amazonaws/crypto/examples/cryptomaterialsmanager/custom/AlgorithmSuiteEnforcement.java)
* How to require encryption context fields
    * [with a custom cryptographic materials manager](./java/com/amazonaws/crypto/examples/cryptomaterialsmanager/custom/RequiringEncryptionContextFields.java)

### Keyrings

Keyrings are the most common way for you to configure the AWS Encryption SDK.
They determine how the AWS Encryption SDK protects your data.
You can find these examples in ['examples/keyring`](./java/com/amazonaws/crypto/examples/keyring).

### Cryptographic Materials Managers

Keyrings define how your data keys are protected,
but there is more going on here than just protecting data keys.

Cryptographic materials managers give you higher-level controls
over how the AWS Encryption SDK protects your data.
This can include things like
enforcing the use of certain algorithm suites or encryption context settings,
reusing data keys across messages,
or changing how you interact with keyrings.
You can find these examples in
[`examples/crypto_materials_manager`](./java/com/amazonaws/crypto/examples/cryptomaterialsmanager).

### Master Key Providers

Before there were keyrings, there were master key providers.
Master key providers were the original configuration structure
that we provided for defining how you want to protect your data keys.
Keyrings provide a simpler experience and often more powerful configuration options,
but if you need to use master key providers,
need help migrating from master key providers to keyrings,
or simply want to see the difference between these configuration experiences,
you can find these examples in [`examples/masterkeyprovider`](./java/com/amazonaws/crypto/examples/masterkeyprovider).

## Legacy

This section includes older examples,
including examples of using master keys and master key providers.
You can use them as a reference,
but we recommend looking at the newer examples, which explain the preferred ways of using this library.
You can find these examples in [`examples/legacy`](./java/com/amazonaws/crypto/examples/legacy).

# Writing Examples

If you want to contribute a new example, that's awesome!
To make sure that your example is tested in our CI,
please make sure that it meets the following requirements:

1. The example MUST be a distinct class in the [`examples`](./java/com/amazonaws/crypto/examples) directory.
1. Each example file MUST contain exactly one example.
1. Each example file MUST contain a static method called `run` that runs the example.
1. If your `run` method needs any of the following inputs,
    the parameters MUST have the following types:
    * `com.amazonaws.encryptionsdk.kms.AwsKmsCmkId` : A single AWS KMS CMK ARN.
        * NOTE: You can assume that automatically discovered credentials have
            `kms:GenerateDataKey`, `kms:Encrypt`, and `kms:Decrypt` permissions on this CMK.
    * `List<com.amazonaws.encryptionsdk.kms.AwsKmsCmkId>` :
        A list of AWS KMS CMK ARNs to use for encrypting and decrypting data keys.
        * NOTE: You can assume that automatically discovered credentials have
            `kms:Encrypt` and `kms:Decrypt` permissions on these CMKs.
    * `byte[]` : Plaintext data to encrypt.
    * `java.io.File` : A path to a file containing plaintext to encrypt.
        * NOTE: You can assume that you have write access to the parent directory
            and that anything you do in that directory will be cleaned up
            by our test runners.
1. Any additional parameters MUST be optional and nullable and not of the same type as the above parameters.
