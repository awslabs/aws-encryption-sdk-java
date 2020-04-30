# AWS Encryption SDK for Java

The AWS Encryption SDK is a client-side encryption library designed to make it easy for everyone to encrypt and decrypt data using industry standards and best practices. It enables you to focus on the core functionality of your application, rather than on how to best encrypt and decrypt your data.

For details about the design, architecture and usage of the SDK, see the [official documentation](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/), [example code][examples] and the [Javadoc](https://aws.github.io/aws-encryption-sdk-java/javadoc/).

[Security issue notifications](./CONTRIBUTING.md#security-issue-notifications)

## Getting Started

### Required Prerequisites
To use this SDK you must have:

* **A Java 8 or newer development environment**

  If you do not have one, we recommend [Amazon Corretto](https://aws.amazon.com/corretto/).

  **Note:** If you use the Oracle JDK, you must also download and install the [Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files](http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html).

* **Bouncy Castle** or **Bouncy Castle FIPS**

  The AWS Encryption SDK for Java uses Bouncy Castle to serialize and deserialize cryptographic objects.
  It does not explicitly use Bouncy Castle (or any other [JCA Provider](https://docs.oracle.com/javase/8/docs/api/java/security/Provider.html)) for the underlying cryptography.
  Instead, it uses the platform default, which you can configure or override as documented in the
  [Java Cryptography Architecture (JCA) Reference Guide](https://docs.oracle.com/javase/9/security/java-cryptography-architecture-jca-reference-guide.htm#JSSEC-GUID-2BCFDD85-D533-4E6C-8CE9-29990DEB0190).

  If you do not have Bouncy Castle, go to https://bouncycastle.org/latest_releases.html, then download the provider file that corresponds to your JDK.
  Or, you can pick it up from Maven (groupId: `org.bouncycastle`, artifactId: `bcprov-ext-jdk15on`).

  Beginning in version 1.6.1,
  the AWS Encryption SDK also works with Bouncy Castle FIPS (groupId: `org.bouncycastle`, artifactId: `bc-fips`)
  as an alternative to non-FIPS Bouncy Castle.
  For help installing and configuring Bouncy Castle FIPS properly, see [BC FIPS documentation](https://www.bouncycastle.org/documentation.html),
  in particular, **User Guides** and **Security Policy**.

### Optional Prerequisites

#### AWS Integration
You don't need an Amazon Web Services (AWS) account to use this SDK, but some of the [example code][examples] requires an AWS account, a customer master key (CMK) in AWS KMS, and the AWS SDK for Java.

* **To create an AWS account**, go to [Sign In or Create an AWS Account](https://portal.aws.amazon.com/gp/aws/developer/registration/index.html) and then choose **I am a new user.** Follow the instructions to create an AWS account.

* **To create a CMK in AWS KMS**, go to [Creating Keys](https://docs.aws.amazon.com/kms/latest/developerguide/create-keys.html) in the KMS documentation and then follow the instructions on that page.

* **To download and install the AWS SDK for Java**, go to [Installing the AWS SDK for Java](https://docs.aws.amazon.com/AWSSdkDocsJava/latest/DeveloperGuide/java-dg-install-sdk.html) in the AWS SDK for Java documentation and then follow the instructions on that page.

#### Amazon Corretto Crypto Provider
Many users find that the Amazon Corretto Crypto Provider (ACCP) significantly improves the performance of the AWS Encryption SDK.
For help installing and using ACCP, see the [ACCP GitHub Respository](https://github.com/corretto/amazon-corretto-crypto-provider) .

### Download

You can get the latest release from Maven:

```xml
<dependency>
  <groupId>com.amazonaws</groupId>
  <artifactId>aws-encryption-sdk-java</artifactId>
  <version>1.6.1</version>
</dependency>
```

### Sample Code

You can find sample code in the [examples directory][examples].

## Public API

Our [versioning policy](./VERSIONING.rst) applies to all public and protected classes/methods/fields
in the  `com.amazonaws.encryptionsdk` package unless otherwise documented.

The `com.amazonaws.encryptionsdk.internal` package is not included in this public API.

## FAQ

See the [Frequently Asked Questions](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/faq.html) page in the official documentation.

[examples]: https://github.com/aws/aws-encryption-sdk-java/tree/master/src/examples/java/com/amazonaws/crypto/examples
