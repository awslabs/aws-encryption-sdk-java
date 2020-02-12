# AWS Encryption SDK for Java

The AWS Encryption SDK is a client-side encryption library designed to make it easy for everyone to encrypt and decrypt data using industry standards and best practices. It enables you to focus on the core functionality of your application, rather than on how to best encrypt and decrypt your data.

For details about the design, architecture and usage of the SDK, see the [official documentation](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/), [example code][examples] and the [Javadoc](https://aws.github.io/aws-encryption-sdk-java/javadoc/).

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
  <version>1.7.0</version>
</dependency>
```

### Get Started

The following code sample demonstrates how to get started:

1. Instantiate the SDK.
2. Setup a KMS keyring.
3. Encrypt and decrypt data.

```java
// This sample code encrypts and then decrypts data using an AWS Key Management Service (AWS KMS) customer master key (CMK).
package com.amazonaws.crypto.examples;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.AwsCryptoResult;
import com.amazonaws.encryptionsdk.DecryptRequest;
import com.amazonaws.encryptionsdk.EncryptRequest;
import com.amazonaws.encryptionsdk.keyrings.Keyring;
import com.amazonaws.encryptionsdk.keyrings.StandardKeyrings;
import com.amazonaws.encryptionsdk.kms.AwsKmsCmkId;

public class BasicEncryptionExample {

    private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

    public static void main(final String[] args) {
        encryptAndDecrypt(AwsKmsCmkId.fromString(args[0]));
    }

    static void encryptAndDecrypt(final AwsKmsCmkId keyArn) {
        // 1. Instantiate the SDK
        final AwsCrypto crypto = new AwsCrypto();

        // 2. Instantiate a KMS keyring. Supply the key ARN for the generator key that generates a
        //    data key. While using a key ARN is a best practice, for encryption operations you can also
        //    use an alias name or alias ARN.
        final Keyring keyring = StandardKeyrings.awsKms(keyArn);

        // 3. Create an encryption context
        //
        //    Most encrypted data should have an associated encryption context
        //    to protect integrity. This sample uses placeholder values.
        //
        //    For more information see: https://amzn.to/1nSbe9X (blogs.aws.amazon.com)
        final Map<String, String> encryptionContext = Collections.singletonMap("Example", "String");

        // 4. Encrypt the data with the keyring and encryption context
        final AwsCryptoResult<byte[]> encryptResult = crypto.encrypt(
                EncryptRequest.builder()
                    .keyring(keyring)
                    .encryptionContext(encryptionContext)
                    .plaintext(EXAMPLE_DATA).build());
        final byte[] ciphertext = encryptResult.getResult();

        // 5. Decrypt the data. You can use the same keyring to encrypt and decrypt, but for decryption
        //    the key IDs must be in the key ARN format.
        final AwsCryptoResult<byte[]> decryptResult = crypto.decrypt(
                DecryptRequest.builder()
                        .keyring(keyring)
                        .ciphertext(ciphertext).build());

        // 6. To verify the CMK that was actually used in the decrypt operation, inspect the keyring trace.
        if(!decryptResult.getKeyringTrace().getEntries().get(0).getKeyName().equals(keyArn.toString())) {
            throw new IllegalStateException("Wrong key ID!");
        }

        // 7.  To verify that the encryption context used to decrypt the data was the encryption context you expected,
        //     examine the encryption context in the result. This helps to ensure that you decrypted the ciphertext that
        //     you intended.
        //
        //     When verifying, test that your expected encryption context is a subset of the actual encryption context,
        //     not an exact match. The Encryption SDK adds the signing key to the encryption context when appropriate.
        assert decryptResult.getEncryptionContext().get("Example").equals("String");

        // 8. Verify that the decrypted plaintext matches the original plaintext
        assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);
    }
}
```

You can find more examples in the [examples directory][examples].

## Public API

Our [versioning policy](./VERSIONING.rst) applies to all public and protected classes/methods/fields
in the  `com.amazonaws.encryptionsdk` package unless otherwise documented.

The `com.amazonaws.encryptionsdk.internal` package is not included in this public API.

## FAQ

See the [Frequently Asked Questions](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/faq.html) page in the official documentation.

[examples]: https://github.com/aws/aws-encryption-sdk-java/tree/master/src/examples/java/com/amazonaws/crypto/examples
