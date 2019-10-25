# AWS Encryption SDK for Java

The AWS Encryption SDK enables secure client-side encryption. It uses cryptography best practices to protect your data and the encryption keys used to protect that data. Each data object is protected with a unique data encryption key (DEK), and the DEK is protected with a key encryption key (KEK) called a *master key*. The encrypted DEK is combined with the encrypted data into a single [encrypted message](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html), so you don't need to keep track of the DEKs for your data. The SDK supports master keys in [AWS Key Management Service](https://aws.amazon.com/kms/) (KMS), and it also provides APIs to define and use other master key providers. The SDK provides methods for encrypting and decrypting strings, byte arrays, and byte streams. For details, see the [example code][examples] and the [Javadoc](https://aws.github.io/aws-encryption-sdk-java/javadoc/).

For more details about the design and architecture of the SDK, see the [official documentation](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/).

## Getting Started

### Required Prerequisites
To use this SDK you must have:

* **A Java 8 or newer development environment**

  If you do not have one, we recommend [Amazon Corretto](https://aws.amazon.com/corretto/).

  **Note:** If you use the Oracle JDK, you must also download and install the [Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files](http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html).

* **Bouncy Castle** or **Bouncy Castle FIPS**

Although the AWS Encryption SDK for Java no longer depends on Bouncy Castle for cryptography, it requires Bouncy Castle for other tasks, such as handling cryptographic objects.```
  If you do not have Bouncy Castle, go to https://bouncycastle.org/latest_releases.html, then download the provider file that corresponds to your JDK.
  Or, you can pick it up from Maven (groupId: `org.bouncycastle`, artifactId: `bcprov-ext-jdk15on`).

  Beginning in version 1.6.1,
  the AWS Encryption SDK also works with Bouncy Castle FIPS (groupId: `org.bouncycastle`, artifactId: `bc-fips`).
  Please follow Bouncy Castle's FIPS [documentation](https://www.bouncycastle.org/documentation.html),
  including User Guides and Security Policy for proper installation and configuration.

### Optional Prerequisites

#### AWS Integration
You don't need an Amazon Web Services (AWS) account to use this SDK, but some of the [example code][examples] requires an AWS account, a customer master key (CMK) in AWS KMS, and the AWS SDK for Java.

* **To create an AWS account**, go to [Sign In or Create an AWS Account](https://portal.aws.amazon.com/gp/aws/developer/registration/index.html) and then choose **I am a new user.** Follow the instructions to create an AWS account.

* **To create a CMK in AWS KMS**, go to [Creating Keys](https://docs.aws.amazon.com/kms/latest/developerguide/create-keys.html) in the KMS documentation and then follow the instructions on that page.

* **To download and install the AWS SDK for Java**, go to [Installing the AWS SDK for Java](https://docs.aws.amazon.com/AWSSdkDocsJava/latest/DeveloperGuide/java-dg-install-sdk.html) in the AWS SDK for Java documentation and then follow the instructions on that page.

#### Amazon Corretto Crypto Provider
Many users find that the Amazon Corretto Crypto Provider (ACCP) significantly improves the performance of the AWS Encryption SDK.
For help with installation and using ACCP, see the [ACCP GitHub Respository](https://github.com/corretto/amazon-corretto-crypto-provider) .

### Download

You can get the latest release from Maven:

```xml
<dependency>
  <groupId>com.amazonaws</groupId>
  <artifactId>aws-encryption-sdk-java</artifactId>
  <version>1.6.0</version>
</dependency>
```

### Get Started

The following code sample demonstrates how to get started:

1. Instantiate the SDK.
2. Define the master key provider.
3. Encrypt and decrypt data.

```java
// This sample code encrypts and then decrypts a string using a KMS CMK.
// You provide the KMS key ARN and plaintext string as arguments.
package com.amazonaws.crypto.examples;

import java.util.Collections;
import java.util.Map;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoResult;
import com.amazonaws.encryptionsdk.kms.KmsMasterKey;
import com.amazonaws.encryptionsdk.kms.KmsMasterKeyProvider;

public class StringExample {
    private static String keyArn;
    private static String data;

    public static void main(final String[] args) {
        keyArn = args[0];
        data = args[1];

        // Instantiate the SDK
        final AwsCrypto crypto = new AwsCrypto();

        // Set up the master key provider
        final KmsMasterKeyProvider prov = new KmsMasterKeyProvider(keyArn);

        // Encrypt the data
        //
        // NOTE: Encrypted data should have associated encryption context
        // to protect integrity. For this example, just use a placeholder
        // value. For more information about encryption context, see
        // https://amzn.to/1nSbe9X (blogs.aws.amazon.com)
        final Map<String, String> context = Collections.singletonMap("Example", "String");

        final String ciphertext = crypto.encryptString(prov, data, context).getResult();
        System.out.println("Ciphertext: " + ciphertext);

        // Decrypt the data
        final CryptoResult<String, KmsMasterKey> decryptResult = crypto.decryptString(prov, ciphertext);
        // Check the encryption context (and ideally the master key) to
        // ensure this is the expected ciphertext
        if (!decryptResult.getMasterKeyIds().get(0).equals(keyArn)) {
            throw new IllegalStateException("Wrong key id!");
        }

        // The SDK may add information to the encryption context, so check to
        // ensure all of the values are present
        for (final Map.Entry<String, String> e : context.entrySet()) {
            if (!e.getValue().equals(decryptResult.getEncryptionContext().get(e.getKey()))) {
                throw new IllegalStateException("Wrong Encryption Context!");
            }
        }

        // The data is correct, so output it.
        System.out.println("Decrypted: " + decryptResult.getResult());
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
