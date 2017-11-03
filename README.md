# AWS Encryption SDK for Java

The AWS Encryption SDK is a client-side encryption library. It helps you to implement cryptography
best practices to protect your data. By default, each encryption operation uses a unique data key
that is encrypted under a *master key*. The encrypted data is combined with the encrypted data into
a single [encrypted
message](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html), so
you don't need to keep track of the data keys that you need to decrypt your data. The SDK supports
[AWS Key Management Service](https://aws.amazon.com/kms/) (KMS) customer master keys (CMKs), and provides APIs to define and use other master key providers. The SDK provides methods for encrypting and decrypting strings, byte arrays, and byte streams. For details, see the [example code][examples] and the [Javadoc](https://awslabs.github.io/aws-encryption-sdk-java/javadoc/).

For more details about the design and architecture of the SDK, see the [official documentation](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/).

## Getting Started

### Required Prerequisites
To use this SDK you must have:

* **A Java development environment**

You will need Java 8 or later. On the Oracle website, go to [Java SE
Downloads](https://www.oracle.com/technetwork/java/javase/downloads/index.html), and then download and install the Java SE Development Kit (JDK).

If you use the Oracle JDK, you must also download and install the [Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files](http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html).

* **Bouncy Castle**

Bouncy Castle provides a cryptography API for Java. If you do not have Bouncy Castle, go to [Bouncy
Castle Latest Java Releases](https://bouncycastle.org/latest_releases.html) to download the provider
file that corresponds to your JDK. If you use [Apache Maven](https://maven.apache.org), Bouncy
Castle is available with the following dependency definition.

  ```xml
  <dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bcprov-ext-jdk15on</artifactId>
    <version>1.58</version>
  </dependency>
  ```

### Optional Elements

You do not need an Amazon Web Services (AWS) account to use this SDK. However, some of the [example
code][examples] requires an AWS account, an AWS KMS customer master key, and the AWS SDK for Java.

* **To create an AWS account**, see [Create an AWS
Account](https://portal.aws.amazon.com/gp/aws/developer/registration/index.html).

* **To create a CMK in AWS KMS**, see [Creating Keys](https://docs.aws.amazon.com/kms/latest/developerguide/create-keys.html).

* **For help with downloading and install the AWS SDK for Java**, see [Installing the AWS SDK for Java](https://docs.aws.amazon.com/AWSSdkDocsJava/latest/DeveloperGuide/java-dg-install-sdk.html).

### Download

You can get the latest release of the AWS SDK for Java from Apache Maven:

```xml
<dependency>
  <groupId>com.amazonaws</groupId>
  <artifactId>aws-encryption-sdk-java</artifactId>
  <version>1.3.1</version>
</dependency>
```

Don't forget to enable the download of snapshot jars from Maven:

```xml
<profiles>
  <profile>
    <id>allow-snapshots</id>
    <activation><activeByDefault>true</activeByDefault></activation>
    <repositories>
      <repository>
        <id>snapshots-repo</id>
        <url>https://oss.sonatype.org/content/repositories/snapshots</url>
        <releases><enabled>false</enabled></releases>
        <snapshots><enabled>true</enabled></snapshots>
      </repository>
    </repositories>
  </profile>
</profiles>
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

For more examples, see the [examples directory][examples].

## FAQ

If you have questions, see the [Frequently Asked
Questions](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/faq.html), create an
[issue][issues], or read and post on the [AWS Key Management Service (KMS) Discussion
Forum](https://forums.aws.amazon.com/forum.jspa?forumID=182) that the Encryption SDK shares with KMS. 

[examples]: https://github.com/awslabs/aws-encryption-sdk-java/tree/master/src/examples/java/com/amazonaws/crypto/examples
[issues]: https://github.com/awslabs/aws-encryption-sdk-java/issues
