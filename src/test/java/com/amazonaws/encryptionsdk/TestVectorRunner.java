/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except
 * in compliance with the License. A copy of the License is located at
 *
 * http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.amazonaws.encryptionsdk;

import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.encryptionsdk.jce.JceMasterKey;
import com.amazonaws.encryptionsdk.keyrings.Keyring;
import com.amazonaws.encryptionsdk.keyrings.RawRsaKeyringBuilder.RsaPaddingScheme;
import com.amazonaws.encryptionsdk.keyrings.StandardKeyrings;
import com.amazonaws.encryptionsdk.kms.AwsKmsClientSupplier;
import com.amazonaws.encryptionsdk.kms.AwsKmsCmkId;
import com.amazonaws.encryptionsdk.kms.KmsMasterKeyProvider;
import com.amazonaws.encryptionsdk.kms.StandardAwsKmsClientSuppliers;
import com.amazonaws.encryptionsdk.multi.MultipleProviderFactory;
import com.amazonaws.util.IOUtils;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.JarURLConnection;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.jar.JarFile;
import java.util.zip.ZipEntry;

import static java.lang.String.format;
import static java.util.Collections.emptyList;
import static org.apache.commons.lang3.Validate.isTrue;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

@Tag(TestUtils.TAG_INTEGRATION)
class TestVectorRunner {
    // We save the files in memory to avoid repeatedly retrieving them.
    // This won't work if the plaintexts are too large or numerous
    private static final Map<String, byte[]> cachedData = new HashMap<>();
    private static final AwsKmsClientSupplier awsKmsClientSupplier = StandardAwsKmsClientSuppliers.defaultBuilder()
            .credentialsProvider(new DefaultAWSCredentialsProviderChain())
            .build();
    private static final KmsMasterKeyProvider kmsProv = KmsMasterKeyProvider
            .builder()
            .withCustomClientFactory(awsKmsClientSupplier::getClient)
            .build();

    @ParameterizedTest(name = "Compatibility Test: {0}")
    @MethodSource("data")
    void decrypt(TestCase testCase) {
        AwsCrypto crypto = new AwsCrypto();
        byte[] keyringPlaintext = crypto.decrypt(DecryptRequest.builder()
                .ciphertext(cachedData.get(testCase.ciphertextPath))
                .keyring(testCase.keyring).build()).getResult();
        byte[] mkpPlaintext = crypto.decryptData(testCase.mkp, cachedData.get(testCase.ciphertextPath)).getResult();
        final byte[] expectedPlaintext = cachedData.get(testCase.plaintextPath);

        assertArrayEquals(expectedPlaintext, keyringPlaintext);
        assertArrayEquals(expectedPlaintext, mkpPlaintext);
    }

    @SuppressWarnings("unchecked")
    static Collection<TestCase> data() throws Exception {
        final String zipPath = System.getProperty("testVectorZip");
        if (zipPath == null) {
            return Collections.emptyList();
        }

        final JarURLConnection jarConnection = (JarURLConnection) new URL("jar:" + zipPath + "!/").openConnection();

        try (JarFile jar = jarConnection.getJarFile()) {
            final Map<String, Object> manifest = readJsonMapFromJar(jar, "manifest.json");
            final Map<String, Object> metaData = (Map<String, Object>) manifest.get("manifest");

            // We only support "awses-decrypt" type manifests right now
            isTrue("awses-decrypt".equals(metaData.get("type")), "Unsupported manifest type: %s", metaData.get("type"));
            isTrue(Integer.valueOf(1).equals(metaData.get("version")), "Unsupported manifest version: %s", metaData.get("version"));

            final Map<String, KeyEntry> keys = parseKeyManifest(readJsonMapFromJar(jar, (String) manifest.get("keys")));

            final List<TestCase> testCases = new ArrayList<>();

            ((Map<String, Map<String, Object>>) manifest.get("tests")).forEach(
                    (testName, data) -> testCases.add(parseTest(testName, data, keys, jar)));

            return testCases;
        }
    }

    @AfterAll
    static void teardown() {
        cachedData.clear();
    }

    private static byte[] readBytesFromJar(JarFile jar, String fileName) {
        try (InputStream is = readFromJar(jar, fileName)) {
            return IOUtils.toByteArray(is);
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }

    private static Map<String, Object> readJsonMapFromJar(JarFile jar, String fileName) throws IOException {
        try (InputStream is = readFromJar(jar, fileName)) {
            final ObjectMapper mapper = new ObjectMapper();
            return mapper.readValue(is, new TypeReference<Map<String, Object>>() {});
        }
    }

    private static InputStream readFromJar(JarFile jar, String name) throws IOException {
        // Our manifest URIs incorrectly start with file:// rather than just file: so we need to strip this
        ZipEntry entry = jar.getEntry(name.replaceFirst("^file://(?!/)", ""));
        return jar.getInputStream(entry);
    }

    @SuppressWarnings("unchecked")
    private static TestCase parseTest(String testName, Map<String, Object> data, Map<String, KeyEntry> keys,
                                      JarFile jar) {
        final String plaintextUrl = (String) data.get("plaintext");
        final String ciphertextURL = (String) data.get("ciphertext");
        cachedData.computeIfAbsent(plaintextUrl, k -> readBytesFromJar(jar, k));
        cachedData.computeIfAbsent(ciphertextURL, k -> readBytesFromJar(jar, k));

        final List<Keyring> keyrings = new ArrayList<>();
        final List<MasterKey<?>> mks = new ArrayList<>();

        for (Map<String, String> mkEntry : (List<Map<String, String>>) data.get("master-keys")) {
            final String type = mkEntry.get("type");
            final String keyName = mkEntry.get("key");
            final KeyEntry key = keys.get(keyName);

            if ("aws-kms".equals(type)) {
                keyrings.add(StandardKeyrings.awsKmsBuilder()
                        .awsKmsClientSupplier(awsKmsClientSupplier)
                        .generatorKeyId(AwsKmsCmkId.fromString(key.keyId))
                        .build());
                mks.add(kmsProv.getMasterKey(key.keyId));
            } else if ("raw".equals(type)) {
                final String provId = mkEntry.get("provider-id");
                final String algorithm = mkEntry.get("encryption-algorithm");
                if ("aes".equals(algorithm)) {
                    keyrings.add(StandardKeyrings.rawAesBuilder()
                            .keyName(key.keyId)
                            .keyNamespace(provId)
                            .wrappingKey((SecretKey) key.key).build());
                    mks.add(JceMasterKey.getInstance((SecretKey) key.key, provId, key.keyId, "AES/GCM/NoPadding"));
                } else if ("rsa".equals(algorithm)) {
                    final RsaPaddingScheme paddingScheme;
                    final String padding = mkEntry.get("padding-algorithm");
                    if ("pkcs1".equals(padding)) {
                        paddingScheme = RsaPaddingScheme.PKCS1;
                    } else if ("oaep-mgf1".equals(padding)) {
                        switch(mkEntry.get("padding-hash")) {
                            case "sha1":
                                paddingScheme = RsaPaddingScheme.OAEP_SHA1_MGF1;
                                break;
                            case "sha256":
                                paddingScheme = RsaPaddingScheme.OAEP_SHA256_MGF1;
                                break;
                            case "sha384":
                                paddingScheme = RsaPaddingScheme.OAEP_SHA384_MGF1;
                                break;
                            case "sha512":
                                paddingScheme = RsaPaddingScheme.OAEP_SHA512_MGF1;
                                break;
                            default:
                                throw new IllegalArgumentException("Unsupported padding hash:" + mkEntry.get("padding-hash"));
                        }
                    } else {
                        throw new IllegalArgumentException("Unsupported padding:" + padding);
                    }
                    final PublicKey wrappingKey;
                    final PrivateKey unwrappingKey;
                    if (key.key instanceof PublicKey) {
                        wrappingKey = (PublicKey) key.key;
                        unwrappingKey = null;
                    } else {
                        wrappingKey = null;
                        unwrappingKey = (PrivateKey) key.key;
                    }
                    keyrings.add(StandardKeyrings.rawRsaBuilder()
                            .publicKey(wrappingKey)
                            .privateKey(unwrappingKey)
                            .keyNamespace(provId)
                            .keyName(key.keyId)
                            .paddingScheme(paddingScheme).build());
                    mks.add(JceMasterKey.getInstance(wrappingKey, unwrappingKey, provId, key.keyId, paddingScheme.getTransformation()));
                } else {
                    throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
                }
            } else {
                throw new IllegalArgumentException("Unsupported Key Type: " + type);
            }
        }

        return new TestCase(testName, ciphertextURL, plaintextUrl, keyrings, mks);
    }

    @SuppressWarnings("unchecked")
    static Map<String, KeyEntry> parseKeyManifest(final Map<String, Object> keysManifest) throws GeneralSecurityException {
        // check our type
        final Map<String, Object> metaData = (Map<String, Object>) keysManifest.get("manifest");
        if (!"keys".equals(metaData.get("type"))) {
            throw new IllegalArgumentException("Invalid manifest type: " + metaData.get("type"));
        }
        if (!Integer.valueOf(3).equals(metaData.get("version"))) {
            throw new IllegalArgumentException("Invalid manifest version: " + metaData.get("version"));
        }

        final Map<String, KeyEntry> result = new HashMap<>();

        Map<String, Object> keys = (Map<String, Object>) keysManifest.get("keys");
        for (Map.Entry<String, Object> entry : keys.entrySet()) {
            final String name = entry.getKey();
            final Map<String, Object> data = (Map<String, Object>) entry.getValue();

            final String keyType = (String) data.get("type");
            final String encoding = (String) data.get("encoding");
            final String keyId = (String) data.get("key-id");
            final String material = (String) data.get("material"); // May be null
            final String algorithm = (String) data.get("algorithm"); // May be null

            final KeyEntry keyEntry;

            final KeyFactory kf;
            switch (keyType) {
                case "symmetric":
                    if (!"base64".equals(encoding)) {
                        throw new IllegalArgumentException(format("Key %s is symmetric but has encoding %s", keyId, encoding));
                    }
                    keyEntry = new KeyEntry(keyId, new SecretKeySpec(Base64.decode(material), algorithm.toUpperCase()));
                    break;
                case "private":
                    kf = KeyFactory.getInstance(algorithm);
                    if (!"pem".equals(encoding)) {
                        throw new IllegalArgumentException(format("Key %s is private but has encoding %s", keyId, encoding));
                    }
                    byte[] pkcs8Key = parsePem(material);
                    keyEntry = new KeyEntry(keyId, kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8Key)));
                    break;
                case "public":
                    kf = KeyFactory.getInstance(algorithm);
                    if (!"pem".equals(encoding)) {
                        throw new IllegalArgumentException(format("Key %s is private but has encoding %s", keyId, encoding));
                    }
                    byte[] x509Key = parsePem(material);
                    keyEntry = new KeyEntry(keyId, kf.generatePublic(new X509EncodedKeySpec(x509Key)));
                    break;
                case "aws-kms":
                    keyEntry = new KeyEntry(keyId, null);
                    break;
                default:
                    throw new IllegalArgumentException("Unsupported key type: " + keyType);
            }

            result.put(name, keyEntry);
        }

        return result;
    }

    private static byte[] parsePem(String pem) {
        final String stripped = pem.replaceAll("-+[A-Z ]+-+", "");
        return Base64.decode(stripped);
    }

    private static class KeyEntry {
        final String keyId;
        final Key key;

        private KeyEntry(String keyId, Key key) {
            this.keyId = keyId;
            this.key = key;
        }
    }

    private static class TestCase {
        private final String name;
        private final String ciphertextPath;
        private final String plaintextPath;
        private final Keyring keyring;
        private final MasterKeyProvider<?> mkp;

        private TestCase(String name, String ciphertextPath, String plaintextPath, List<Keyring> keyrings, List<MasterKey<?>> mks) {
            this.name = name;
            this.ciphertextPath = ciphertextPath;
            this.plaintextPath = plaintextPath;
            this.keyring = StandardKeyrings.multi(keyrings.get(0), keyrings.size() > 1 ? keyrings.subList(1, keyrings.size()) : emptyList());
            this.mkp = MultipleProviderFactory.buildMultiProvider(mks);
        }

        @Override
        public String toString() {
            return name;
        }
    }
}
