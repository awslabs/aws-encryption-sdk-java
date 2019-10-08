package com.amazonaws.encryptionsdk;

import static java.lang.String.format;

import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.encryptionsdk.jce.JceMasterKey;
import com.amazonaws.encryptionsdk.kms.KmsMasterKeyProvider;
import com.amazonaws.encryptionsdk.multi.MultipleProviderFactory;
import com.amazonaws.util.IOUtils;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.util.encoders.Base64;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
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

@RunWith(Parameterized.class)
public class TestVectorRunner {
    // We save the files in memory to avoid repeatedly retrieving them. This won't work if the plaintexts are too
    // large or numerous
    private static final Map<String, byte[]> cachedData = new HashMap<>();

    private final String testName;
    private final TestCase testCase;

    public TestVectorRunner(final String testName, TestCase testCase) {
        this.testName = testName;
        this.testCase = testCase;
    }

    @Test
    public void decrypt() {
        AwsCrypto crypto = new AwsCrypto();
        byte[] plaintext = crypto.decryptData(testCase.mkp, cachedData.get(testCase.ciphertextPath)).getResult();
        final byte[] expectedPlaintext = cachedData.get(testCase.plaintextPath);

        Assert.assertArrayEquals(expectedPlaintext, plaintext);
    }

    @Parameterized.Parameters(name="Compatibility Test: {0}")
    @SuppressWarnings("unchecked")
    public static Collection<Object[]> data() throws Exception {
        final String zipPath = System.getProperty("testVectorZip");
        if (zipPath == null) {
            return Collections.emptyList();
        }

        final JarURLConnection jarConnection = (JarURLConnection) new URL("jar:" + zipPath + "!/").openConnection();

        try (JarFile jar = jarConnection.getJarFile()) {
            final Map<String, Object> manifest = readJsonMapFromJar(jar, "manifest.json");

            final Map<String, Object> metaData = (Map<String, Object>) manifest.get("manifest");

            // We only support "awses-decrypt" type manifests right now
            if (!"awses-decrypt".equals(metaData.get("type"))) {
                throw new IllegalArgumentException("Unsupported manifest type: " + metaData.get("type"));
            }

            if (!Integer.valueOf(1).equals(metaData.get("version"))) {
                throw new IllegalArgumentException("Unsupported manifest version: " + metaData.get("version"));
            }

            final Map<String, KeyEntry> keys = parseKeyManifest(readJsonMapFromJar(jar, (String) manifest.get("keys")));

            final KmsMasterKeyProvider kmsProv = KmsMasterKeyProvider
                                                         .builder()
                                                         .withCredentials(new DefaultAWSCredentialsProviderChain())
                                                         .build();

            List<Object[]> testCases = new ArrayList<>();
            for (Map.Entry<String, Map<String, Object>> testEntry :
                    ((Map<String, Map<String, Object>>) manifest.get("tests")).entrySet()) {
                testCases.add(new Object[]{testEntry.getKey(),
                        parseTest(testEntry.getKey(), testEntry.getValue(), keys, jar, kmsProv)});
            }
            return testCases;
        }
    }

    @AfterClass
    public static void teardown() {
        cachedData.clear();
    }

    private static byte[] readBytesFromJar(JarFile jar, String fileName) throws IOException {
        try (InputStream is = readFromJar(jar, fileName)) {
            return IOUtils.toByteArray(is);
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

    private static void cacheData(JarFile jar, String url) throws IOException {
        if (!cachedData.containsKey(url)) {
            cachedData.put(url, readBytesFromJar(jar, url));
        }
    }

    @SuppressWarnings("unchecked")
    private static TestCase parseTest(String testName, Map<String, Object> data, Map<String, KeyEntry> keys,
                                      JarFile jar, KmsMasterKeyProvider kmsProv) throws IOException {
        final String plaintextUrl = (String) data.get("plaintext");
        cacheData(jar, plaintextUrl);
        final String ciphertextURL = (String) data.get("ciphertext");
        cacheData(jar, ciphertextURL);

        @SuppressWarnings("generic")
        final List<MasterKey<?>> mks = new ArrayList<>();

        for (Map<String, String> mkEntry : (List<Map<String, String>>) data.get("master-keys")) {
            final String type = mkEntry.get("type");
            final String keyName = mkEntry.get("key");
            final KeyEntry key = keys.get(keyName);

            if ("aws-kms".equals(type)) {
                mks.add(kmsProv.getMasterKey(key.keyId));
            } else if ("raw".equals(type)) {
                final String provId = mkEntry.get("provider-id");
                final String algorithm = mkEntry.get("encryption-algorithm");
                if ("aes".equals(algorithm)) {
                    mks.add(JceMasterKey.getInstance((SecretKey) key.key, provId, key.keyId, "AES/GCM/NoPadding"));
                } else if ("rsa".equals(algorithm)) {
                    String transformation = "RSA/ECB/";
                    final String padding = mkEntry.get("padding-algorithm");
                    if ("pkcs1".equals(padding)) {
                        transformation += "PKCS1Padding";
                    } else if ("oaep-mgf1".equals(padding)) {
                        final String hashName = mkEntry.get("padding-hash")
                                                       .replace("sha", "sha-")
                                                       .toUpperCase();
                        transformation += "OAEPWith" + hashName + "AndMGF1Padding";
                    } else {
                        throw new IllegalArgumentException("Unsupported padding:" + padding);
                    }
                    final PublicKey wrappingKey;
                    final PrivateKey unwrappingKey;
                    if (key.key instanceof  PublicKey) {
                        wrappingKey = (PublicKey) key.key;
                        unwrappingKey = null;
                    } else {
                        wrappingKey = null;
                        unwrappingKey = (PrivateKey) key.key;
                    }
                    mks.add(JceMasterKey.getInstance(wrappingKey, unwrappingKey, provId, key.keyId, transformation));
                } else {
                    throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
                }
            } else {
                throw new IllegalArgumentException("Unsupported Key Type: " + type);
            }
        }

        return new TestCase(testName, ciphertextURL, plaintextUrl, mks);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, KeyEntry> parseKeyManifest(final Map<String, Object> keysManifest) throws GeneralSecurityException {
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
                    keyEntry = new KeyEntry(name, keyId, keyType,
                                            new SecretKeySpec(Base64.decode(material), algorithm.toUpperCase()));
                    break;
                case "private":
                    kf = KeyFactory.getInstance(algorithm);
                    if (!"pem".equals(encoding)) {
                        throw new IllegalArgumentException(format("Key %s is private but has encoding %s", keyId, encoding));
                    }
                    byte[] pkcs8Key = parsePem(material);
                    keyEntry = new KeyEntry(name, keyId, keyType,
                                            kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8Key)));
                    break;
                case "public":
                    kf = KeyFactory.getInstance(algorithm);
                    if (!"pem".equals(encoding)) {
                        throw new IllegalArgumentException(format("Key %s is private but has encoding %s", keyId, encoding));
                    }
                    byte[] x509Key = parsePem(material);
                    keyEntry = new KeyEntry(name, keyId, keyType,
                                            kf.generatePublic(new X509EncodedKeySpec(x509Key)));
                    break;
                case "aws-kms":
                    keyEntry = new KeyEntry(name, keyId, keyType, null);
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
        final String name;
        final String keyId;
        final String type;
        final Key key;

        private KeyEntry(String name, String keyId, String type, Key key) {
            this.name = name;
            this.keyId = keyId;
            this.type = type;
            this.key = key;
        }
    }

    private static class TestCase {
        private final String name;
        private final String ciphertextPath;
        private final String plaintextPath;
        private final MasterKeyProvider<?> mkp;

        private TestCase(String name, String ciphertextPath, String plaintextPath, List<MasterKey<?>> mks) {
            this(name, ciphertextPath, plaintextPath, MultipleProviderFactory.buildMultiProvider(mks));
        }

        private TestCase(String name, String ciphertextPath, String plaintextPath, MasterKeyProvider<?> mkp) {
            this.name = name;
            this.ciphertextPath = ciphertextPath;
            this.plaintextPath = plaintextPath;
            this.mkp = mkp;
        }
    }
}
