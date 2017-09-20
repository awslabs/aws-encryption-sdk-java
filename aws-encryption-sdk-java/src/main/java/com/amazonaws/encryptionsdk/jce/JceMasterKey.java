/*
 * Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package com.amazonaws.encryptionsdk.jce;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.DataKey;
import com.amazonaws.encryptionsdk.EncryptedDataKey;
import com.amazonaws.encryptionsdk.MasterKey;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.UnsupportedProviderException;
import com.amazonaws.encryptionsdk.internal.EncryptionContextSerializer;

/**
 * Represents a {@link MasterKey} backed by one (or more) JCE {@link Key}s. Instances of this should
 * only be acquired using {@link #getInstance(SecretKey, String, String, String)} or
 * {@link #getInstance(PublicKey, PrivateKey, String, String, String)}.
 */
public abstract class JceMasterKey extends MasterKey<JceMasterKey> {
    private static final byte[] EMPTY_ARRAY = new byte[0];

    private final SecureRandom rnd = new SecureRandom();
    private final Key wrappingKey_;
    private final Key unwrappingKey_;
    private final String providerName_;
    private final String keyId_;
    private final byte[] keyIdBytes_;

    /**
     * Returns a {@code JceMasterKey} backed by {@code key} using {@code wrappingAlgorithm}.
     * Currently "{@code AES/GCM/NoPadding}" is the only supported value for
     * {@code wrappingAlgorithm}.
     * 
     * @param key
     *            key used to wrap/unwrap (encrypt/decrypt) {@link DataKey}s
     * @param provider
     * @param keyId
     * @param wrappingAlgorithm
     * @return
     */
    public static JceMasterKey getInstance(final SecretKey key, final String provider, final String keyId,
            final String wrappingAlgorithm) {
        switch (wrappingAlgorithm) {
            case "AES/GCM/NoPadding":
                return new AesGcm(key, provider, keyId);
            default:
                throw new IllegalArgumentException("Right now only AES/GCM/NoPadding is supported");

        }
    }

    /**
     * Returns a {@code JceMasterKey} backed by {@code unwrappingKey} and {@code wrappingKey} using
     * {@code wrappingAlgorithm}. Currently only RSA algorithms are supported for
     * {@code wrappingAlgorithm}. {@code wrappingAlgorithm}. If {@code unwrappingKey} is
     * {@code null} then the returned {@link JceMasterKey} can only be used for encryption.
     *
     * @param wrappingKey
     *            key used to wrap (encrypt) {@link DataKey}s
     * @param unwrappingKey
     *            (Optional) key used to unwrap (decrypt) {@link DataKey}s.
     */
    public static JceMasterKey getInstance(final PublicKey wrappingKey, final PrivateKey unwrappingKey,
            final String provider, final String keyId,
            final String wrappingAlgorithm) {
        if (wrappingAlgorithm.toUpperCase().startsWith("RSA/ECB/")) {
            return new Rsa(wrappingKey, unwrappingKey, provider, keyId, wrappingAlgorithm);
        }
        throw new UnsupportedOperationException("Currently only RSA asymmetric algorithms are supported");
    }

    protected JceMasterKey(final Key wrappingKey, final Key unwrappingKey, final String providerName,
            final String keyId) {
        wrappingKey_ = wrappingKey;
        unwrappingKey_ = unwrappingKey;
        providerName_ = providerName;
        keyId_ = keyId;
        keyIdBytes_ = keyId_.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public String getProviderId() {
        return providerName_;
    }

    @Override
    public String getKeyId() {
        return keyId_;
    }

    @Override
    public DataKey<JceMasterKey> generateDataKey(final CryptoAlgorithm algorithm,
            final Map<String, String> encryptionContext) {
        final byte[] rawKey = new byte[algorithm.getDataKeyLength()];
        rnd.nextBytes(rawKey);
        final SecretKeySpec key = new SecretKeySpec(rawKey, algorithm.getDataKeyAlgo());
        return encryptRawKey(key, rawKey, encryptionContext);
    }

    @Override
    public DataKey<JceMasterKey> encryptDataKey(final CryptoAlgorithm algorithm,
            final Map<String, String> encryptionContext,
            final DataKey<?> dataKey) {
        final SecretKey key = dataKey.getKey();
        if (!key.getFormat().equals("RAW")) {
            throw new IllegalArgumentException("Can only re-encrypt data keys which are in RAW format, not "
                    + dataKey.getKey().getFormat());
        }
        if (!key.getAlgorithm().equalsIgnoreCase(algorithm.getDataKeyAlgo())) {
            throw new IllegalArgumentException("Incorrect key algorithm. Expected " + key.getAlgorithm()
                    + " but got " + algorithm.getKeyAlgo());
        }
        final byte[] rawKey = key.getEncoded();
        final DataKey<JceMasterKey> result = encryptRawKey(key, rawKey, encryptionContext);
        Arrays.fill(rawKey, (byte) 0);
        return result;
    }

    protected DataKey<JceMasterKey> encryptRawKey(final SecretKey key, final byte[] rawKey,
            final Map<String, String> encryptionContext) {
        try {
            final WrappingData wData = buildWrappingCipher(wrappingKey_, encryptionContext);
            final Cipher cipher = wData.cipher;
            final byte[] encryptedKey = cipher.doFinal(rawKey);

            final byte[] provInfo = new byte[keyIdBytes_.length + wData.extraInfo.length];
            System.arraycopy(keyIdBytes_, 0, provInfo, 0, keyIdBytes_.length);
            System.arraycopy(wData.extraInfo, 0, provInfo, keyIdBytes_.length, wData.extraInfo.length);
            return new DataKey<>(key, encryptedKey, provInfo, this);
        } catch (final GeneralSecurityException gsex) {
            throw new AwsCryptoException(gsex);
        }
    }

    @Override
    public DataKey<JceMasterKey> decryptDataKey(final CryptoAlgorithm algorithm,
            final Collection<? extends EncryptedDataKey> encryptedDataKeys,
            final Map<String, String> encryptionContext)
            throws UnsupportedProviderException, AwsCryptoException {
        final List<Exception> exceptions = new ArrayList<>();
        // Find an encrypted key who's provider and info match us
        for (final EncryptedDataKey edk : encryptedDataKeys) {
            try {
                if (edk.getProviderId().equals(getProviderId())
                        && arrayPrefixEquals(edk.getProviderInformation(), keyIdBytes_, keyIdBytes_.length)) {
                    final DataKey<JceMasterKey> result = actualDecrypt(algorithm, edk, encryptionContext);
                    if (result != null) {
                        return result;
                    }
                }
            } catch (final Exception ex) {
                exceptions.add(ex);
            }
        }
        throw buildCannotDecryptDksException(exceptions);
    }

    protected DataKey<JceMasterKey> actualDecrypt(final CryptoAlgorithm algorithm, final EncryptedDataKey edk,
            final Map<String, String> encryptionContext) throws GeneralSecurityException {
        final Cipher cipher = buildUnwrappingCipher(unwrappingKey_, edk.getProviderInformation(),
                keyIdBytes_.length,
                encryptionContext);
        final byte[] rawKey = cipher.doFinal(edk.getEncryptedDataKey());
        if (rawKey.length != algorithm.getDataKeyLength()) {
            // Something's wrong here. Assume that the decryption is invalid.
            return null;
        }
        return new DataKey<>(
                new SecretKeySpec(rawKey, algorithm.getDataKeyAlgo()),
                edk.getEncryptedDataKey(),
                edk.getProviderInformation(), this);

    }

    protected static boolean arrayPrefixEquals(final byte[] a, final byte[] b, final int len) {
        if (a == null || b == null || a.length < len || b.length < len) {
            return false;
        }
        for (int x = 0; x < len; x++) {
            if (a[x] != b[x]) {
                return false;
            }
        }
        return true;
    }

    protected abstract WrappingData buildWrappingCipher(Key key, Map<String, String> encryptionContext)
            throws GeneralSecurityException;

    protected abstract Cipher buildUnwrappingCipher(Key key, byte[] extraInfo, int offset,
            Map<String, String> encryptionContext) throws GeneralSecurityException;

    private static class WrappingData {
        public final Cipher cipher;
        public final byte[] extraInfo;

        public WrappingData(final Cipher cipher, final byte[] extraInfo) {
            super();
            this.cipher = cipher;
            this.extraInfo = extraInfo != null ? extraInfo : EMPTY_ARRAY;
        }
    }

    private static class Rsa extends JceMasterKey {
        private final String transformation_;

        private Rsa(PublicKey wrappingKey, PrivateKey unwrappingKey, String providerName, String keyId,
                String transformation) {
            super(wrappingKey, unwrappingKey, providerName, keyId);
            transformation_ = transformation;
        }

        @Override
        protected WrappingData buildWrappingCipher(Key key, Map<String, String> encryptionContext)
                throws GeneralSecurityException {
            // We require BouncyCastle to avoid some bugs in the default Java implementation
            // of OAEP.
            final Cipher cipher = Cipher.getInstance(transformation_, "BC");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return new WrappingData(cipher, EMPTY_ARRAY);
        }

        @Override
        protected Cipher buildUnwrappingCipher(Key key, byte[] extraInfo, int offset,
                Map<String, String> encryptionContext) throws GeneralSecurityException {
            if (extraInfo.length != offset) {
                throw new IllegalArgumentException("Extra info must be empty for RSA keys");
            }
            // We require BouncyCastle to avoid some bugs in the default Java implementation
            // of OAEP.
            final Cipher cipher = Cipher.getInstance(transformation_, "BC");
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher;
        }
    }

    private static class AesGcm extends JceMasterKey {
        private static final int NONCE_LENGTH = 12;
        private static final int TAG_LENGTH = 128;
        private static final String TRANSFORMATION = "AES/GCM/NoPadding";

        private final SecureRandom rnd = new SecureRandom();

        public AesGcm(final SecretKey key, final String providerName, final String keyId) {
            super(key, key, providerName, keyId);
        }

        private static byte[] specToBytes(final GCMParameterSpec spec) {
            final byte[] nonce = spec.getIV();
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try (final DataOutputStream dos = new DataOutputStream(baos)) {
                dos.writeInt(spec.getTLen());
                dos.writeInt(nonce.length);
                dos.write(nonce);
                dos.close();
                baos.close();
            } catch (final IOException ex) {
                throw new AssertionError("Impossible exception", ex);
            }
            return baos.toByteArray();
        }

        private static GCMParameterSpec bytesToSpec(final byte[] data, final int offset) {
            final ByteArrayInputStream bais = new ByteArrayInputStream(data, offset, data.length - offset);
            try (final DataInputStream dis = new DataInputStream(bais)) {
                final int tagLen = dis.readInt();
                final int nonceLen = dis.readInt();
                final byte[] nonce = new byte[nonceLen];
                dis.readFully(nonce);
                return new GCMParameterSpec(tagLen, nonce);
            } catch (final IOException ex) {
                throw new AssertionError("Impossible exception", ex);
            }
        }

        @Override
        protected WrappingData buildWrappingCipher(final Key key, final Map<String, String> encryptionContext)
                throws GeneralSecurityException {
            final byte[] nonce = new byte[NONCE_LENGTH];
            rnd.nextBytes(nonce);
            final GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH, nonce);
            final Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, spec);
            final byte[] aad = EncryptionContextSerializer.serialize(encryptionContext);
            cipher.updateAAD(aad);
            return new WrappingData(cipher, specToBytes(spec));
        }

        @Override
        protected Cipher buildUnwrappingCipher(final Key key, final byte[] extraInfo, final int offset,
                final Map<String, String> encryptionContext) throws GeneralSecurityException {
            final GCMParameterSpec spec = bytesToSpec(extraInfo, offset);
            final Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, spec);
            final byte[] aad = EncryptionContextSerializer.serialize(encryptionContext);
            cipher.updateAAD(aad);
            return cipher;
        }
    }
}
