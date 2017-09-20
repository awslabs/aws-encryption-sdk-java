package com.amazonaws.encryptionsdk.internal;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

import java.util.Base64;

import com.amazonaws.encryptionsdk.CryptoAlgorithm;

/**
 * Provides a consistent interface across various trailing signature algorithms.
 *
 * NOTE: This is not a stable API and may undergo breaking changes in the future.
 */
public abstract class TrailingSignatureAlgorithm {
    private TrailingSignatureAlgorithm() {
        /* Do not allow arbitrary subclasses */
    }

    public abstract String getMessageDigestAlgorithm();
    public abstract String getRawSignatureAlgorithm();
    public abstract String getHashAndSignAlgorithm();
    public abstract PublicKey deserializePublicKey(String keyString);
    public abstract String serializePublicKey(PublicKey key);
    public abstract KeyPair generateKey() throws GeneralSecurityException;

    private static final class ECDSASignatureAlgorithm extends TrailingSignatureAlgorithm {
        private final ECNamedCurveParameterSpec ecSpec;
        private final String messageDigestAlgorithm;
        private final String hashAndSignAlgorithm;

        private ECDSASignatureAlgorithm(ECNamedCurveParameterSpec ecSpec, String messageDigestAlgorithm) {
            this.ecSpec = ecSpec;
            this.messageDigestAlgorithm = messageDigestAlgorithm;
            this.hashAndSignAlgorithm = messageDigestAlgorithm + "withECDSA";
        }

        @Override
        public String toString() {
            return "ECDSASignatureAlgorithm(curve=" + ecSpec.getName() + ")";
        }

        @Override
        public String getMessageDigestAlgorithm() {
            return messageDigestAlgorithm;
        }

        @Override
        public String getRawSignatureAlgorithm() {
            return "NONEwithECDSA";
        }

        @Override public String getHashAndSignAlgorithm() {
            return hashAndSignAlgorithm;
        }

        @Override
        public PublicKey deserializePublicKey(String keyString) {
            final ECPoint q = ecSpec.getCurve().decodePoint(Base64.getDecoder().decode(keyString));

            ECPublicKeyParameters keyParams = new ECPublicKeyParameters(
                    q,
                    new ECDomainParameters(ecSpec.getCurve(), ecSpec.getG(), ecSpec.getN(), ecSpec.getH())
            );

            return new BCECPublicKey("ECDSA", keyParams, ecSpec, BouncyCastleProvider.CONFIGURATION);
        }

        @Override
        public String serializePublicKey(PublicKey key) {
            return Base64.getEncoder().encodeToString(((ECPublicKey)key).getQ().getEncoded(true));
        }

        @Override
        public KeyPair generateKey() throws GeneralSecurityException {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA", "BC");
            keyGen.initialize(ecSpec, Utils.getSecureRandom());

            return keyGen.generateKeyPair();
        }
    }

    private static final ECDSASignatureAlgorithm SHA256_ECDSA_P256
            = new ECDSASignatureAlgorithm(ECNamedCurveTable.getParameterSpec("secp256r1"), "SHA256");
    private static final ECDSASignatureAlgorithm SHA384_ECDSA_P384
            = new ECDSASignatureAlgorithm(ECNamedCurveTable.getParameterSpec("secp384r1"), "SHA384");

    public static TrailingSignatureAlgorithm forCryptoAlgorithm(CryptoAlgorithm algorithm) {
        switch (algorithm) {
            case ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256:
                return SHA256_ECDSA_P256;
            case ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384:
            case ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384:
                return SHA384_ECDSA_P384;
            default:
                throw new IllegalStateException("Algorithm does not support trailing signature");
        }
    }
}

