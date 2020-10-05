// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk.kms;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.AmazonWebServiceRequest;
import com.amazonaws.RequestClientOptions;
import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.EncryptedDataKey;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.CannotUnwrapDataKeyException;
import com.amazonaws.encryptionsdk.exception.MismatchedDataKeyException;
import com.amazonaws.encryptionsdk.exception.UnsupportedRegionException;
import com.amazonaws.encryptionsdk.internal.VersionInfo;
import com.amazonaws.encryptionsdk.model.KeyBlob;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.EncryptRequest;
import com.amazonaws.services.kms.model.GenerateDataKeyRequest;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static com.amazonaws.encryptionsdk.EncryptedDataKey.PROVIDER_ENCODING;
import static com.amazonaws.encryptionsdk.internal.Constants.AWS_KMS_PROVIDER_ID;
import static java.util.Objects.requireNonNull;
import static org.apache.commons.lang3.Validate.isTrue;

/**
 * An implementation of DataKeyEncryptionDao that uses AWS Key Management Service (KMS) for
 * generation, encryption, and decryption of data keys. The KmsMethods interface is implemented
 * to allow usage in KmsMasterKey.
 */
public class AwsKmsDataKeyEncryptionDao implements DataKeyEncryptionDao, KmsMethods {

    private final AWSKMS client;
    private final boolean canAppendUserAgentString;
    private List<String> grantTokens;

    AwsKmsDataKeyEncryptionDao(AWSKMS client, List<String> grantTokens) {
        // Assume the user agent string cannot be appended (default)
        this(client, grantTokens, false);
    }

    AwsKmsDataKeyEncryptionDao(AWSKMS client, List<String> grantTokens, boolean canAppendUserAgentString) {
        requireNonNull(client, "client is required");

        this.canAppendUserAgentString = canAppendUserAgentString;
        this.client = client;
        this.grantTokens = grantTokens == null ? new ArrayList<>() : new ArrayList<>(grantTokens);
    }

    @Override
    public GenerateDataKeyResult generateDataKey(AwsKmsCmkId keyId, CryptoAlgorithm algorithmSuite, Map<String, String> encryptionContext) {
        requireNonNull(keyId, "keyId is required");
        requireNonNull(algorithmSuite, "algorithmSuite is required");
        requireNonNull(encryptionContext, "encryptionContext is required");

        final com.amazonaws.services.kms.model.GenerateDataKeyResult kmsResult;

        try {
            kmsResult = client.generateDataKey(updateUserAgent(
                new GenerateDataKeyRequest()
                    .withKeyId(keyId.toString())
                    .withNumberOfBytes(algorithmSuite.getDataKeyLength())
                    .withEncryptionContext(encryptionContext)
                    .withGrantTokens(grantTokens)));
        } catch (final AmazonServiceException ex) {
            throw new AwsCryptoException(ex);
        }

        final byte[] rawKey = new byte[algorithmSuite.getDataKeyLength()];
        kmsResult.getPlaintext().get(rawKey);
        if (kmsResult.getPlaintext().remaining() > 0) {
            throw new IllegalStateException("Received an unexpected number of bytes from KMS");
        }
        final byte[] encryptedKey = new byte[kmsResult.getCiphertextBlob().remaining()];
        kmsResult.getCiphertextBlob().get(encryptedKey);

        return new GenerateDataKeyResult(new SecretKeySpec(rawKey, algorithmSuite.getDataKeyAlgo()),
            new KeyBlob(AWS_KMS_PROVIDER_ID, kmsResult.getKeyId().getBytes(PROVIDER_ENCODING), encryptedKey));
    }

    @Override
    public EncryptedDataKey encryptDataKey(final AwsKmsCmkId keyId, SecretKey plaintextDataKey, Map<String, String> encryptionContext) {
        requireNonNull(keyId, "keyId is required");
        requireNonNull(plaintextDataKey, "plaintextDataKey is required");
        requireNonNull(encryptionContext, "encryptionContext is required");
        isTrue(plaintextDataKey.getFormat().equals("RAW"), "Only RAW encoded keys are supported");

        final com.amazonaws.services.kms.model.EncryptResult kmsResult;

        try {
            kmsResult = client.encrypt(updateUserAgent(
                new EncryptRequest()
                    .withKeyId(keyId.toString())
                    .withPlaintext(ByteBuffer.wrap(plaintextDataKey.getEncoded()))
                    .withEncryptionContext(encryptionContext)
                    .withGrantTokens(grantTokens)));
        } catch (final AmazonServiceException ex) {
            throw new AwsCryptoException(ex);
        }
        final byte[] encryptedDataKey = new byte[kmsResult.getCiphertextBlob().remaining()];
        kmsResult.getCiphertextBlob().get(encryptedDataKey);

        return new KeyBlob(AWS_KMS_PROVIDER_ID, kmsResult.getKeyId().getBytes(PROVIDER_ENCODING), encryptedDataKey);

    }

    @Override
    public DecryptDataKeyResult decryptDataKey(EncryptedDataKey encryptedDataKey, CryptoAlgorithm algorithmSuite, Map<String, String> encryptionContext) {
        requireNonNull(encryptedDataKey, "encryptedDataKey is required");
        requireNonNull(algorithmSuite, "algorithmSuite is required");
        requireNonNull(encryptionContext, "encryptionContext is required");

        final String providerInformation = new String(encryptedDataKey.getProviderInformation(), PROVIDER_ENCODING);
        final com.amazonaws.services.kms.model.DecryptResult kmsResult;

        try {
            kmsResult = client.decrypt(updateUserAgent(
                new DecryptRequest()
                    .withCiphertextBlob(ByteBuffer.wrap(encryptedDataKey.getEncryptedDataKey()))
                    // provide the encrypted data key’s provider info as part of the AWS KMS Decrypt API call
                    .withKeyId(providerInformation)
                    .withEncryptionContext(encryptionContext)
                    .withGrantTokens(grantTokens)));
        } catch (final AmazonServiceException | UnsupportedRegionException ex) {
            throw new CannotUnwrapDataKeyException(ex);
        }
        if (kmsResult == null) {
            throw new IllegalStateException("Received an empty response from KMS");
        }
        if (kmsResult.getKeyId() == null) {
            throw new IllegalStateException("Received an empty keyId from KMS");
        }
        if (!kmsResult.getKeyId().equals(providerInformation)) {
            throw new MismatchedDataKeyException("Received an unexpected key Id from KMS");
        }

        final byte[] rawKey = new byte[algorithmSuite.getDataKeyLength()];
        kmsResult.getPlaintext().get(rawKey);
        if (kmsResult.getPlaintext().remaining() > 0) {
            throw new IllegalStateException("Received an unexpected number of bytes from KMS");
        }

        return new DecryptDataKeyResult(kmsResult.getKeyId(), new SecretKeySpec(rawKey, algorithmSuite.getDataKeyAlgo()));

    }

    private <T extends AmazonWebServiceRequest> T updateUserAgent(T request) {
        if (this.canAppendUserAgentString) {
            request.getRequestClientOptions().appendUserAgent(VersionInfo.USER_AGENT);
        }
        return request;
    }

    @Override
    public void setGrantTokens(List<String> grantTokens) {
        this.grantTokens = new ArrayList<>(grantTokens);
    }

    @Override
    public List<String> getGrantTokens() {
        return Collections.unmodifiableList(grantTokens);
    }

    @Override
    public void addGrantToken(String grantToken) {
        grantTokens.add(grantToken);
    }
}
