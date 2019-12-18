/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package com.amazonaws.encryptionsdk.kms;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.AmazonWebServiceRequest;
import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.EncryptedDataKey;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.CannotUnwrapDataKeyException;
import com.amazonaws.encryptionsdk.exception.MismatchedDataKeyException;
import com.amazonaws.encryptionsdk.exception.UnsupportedRegionException;
import com.amazonaws.encryptionsdk.internal.VersionInfo;
import com.amazonaws.encryptionsdk.model.KeyBlob;
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
import static com.amazonaws.encryptionsdk.kms.KmsUtils.KMS_PROVIDER_ID;
import static com.amazonaws.encryptionsdk.kms.KmsUtils.getClientByArn;
import static java.util.Objects.requireNonNull;
import static org.apache.commons.lang3.Validate.isTrue;

/**
 * An implementation of DataKeyEncryptionDao that uses AWS Key Management Service (KMS) for
 * generation, encryption, and decryption of data keys. The KmsMethods interface is implemented
 * to allow usage in KmsMasterKey.
 */
class KmsDataKeyEncryptionDao implements DataKeyEncryptionDao, KmsMethods {

    private final KmsClientSupplier clientSupplier;
    private List<String> grantTokens;

    KmsDataKeyEncryptionDao(KmsClientSupplier clientSupplier, List<String> grantTokens) {
        requireNonNull(clientSupplier, "clientSupplier is required");

        this.clientSupplier = clientSupplier;
        this.grantTokens = grantTokens == null ? new ArrayList<>() : new ArrayList<>(grantTokens);
    }

    @Override
    public GenerateDataKeyResult generateDataKey(String keyId, CryptoAlgorithm algorithmSuite, Map<String, String> encryptionContext) {
        requireNonNull(keyId, "keyId is required");
        requireNonNull(algorithmSuite, "algorithmSuite is required");
        requireNonNull(encryptionContext, "encryptionContext is required");

        final com.amazonaws.services.kms.model.GenerateDataKeyResult kmsResult;

        try {
            kmsResult = getClientByArn(keyId, clientSupplier)
                    .generateDataKey(updateUserAgent(
                            new GenerateDataKeyRequest()
                                    .withKeyId(keyId)
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
                new KeyBlob(KMS_PROVIDER_ID, kmsResult.getKeyId().getBytes(PROVIDER_ENCODING), encryptedKey));
    }

    @Override
    public EncryptedDataKey encryptDataKey(final String keyId, SecretKey plaintextDataKey, Map<String, String> encryptionContext) {
        requireNonNull(keyId, "keyId is required");
        requireNonNull(plaintextDataKey, "plaintextDataKey is required");
        requireNonNull(encryptionContext, "encryptionContext is required");
        isTrue(plaintextDataKey.getFormat().equals("RAW"), "Only RAW encoded keys are supported");

        final com.amazonaws.services.kms.model.EncryptResult kmsResult;

        try {
            kmsResult = getClientByArn(keyId, clientSupplier)
                    .encrypt(updateUserAgent(new EncryptRequest()
                            .withKeyId(keyId)
                            .withPlaintext(ByteBuffer.wrap(plaintextDataKey.getEncoded()))
                            .withEncryptionContext(encryptionContext)
                            .withGrantTokens(grantTokens)));
        } catch (final AmazonServiceException ex) {
            throw new AwsCryptoException(ex);
        }
        final byte[] encryptedDataKey = new byte[kmsResult.getCiphertextBlob().remaining()];
        kmsResult.getCiphertextBlob().get(encryptedDataKey);

        return new KeyBlob(KMS_PROVIDER_ID, kmsResult.getKeyId().getBytes(PROVIDER_ENCODING), encryptedDataKey);

    }

    @Override
    public DecryptDataKeyResult decryptDataKey(EncryptedDataKey encryptedDataKey, CryptoAlgorithm algorithmSuite, Map<String, String> encryptionContext) {
        requireNonNull(encryptedDataKey, "encryptedDataKey is required");
        requireNonNull(algorithmSuite, "algorithmSuite is required");
        requireNonNull(encryptionContext, "encryptionContext is required");

        final String providerInformation = new String(encryptedDataKey.getProviderInformation(), PROVIDER_ENCODING);
        final com.amazonaws.services.kms.model.DecryptResult kmsResult;

        try {
            kmsResult = getClientByArn(providerInformation, clientSupplier)
                    .decrypt(updateUserAgent(new DecryptRequest()
                            .withCiphertextBlob(ByteBuffer.wrap(encryptedDataKey.getEncryptedDataKey()))
                            .withEncryptionContext(encryptionContext)
                            .withGrantTokens(grantTokens)));
        } catch (final AmazonServiceException | UnsupportedRegionException ex) {
            throw new CannotUnwrapDataKeyException(ex);
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
        request.getRequestClientOptions().appendUserAgent(VersionInfo.USER_AGENT);

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
