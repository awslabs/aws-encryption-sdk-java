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

package com.amazonaws.encryptionsdk.kms;

import javax.crypto.SecretKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.DataKey;
import com.amazonaws.encryptionsdk.EncryptedDataKey;
import com.amazonaws.encryptionsdk.MasterKey;
import com.amazonaws.encryptionsdk.MasterKeyProvider;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.UnsupportedProviderException;
import com.amazonaws.encryptionsdk.keyrings.StandardKeyrings;
import com.amazonaws.services.kms.AWSKMS;

import static java.util.Collections.emptyList;

/**
 * Represents a single Customer Master Key (CMK) and is used to encrypt/decrypt data with
 * {@link AwsCrypto}.
 *
 * @deprecated Replaced by {@code AwsKmsSymmetricKeyring} and {@code AwsKmsSymmetricRegionDiscoveryKeyring}. See {@link StandardKeyrings}.
 */
@Deprecated
public final class KmsMasterKey extends MasterKey<KmsMasterKey> implements KmsMethods {
    private final AwsKmsDataKeyEncryptionDao dataKeyEncryptionDao_;
    private final MasterKeyProvider<KmsMasterKey> sourceProvider_;
    private final String id_;

    /**
     * @deprecated Use a {@link KmsMasterKeyProvider} to obtain {@link KmsMasterKey}s.
     */
    @Deprecated
    public static KmsMasterKey getInstance(final AWSCredentials creds, final String keyId) {
        return new KmsMasterKeyProvider(creds, keyId).getMasterKey(keyId);
    }

    /**
     * @deprecated Use a {@link KmsMasterKeyProvider} to obtain {@link KmsMasterKey}s.
     */
    @Deprecated
    public static KmsMasterKey getInstance(final AWSCredentialsProvider creds, final String keyId) {
        return new KmsMasterKeyProvider(creds, keyId).getMasterKey(keyId);
    }

    static KmsMasterKey getInstance(final Supplier<AWSKMS> kms, final String id,
                                    final MasterKeyProvider<KmsMasterKey> provider) {
        // Allow the user agent string to be appended (in order to match existing behavior)
        return new KmsMasterKey(new AwsKmsDataKeyEncryptionDao(kms.get(), emptyList(), true), id, provider);
    }

    KmsMasterKey(final AwsKmsDataKeyEncryptionDao dataKeyEncryptionDao, final String id, final MasterKeyProvider<KmsMasterKey> provider) {
        dataKeyEncryptionDao_ = dataKeyEncryptionDao;
        id_ = id;
        sourceProvider_ = provider;
    }

    @Override
    public String getProviderId() {
        return sourceProvider_.getDefaultProviderId();
    }

    @Override
    public String getKeyId() {
        return id_;
    }

    @Override
    public DataKey<KmsMasterKey> generateDataKey(final CryptoAlgorithm algorithm,
                                                 final Map<String, String> encryptionContext) {
        final DataKeyEncryptionDao.GenerateDataKeyResult gdkResult = dataKeyEncryptionDao_.generateDataKey(
            AwsKmsCmkId.fromString(getKeyId()), algorithm, encryptionContext);
        return new DataKey<>(gdkResult.getPlaintextDataKey(),
            gdkResult.getEncryptedDataKey().getEncryptedDataKey(),
            gdkResult.getEncryptedDataKey().getProviderInformation(),
            this);
    }

    @Override
    public void setGrantTokens(final List<String> grantTokens) {
        dataKeyEncryptionDao_.setGrantTokens(grantTokens);
    }

    @Override
    public List<String> getGrantTokens() {
        return dataKeyEncryptionDao_.getGrantTokens();
    }

    @Override
    public void addGrantToken(final String grantToken) {
        dataKeyEncryptionDao_.addGrantToken(grantToken);
    }

    @Override
    public DataKey<KmsMasterKey> encryptDataKey(final CryptoAlgorithm algorithm,
                                                final Map<String, String> encryptionContext,
                                                final DataKey<?> dataKey) {
        final SecretKey key = dataKey.getKey();
        final EncryptedDataKey encryptedDataKey = dataKeyEncryptionDao_.encryptDataKey(
            AwsKmsCmkId.fromString(id_), key, encryptionContext);

        return new DataKey<>(dataKey.getKey(),
            encryptedDataKey.getEncryptedDataKey(),
            encryptedDataKey.getProviderInformation(),
            this);
    }

    @Override
    public DataKey<KmsMasterKey> decryptDataKey(final CryptoAlgorithm algorithm,
                                                final Collection<? extends EncryptedDataKey> encryptedDataKeys,
                                                final Map<String, String> encryptionContext)
        throws UnsupportedProviderException, AwsCryptoException {
        final List<Exception> exceptions = new ArrayList<>();
        for (final EncryptedDataKey edk : encryptedDataKeys) {
            try {
                final DataKeyEncryptionDao.DecryptDataKeyResult result = dataKeyEncryptionDao_.decryptDataKey(edk, algorithm, encryptionContext);
                return new DataKey<>(
                    result.getPlaintextDataKey(),
                    edk.getEncryptedDataKey(),
                    edk.getProviderInformation(), this);
            } catch (final AwsCryptoException ex) {
                exceptions.add(ex);
            }
        }

        throw buildCannotDecryptDksException(exceptions);
    }
}
