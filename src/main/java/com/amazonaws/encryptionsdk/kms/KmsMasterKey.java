// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk.kms;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

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
                                                final Map<String, String> encryptionContext) throws AwsCryptoException {
        final List<Exception> exceptions = new ArrayList<>();
        for (final EncryptedDataKey edk : encryptedDataKeys) {
            try {
                final String edkKeyId = new String(edk.getProviderInformation(), StandardCharsets.UTF_8);
                if (!edkKeyId.equals(id_)) {
                    continue;
                }
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
