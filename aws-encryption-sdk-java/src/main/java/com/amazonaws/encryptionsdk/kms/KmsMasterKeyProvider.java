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

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import com.amazonaws.ClientConfiguration;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.DataKey;
import com.amazonaws.encryptionsdk.EncryptedDataKey;
import com.amazonaws.encryptionsdk.MasterKey;
import com.amazonaws.encryptionsdk.MasterKeyProvider;
import com.amazonaws.encryptionsdk.MasterKeyRequest;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.NoSuchMasterKeyException;
import com.amazonaws.encryptionsdk.exception.UnsupportedProviderException;
import com.amazonaws.internal.StaticCredentialsProvider;
import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClient;

/**
 * Provides {@link MasterKey}s backed by the AWS Key Management Service. This object is regional and
 * if you want to use keys from multiple regions, you'll need multiple copies of this object.
 */
public class KmsMasterKeyProvider extends MasterKeyProvider<KmsMasterKey> implements KmsMethods {
    private static final String PROVIDER_NAME = "aws-kms";
    private final AWSKMS kms_;
    private final List<String> keyIds_;
    private final List<String> grantTokens_ = new ArrayList<>();
    private Region region_;
    private String regionName_;

    /**
     * Returns an instance of this object with default settings, default credentials, and configured
     * to talk to the {@link Regions#DEFAULT_REGION}.
     */
    public KmsMasterKeyProvider() {
        this(new AWSKMSClient(), Region.getRegion(Regions.DEFAULT_REGION), Collections.<String> emptyList());
    }

    /**
     * Returns an instance of this object with default settings and credentials configured to speak
     * to the region specified by {@code keyId} (if specified). Data will be protected with
     * {@code keyId} as appropriate.
     */
    public KmsMasterKeyProvider(final String keyId) {
        this(new AWSKMSClient(), getStartingRegion(keyId), Collections.singletonList(keyId));
    }

    /**
     * Returns an instance of this object with default settings configured to speak to the region
     * specified by {@code keyId} (if specified). Data will be protected with {@code keyId} as
     * appropriate.
     */
    public KmsMasterKeyProvider(final AWSCredentials creds, final String keyId) {
        this(new StaticCredentialsProvider(creds), getStartingRegion(keyId), new ClientConfiguration(),
                keyId);
    }

    /**
     * Returns an instance of this object with default settings configured to speak to the region
     * specified by {@code keyId} (if specified). Data will be protected with {@code keyId} as
     * appropriate.
     */
    public KmsMasterKeyProvider(final AWSCredentialsProvider creds, final String keyId) {
        this(creds, getStartingRegion(keyId), new ClientConfiguration(), keyId);
    }

    /**
     * Returns an instance of this object with default settings and configured to talk to the
     * {@link Regions#DEFAULT_REGION}.
     */
    public KmsMasterKeyProvider(final AWSCredentials creds) {
        this(new StaticCredentialsProvider(creds), Region.getRegion(Regions.DEFAULT_REGION), new ClientConfiguration(),
                Collections.<String> emptyList());
    }

    /**
     * Returns an instance of this object with default settings and configured to talk to the
     * {@link Regions#DEFAULT_REGION}.
     */
    public KmsMasterKeyProvider(final AWSCredentialsProvider creds) {
        this(creds, Region.getRegion(Regions.DEFAULT_REGION), new ClientConfiguration(), Collections
                .<String> emptyList());
    }

    /**
     * Returns an instance of this object with the supplied configuration and credentials.
     * {@code keyId} will be used to protect data.
     */
    public KmsMasterKeyProvider(final AWSCredentialsProvider creds, final Region region,
            final ClientConfiguration clientConfiguration, final String keyId) {
        this(new AWSKMSClient(creds, clientConfiguration), region, Collections.singletonList(keyId));
    }

    /**
     * Returns an instance of this object with the supplied configuration and credentials. all keys
     * listed in {@code keyIds} will be used to protect data.
     */
    public KmsMasterKeyProvider(final AWSCredentialsProvider creds, final Region region,
            final ClientConfiguration clientConfiguration, final List<String> keyIds) {
        this(new AWSKMSClient(creds, clientConfiguration), region, keyIds);
    }

    /**
     * Returns an instance of this object with the supplied client and region; the client will be 
     * configured to use the provided region. All keys listed in {@code keyIds} will be used to 
     * protect data. 
     */
    public KmsMasterKeyProvider(final AWSKMS kms, final Region region, final List<String> keyIds) {
        kms_ = kms;
        region_ = region;
        regionName_ = region.getName();
        kms_.setRegion(region);
        keyIds_ = new ArrayList<>(keyIds);
    }

    /**
     * Returns "aws-kms"
     */
    @Override
    public String getDefaultProviderId() {
        return PROVIDER_NAME;
    }

    @Override
    public KmsMasterKey getMasterKey(final String provider, final String keyId) throws UnsupportedProviderException,
            NoSuchMasterKeyException {
        if (!canProvide(provider)) {
            throw new UnsupportedProviderException();
        }
        final KmsMasterKey result = KmsMasterKey.getInstance(kms_, keyId, this);
        result.setGrantTokens(grantTokens_);
        return result;
    }

    /**
     * Returns all CMKs provided to the constructor of this object.
     */
    @Override
    public List<KmsMasterKey> getMasterKeysForEncryption(final MasterKeyRequest request) {
        if (keyIds_ == null) {
            return Collections.emptyList();
        }
        List<KmsMasterKey> result = new ArrayList<>(keyIds_.size());
        for (String id : keyIds_) {
            result.add(getMasterKey(id));
        }
        return result;
    }

    @Override
    public DataKey<KmsMasterKey> decryptDataKey(final CryptoAlgorithm algorithm,
            final Collection<? extends EncryptedDataKey> encryptedDataKeys, final Map<String, String> encryptionContext)
            throws UnsupportedProviderException, AwsCryptoException {
        final List<Exception> exceptions = new ArrayList<>();
        for (final EncryptedDataKey edk : encryptedDataKeys) {
            if (canProvide(edk.getProviderId())) {
                try {
                    // Check for it being the right region
                    final String keyArn = new String(edk.getProviderInformation(), StandardCharsets.UTF_8);
                    final String keyRegion = parseRegionfromKeyArn(keyArn);
                    if (regionName_.equals(keyRegion)) {
                        final DataKey<KmsMasterKey> result = getMasterKey(keyArn).decryptDataKey(algorithm,
                                Collections.singletonList(edk), encryptionContext);
                        if (result != null) {
                            return result;
                        }
                    }
                } catch (final Exception asex) {
                    exceptions.add(asex);
                }
            }
        }
        throw buildCannotDecryptDksException(exceptions);
    }

    @Override
    public void setGrantTokens(final List<String> grantTokens) {
        grantTokens_.clear();
        grantTokens_.addAll(grantTokens);
    }

    @Override
    public List<String> getGrantTokens() {
        return grantTokens_;
    }

    @Override
    public void addGrantToken(final String grantToken) {
        grantTokens_.add(grantToken);
    }

    /**
     * Configures this provider to use a custom endpoint. Sets the underlying {@link Region} object
     * to {@code null}, and instructs the internal KMS client to use the specified {@code endPoint}
     * and {@code regionName}.
     */
    public void setCustomEndpoint(final String regionName, final String endPoint) {
        if (kms_ instanceof AWSKMSClient) {
            kms_.setEndpoint(endPoint);
            ((AWSKMSClient)kms_).setSignerRegionOverride(regionName);
        } else {
            throw new IllegalStateException("This method can only be called when kms is an instance of AWSKMSClient");
        }
        region_ = null;
        regionName_ = regionName;
    }

    /**
     * Set the AWS region of the AWS KMS service for access to the master key. This method simply
     * calls the same method of the underlying {@link AWSKMSClient}
     *
     * @param region
     *            string containing the region.
     */
    public void setRegion(final Region region) {
        kms_.setRegion(region);
        region_ = region;
        regionName_ = region.getName();
    }

    public Region getRegion() {
        return region_;
    }

    private static Region getStartingRegion(final String keyArn) {
        final String region = parseRegionfromKeyArn(keyArn);
        if (region != null) {
            return Region.getRegion(Regions.fromName(region));
        }
        final Region currentRegion = Regions.getCurrentRegion();
        if (currentRegion != null) {
            return currentRegion;
        }

        return Region.getRegion(Regions.DEFAULT_REGION);
    }

    private static String parseRegionfromKeyArn(final String keyArn) {
        final String[] parts = keyArn.split(":", 5);

        if (!parts[0].equals("arn")) {
            // Not an arn
            return null;
        }
        // parts[1].equals("aws"); // This can vary
        if (!parts[2].equals("kms")) {
            // Not a kms arn
            return null;
        }
        return parts[3]; // return region
    }
}
