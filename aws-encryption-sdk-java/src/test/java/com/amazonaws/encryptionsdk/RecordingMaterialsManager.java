package com.amazonaws.encryptionsdk;

import java.util.Collections;

import com.amazonaws.encryptionsdk.model.DecryptionMaterialsRequest;
import com.amazonaws.encryptionsdk.model.DecryptionMaterials;
import com.amazonaws.encryptionsdk.model.EncryptionMaterialsRequest;
import com.amazonaws.encryptionsdk.model.EncryptionMaterials;

public class RecordingMaterialsManager implements CryptoMaterialsManager {
    private final CryptoMaterialsManager delegate;

    public boolean didDecrypt = false;

    public RecordingMaterialsManager(CryptoMaterialsManager delegate) {
        this.delegate = delegate;
    }

    public RecordingMaterialsManager(MasterKeyProvider<?> delegate) {
        this.delegate = new DefaultCryptoMaterialsManager(delegate);
    }

    @Override public EncryptionMaterials getMaterialsForEncrypt(
            EncryptionMaterialsRequest request
    ) {
        request = request.toBuilder().setContext(
                Collections.singletonMap("foo", "bar")
        ).build();

        EncryptionMaterials result = delegate.getMaterialsForEncrypt(request);

        return result;
    }

    @Override public DecryptionMaterials decryptMaterials(
            DecryptionMaterialsRequest request
    ) {
        didDecrypt = true;
        return delegate.decryptMaterials(request);
    }
}
