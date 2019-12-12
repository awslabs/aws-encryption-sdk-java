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

package com.amazonaws.encryptionsdk.keyrings;

import com.amazonaws.encryptionsdk.EncryptedDataKey;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class MultiKeyringTest {

    @Mock Keyring generatorKeyring;
    @Mock Keyring keyring1;
    @Mock Keyring keyring2;
    @Mock EncryptionMaterials encryptionMaterials;
    @Mock DecryptionMaterials decryptionMaterials;
    @Mock List<EncryptedDataKey> encryptedDataKeys;
    final List<Keyring> childrenKeyrings = new ArrayList<>();

    @BeforeEach
    void setup() {
        childrenKeyrings.add(keyring1);
        childrenKeyrings.add(keyring2);
    }

    @Test
    void testConstructor() {
        assertThrows(IllegalArgumentException.class, () -> new MultiKeyring(null, null));
        assertThrows(IllegalArgumentException.class, () -> new MultiKeyring(null, Collections.emptyList()));
        new MultiKeyring(generatorKeyring, null);
        new MultiKeyring(null, Collections.singletonList(keyring1));
    }

    @Test
    void testOnEncryptWithGenerator() {
        MultiKeyring keyring = new MultiKeyring(generatorKeyring, childrenKeyrings);
        when(encryptionMaterials.hasPlaintextDataKey()).thenReturn(true);

        keyring.onEncrypt(encryptionMaterials);

        verify(generatorKeyring).onEncrypt(encryptionMaterials);
        verify(keyring1).onEncrypt(encryptionMaterials);
        verify(keyring2).onEncrypt(encryptionMaterials);
    }

    @Test
    void testOnEncryptWithoutGenerator() {
        MultiKeyring keyring = new MultiKeyring(null, childrenKeyrings);
        when(encryptionMaterials.hasPlaintextDataKey()).thenReturn(true);

        keyring.onEncrypt(encryptionMaterials);

        verifyNoInteractions(generatorKeyring);
        verify(keyring1).onEncrypt(encryptionMaterials);
        verify(keyring2).onEncrypt(encryptionMaterials);
    }

    @Test
    void testOnEncryptNoPlaintextDataKey() {
        MultiKeyring keyring = new MultiKeyring(null, childrenKeyrings);
        when(encryptionMaterials.hasPlaintextDataKey()).thenReturn(false);

        assertThrows(AwsCryptoException.class, () -> keyring.onEncrypt(encryptionMaterials));
    }

    @Test
    void testOnDecryptWithPlaintextDataKey() {
        MultiKeyring keyring = new MultiKeyring(generatorKeyring, childrenKeyrings);

        when(decryptionMaterials.hasPlaintextDataKey()).thenReturn(true);
        keyring.onDecrypt(decryptionMaterials, encryptedDataKeys);

        verifyNoInteractions(generatorKeyring, keyring1, keyring2);
    }

    @Test
    void testOnDecryptWithGenerator() {
        MultiKeyring keyring = new MultiKeyring(generatorKeyring, childrenKeyrings);

        when(decryptionMaterials.hasPlaintextDataKey()).thenReturn(false).thenReturn(false).thenReturn(true);
        keyring.onDecrypt(decryptionMaterials, encryptedDataKeys);

        InOrder inOrder = inOrder(generatorKeyring, keyring1);
        inOrder.verify(generatorKeyring).onDecrypt(decryptionMaterials, encryptedDataKeys);
        inOrder.verify(keyring1).onDecrypt(decryptionMaterials, encryptedDataKeys);
        verifyNoInteractions(keyring2);
    }

    @Test
    void testOnDecryptWithoutGenerator() {
        MultiKeyring keyring = new MultiKeyring(null, childrenKeyrings);

        when(decryptionMaterials.hasPlaintextDataKey()).thenReturn(false).thenReturn(false).thenReturn(true);
        keyring.onDecrypt(decryptionMaterials, encryptedDataKeys);

        InOrder inOrder = inOrder(keyring1, keyring2);
        inOrder.verify(keyring1).onDecrypt(decryptionMaterials, encryptedDataKeys);
        inOrder.verify(keyring2).onDecrypt(decryptionMaterials, encryptedDataKeys);
        verifyNoInteractions(generatorKeyring);
    }

    @Test
    void testOnDecryptFailureThenSuccess() {
        MultiKeyring keyring = new MultiKeyring(generatorKeyring, childrenKeyrings);

        when(decryptionMaterials.hasPlaintextDataKey()).thenReturn(false).thenReturn(true);
        doThrow(new IllegalStateException()).when(generatorKeyring).onDecrypt(decryptionMaterials, encryptedDataKeys);

        keyring.onDecrypt(decryptionMaterials, encryptedDataKeys);

        InOrder inOrder = inOrder(generatorKeyring, keyring1);
        inOrder.verify(generatorKeyring).onDecrypt(decryptionMaterials, encryptedDataKeys);
        inOrder.verify(keyring1).onDecrypt(decryptionMaterials, encryptedDataKeys);
        verifyNoInteractions(keyring2);
    }

    @Test
    void testOnDecryptFailure() {
        MultiKeyring keyring = new MultiKeyring(generatorKeyring, childrenKeyrings);

        when(decryptionMaterials.hasPlaintextDataKey()).thenReturn(false);
        doThrow(new AwsCryptoException()).when(generatorKeyring).onDecrypt(decryptionMaterials, encryptedDataKeys);
        doThrow(new IllegalStateException()).when(keyring1).onDecrypt(decryptionMaterials, encryptedDataKeys);
        doThrow(new IllegalArgumentException()).when(keyring2).onDecrypt(decryptionMaterials, encryptedDataKeys);

        AwsCryptoException exception = null;
        try {
            keyring.onDecrypt(decryptionMaterials, encryptedDataKeys);
            fail();
        } catch (AwsCryptoException e) {
            exception = e;
        }

        assertEquals(3, exception.getSuppressed().length);

        InOrder inOrder = inOrder(generatorKeyring, keyring1, keyring2);
        inOrder.verify(generatorKeyring).onDecrypt(decryptionMaterials, encryptedDataKeys);
        inOrder.verify(keyring1).onDecrypt(decryptionMaterials, encryptedDataKeys);
        inOrder.verify(keyring2).onDecrypt(decryptionMaterials, encryptedDataKeys);
    }

    @Test
    void testOnDecryptNoFailuresNoPlaintextDataKeys() {
        MultiKeyring keyring = new MultiKeyring(generatorKeyring, childrenKeyrings);

        when(decryptionMaterials.hasPlaintextDataKey()).thenReturn(false, false, false, false);
        keyring.onDecrypt(decryptionMaterials, encryptedDataKeys);

        InOrder inOrder = inOrder(generatorKeyring, keyring1, keyring2);
        inOrder.verify(generatorKeyring).onDecrypt(decryptionMaterials, encryptedDataKeys);
        inOrder.verify(keyring1).onDecrypt(decryptionMaterials, encryptedDataKeys);
        inOrder.verify(keyring2).onDecrypt(decryptionMaterials, encryptedDataKeys);
    }

}
