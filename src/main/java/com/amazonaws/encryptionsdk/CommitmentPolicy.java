// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk;

public enum CommitmentPolicy {
  ForbidEncryptAllowDecrypt,
  RequireEncryptAllowDecrypt,
  RequireEncryptRequireDecrypt;

  public boolean algorithmAllowedForEncrypt(CryptoAlgorithm algorithm) {
    switch (this) {
      case ForbidEncryptAllowDecrypt:
        return !algorithm.isCommitting();
      case RequireEncryptAllowDecrypt:
      case RequireEncryptRequireDecrypt:
        return algorithm.isCommitting();
      default:
        throw new UnsupportedOperationException(
            "Support for commitment policy " + this + " not yet built.");
    }
  }

  public boolean algorithmAllowedForDecrypt(CryptoAlgorithm algorithm) {
    switch (this) {
      case ForbidEncryptAllowDecrypt:
      case RequireEncryptAllowDecrypt:
        return true;
      case RequireEncryptRequireDecrypt:
        return algorithm.isCommitting();
      default:
        throw new UnsupportedOperationException(
            "Support for commitment policy " + this + " not yet built.");
    }
  }
}
