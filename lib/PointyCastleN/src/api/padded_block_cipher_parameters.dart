// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

part of pointycastle.api;

class PaddedBlockCipherParameters<
        UnderlyingCipherParameters extends CipherParameters,
        PaddingCipherParameters extends CipherParameters>
    implements CipherParameters {
  final UnderlyingCipherParameters underlyingCipherParameters;
  final PaddingCipherParameters paddingCipherParameters;

  PaddedBlockCipherParameters(
      this.underlyingCipherParameters, this.paddingCipherParameters);
}
