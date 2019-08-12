// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

part of pointycastle.api;


abstract class PaddedBlockCipher implements BlockCipher {
  /// Create the padded block cipher specified by the standard [algorithmName].
  factory PaddedBlockCipher(String algorithmName) =>
      registry.create<PaddedBlockCipher>(algorithmName);

  /// Get the underlying [Padding] used by this cipher.
  Padding get padding;

  /// Get the underlying [BlockCipher] used by this cipher.
  BlockCipher get cipher;


  Uint8List process(Uint8List data);


  int doFinal(Uint8List inp, int inpOff, Uint8List out, int outOff);
}
