// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

part of pointycastle.api;

abstract class KeyDerivator extends Algorithm {
  /// Create the key derivator specified by the standard [algorithmName].
  factory KeyDerivator(String algorithmName) =>
      registry.create<KeyDerivator>(algorithmName);

  /// Get this derivator key's output size.
  int get keySize;

  void init(CipherParameters params);

  /// Process a whole block of [data] at once, returning the result in a new byte array.
  Uint8List process(Uint8List data);

  /// Derive key from given input and put it in [out] at offset [outOff].
  int deriveKey(Uint8List inp, int inpOff, Uint8List out, int outOff);
}
