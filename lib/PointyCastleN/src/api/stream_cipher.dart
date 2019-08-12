// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

part of pointycastle.api;

/// The interface stream ciphers conform to.
abstract class StreamCipher extends Algorithm {
  /// Create the cipher specified by the standard [algorithmName].
  factory StreamCipher(String algorithmName) =>
      registry.create<StreamCipher>(algorithmName);

  /// Reset the cipher to its original state.
  void reset();

  void init(bool forEncryption, CipherParameters params);

  /// Process a whole block of [data] at once, returning the result in a new byte array.
  Uint8List process(Uint8List data);

  /// Process one byte of data given by [inp] and return its encrypted value.
  int returnByte(int inp);

  void processBytes(
      Uint8List inp, int inpOff, int len, Uint8List out, int outOff);
}
