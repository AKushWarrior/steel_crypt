// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

// ignore_for_file: omit_local_variable_types, prefer_single_quotes, non_constant_identifier_names, directives_ordering, prefer_typing_uninitialized_variables

part of pointycastle.api;

/// Asymmetric block cipher engines are expected to conform to this interface.
abstract class AsymmetricBlockCipher extends Algorithm {
  /// Create the cipher specified by the standard [algorithmName].
  factory AsymmetricBlockCipher(String algorithmName) =>
      registry.create<AsymmetricBlockCipher>(algorithmName);

  /// Get this ciphers's maximum input block size.
  int get inputBlockSize;

  /// Get this ciphers's maximum output block size.
  int get outputBlockSize;

  /// Reset the cipher to its original state.
  void reset();

  void init(bool forEncryption, CipherParameters params);

  /// Process a whole block of [data] at once, returning the result in a new byte array.
  Uint8List process(Uint8List data);

  int processBlock(
      Uint8List inp, int inpOff, int len, Uint8List out, int outOff);
}
