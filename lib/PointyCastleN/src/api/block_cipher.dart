// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

// ignore_for_file: omit_local_variable_types, prefer_single_quotes
// ignore_for_file: non_constant_identifier_names, directives_ordering
// ignore_for_file: prefer_typing_uninitialized_variables, camel_case_types
// ignore_for_file: annotate_overrides

part of pointycastle.api;

/// Block cipher engines are expected to conform to this interface.
abstract class BlockCipher extends Algorithm {
  /// Create the cipher specified by the standard [algorithmName].
  factory BlockCipher(String algorithmName) =>
      registry.create<BlockCipher>(algorithmName);

  /// Get this ciphers's block size.
  int get blockSize;

  /// Reset the cipher to its original state.
  void reset();

  void init(bool forEncryption, CipherParameters params);

  Uint8List process(Uint8List data);

  int processBlock(Uint8List inp, int inpOff, Uint8List out, int outOff);
}
