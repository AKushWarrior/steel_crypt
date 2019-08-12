// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

part of pointycastle.api;

/// The interface that a padding conforms to.
abstract class Padding extends Algorithm {
  /// Create the digest specified by the standard [algorithmName].
  factory Padding(String algorithmName) =>
      registry.create<Padding>(algorithmName);

  /// Initialise the padder. Normally, paddings don't need any init params.
  void init([CipherParameters params]);

  Uint8List process(bool pad, Uint8List data);

  int addPadding(Uint8List data, int offset);

  /// Get the number of pad bytes present in the block.
  int padCount(Uint8List data);
}
