// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

part of pointycastle.api;

/// The interface that a MAC (message authentication code) conforms to.
abstract class Mac extends Algorithm {
  /// Create the MAC specified by the standard [algorithmName].
  factory Mac(String algorithmName) => registry.create<Mac>(algorithmName);

  /// Get this MAC's output size.
  int get macSize;

  /// Reset the MAC to its original state.
  void reset();


  void init(CipherParameters params);

  /// Process a whole block of [data] at once, returning the result in a new
  /// byte array.
  Uint8List process(Uint8List data);

  /// Add one byte of data to the MAC input.
  void updateByte(int inp);


  void update(Uint8List inp, int inpOff, int len);


  int doFinal(Uint8List out, int outOff);
}
