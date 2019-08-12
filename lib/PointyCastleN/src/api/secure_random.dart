// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

part of pointycastle.api;

abstract class SecureRandom extends Algorithm {
  /// Create the secure random specified by the standard [algorithmName].
  factory SecureRandom([String algorithmName = ""]) =>
      registry.create<SecureRandom>(algorithmName);

  /// Seed the RNG with some entropy (look at package cipher_entropy providing entropy sources).
  void seed(CipherParameters params);

  /// Get one byte long random int.
  int nextUint8();

  /// Get two bytes long random int.
  int nextUint16();

  /// Get four bytes long random int.
  int nextUint32();

  /// Get a random [BigInteger] of [bitLength] bits.
  BigInt nextBigInteger(int bitLength);

  /// Get a list of bytes of arbitrary length.
  Uint8List nextBytes(int count);
}
