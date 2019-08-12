// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

part of pointycastle.api;

abstract class KeyGenerator extends Algorithm {
  /// Create the key generator specified by the standard [algorithmName].
  factory KeyGenerator(String algorithmName) =>
      registry.create<KeyGenerator>(algorithmName);

  void init(CipherParameters params);

  /// Generate a new key pair.
  AsymmetricKeyPair generateKeyPair();
}
