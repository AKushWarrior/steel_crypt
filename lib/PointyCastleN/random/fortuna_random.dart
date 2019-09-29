// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.impl.secure_random.fortuna_random;

import "dart:typed_data";

import '../api.dart';
import '../block/aes_fast.dart';
import 'auto_seed_block_ctr_random.dart';
import '../src/registry/registry.dart';

/// An implementation of [SecureRandom] as specified in the Fortuna algorithm.
class FortunaRandom implements SecureRandom {
  static final FactoryConfig FACTORY_CONFIG =
       StaticFactoryConfig(SecureRandom, "Fortuna", () => FortunaRandom());

  AESFastEngine _aes;
  AutoSeedBlockCtrRandom _prng;

  String get algorithmName => "Fortuna";

  FortunaRandom() {
    _aes =  AESFastEngine();
    _prng =  AutoSeedBlockCtrRandom(_aes, false);
  }

  void seed(covariant KeyParameter param) {
    if (param.key.length != 32) {
      throw  ArgumentError(
          "Fortuna PRNG can only be used with 256 bits keys");
    }

    final iv =  Uint8List(16);
    iv[15] = 1;
    _prng.seed( ParametersWithIV(param, iv));
  }

  int nextUint8() => _prng.nextUint8();

  int nextUint16() => _prng.nextUint16();

  int nextUint32() => _prng.nextUint32();

  BigInt nextBigInteger(int bitLength) => _prng.nextBigInteger(bitLength);

  Uint8List nextBytes(int count) {
    if (count > 1048576) {
      throw  ArgumentError(
          "Fortuna PRNG cannot generate more than 1MB of random data per invocation");
    }

    return _prng.nextBytes(count);
  }
}
