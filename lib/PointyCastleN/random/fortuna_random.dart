// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

// ignore_for_file: omit_local_variable_types, prefer_single_quotes
// ignore_for_file: non_constant_identifier_names, directives_ordering
// ignore_for_file: prefer_typing_uninitialized_variables, camel_case_types
// ignore_for_file: annotate_overrides
library pointycastle.impl.secure_random.fortuna_random;

import 'dart:typed_data';

import '../api.dart';
import '../block/aes_fast.dart';
import '../src/registry/registry.dart';
import 'auto_seed_block_ctr_random.dart';

/// An implementation of [SecureRandom] as specified in the Fortuna algorithm.
class FortunaRandom implements SecureRandom {
  // ignore: non_constant_identifier_names
  static final FactoryConfig FACTORY_CONFIG =
      StaticFactoryConfig(SecureRandom, 'Fortuna', () => FortunaRandom());

  AESFastEngine _aes;
  AutoSeedBlockCtrRandom _prng;

  @override
  String get algorithmName => 'Fortuna';

  FortunaRandom() {
    _aes = AESFastEngine();
    _prng = AutoSeedBlockCtrRandom(_aes, false);
  }

  void seed(covariant KeyParameter param) {
    if (param.key.length != 32) {
      throw ArgumentError('Fortuna PRNG can only be used with 256 bits keys');
    }

    final iv = Uint8List(16);
    iv[15] = 1;
    _prng.seed(ParametersWithIV(param, iv));
  }

  @override
  int nextUint8() => _prng.nextUint8();

  @override
  int nextUint16() => _prng.nextUint16();

  @override
  int nextUint32() => _prng.nextUint32();

  @override
  BigInt nextBigInteger(int bitLength) => _prng.nextBigInteger(bitLength);

  @override
  Uint8List nextBytes(int count) {
    if (count > 1048576) {
      throw ArgumentError(
          'Fortuna PRNG cannot generate more than 1MB of random data per invocation');
    }

    return _prng.nextBytes(count);
  }
}
