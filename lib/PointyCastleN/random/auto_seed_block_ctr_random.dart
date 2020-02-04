// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

// ignore_for_file: omit_local_variable_types, prefer_single_quotes
// ignore_for_file: non_constant_identifier_names, directives_ordering
// ignore_for_file: prefer_typing_uninitialized_variables, camel_case_types
// ignore_for_file: annotate_overrides
library pointycastle.impl.secure_random.auto_seed_block_ctr_random;

import "dart:typed_data";

import '../api.dart';
import '../src/registry/registry.dart';
import 'block_ctr_random.dart';

class AutoSeedBlockCtrRandom implements SecureRandom {
  /// Intended for internal use.
  static final FactoryConfig FACTORY_CONFIG = DynamicFactoryConfig.regex(
      SecureRandom,
      r'^(.*)/CTR/AUTO-SEED-PRNG$',
      (_, final Match match) => () {
        var blockCipherName = match.group(1);
        var blockCipher = BlockCipher(blockCipherName);
            return AutoSeedBlockCtrRandom(blockCipher);
          });

  BlockCtrRandom _delegate;
  final bool _reseedIV;

  var _inAutoReseed = false;

  // ignore: prefer_typing_uninitialized_variables
  var _autoReseedKeyLength;

  @override
  String get algorithmName =>
      '${_delegate.cipher.algorithmName}/CTR/AUTO-SEED-PRNG';

  AutoSeedBlockCtrRandom(BlockCipher cipher, [this._reseedIV = true]) {
    _delegate = BlockCtrRandom(cipher);
  }

  @override
  void seed(CipherParameters params) {
    if (params is ParametersWithIV<KeyParameter>) {
      _autoReseedKeyLength = params.parameters.key.length;
      _delegate.seed(params);
    } else if (params is KeyParameter) {
      _autoReseedKeyLength = params.key.length;
      _delegate.seed(params);
    } else {
      throw ArgumentError(
          'Only types ParametersWithIV<KeyParameter> or KeyParameter allowed for seeding');
    }
  }

  @override
  int nextUint8() => _autoReseedIfNeededAfter(() {
    return _delegate.nextUint8();
  }) as int;

  @override
  int nextUint16() => _autoReseedIfNeededAfter(() {
    return _delegate.nextUint16();
  }) as int;

  @override
  int nextUint32() => _autoReseedIfNeededAfter(() {
    return _delegate.nextUint32();
  }) as int;

  BigInt nextBigInteger(int bitLength) => _autoReseedIfNeededAfter(() {
        return _delegate.nextBigInteger(bitLength);
  }) as BigInt;

  Uint8List nextBytes(int count) => _autoReseedIfNeededAfter(() {
        return _delegate.nextBytes(count);
  }) as Uint8List;

  dynamic _autoReseedIfNeededAfter(dynamic closure) {
    if (_inAutoReseed) {
      return closure();
    } else {
      _inAutoReseed = true;
      var ret = closure();
      _doAutoReseed();
      _inAutoReseed = false;
      return ret;
    }
  }

  void _doAutoReseed() {
    // ignore: non_constant_identifier_names
    var Key = nextBytes(_autoReseedKeyLength as int);
    var keyParam = KeyParameter(Key);

    // ignore: prefer_typing_uninitialized_variables
    var params;
    if (_reseedIV) {
      params =
          ParametersWithIV(keyParam, nextBytes(_delegate.cipher.blockSize));
    } else {
      params = keyParam;
    }

    _delegate.seed(params as CipherParameters);
  }
}
