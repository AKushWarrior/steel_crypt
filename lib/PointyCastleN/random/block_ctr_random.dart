// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

// ignore_for_file: omit_local_variable_types, prefer_single_quotes
// ignore_for_file: non_constant_identifier_names, directives_ordering
// ignore_for_file: prefer_typing_uninitialized_variables, camel_case_types
// ignore_for_file: annotate_overrides
library pointycastle.impl.secure_random.block_ctr_random;

import "dart:typed_data";

import '../api.dart';
import '../src/impl/secure_random_base.dart';
import '../src/registry/registry.dart';
import '../src/ufixnum.dart';

class BlockCtrRandom extends SecureRandomBase implements SecureRandom {
  /// Intended for internal use.
  static final FactoryConfig FACTORY_CONFIG = DynamicFactoryConfig.regex(
      SecureRandom,
      r"^(.*)/CTR/PRNG$",
      (_, final Match match) => () {
            String blockCipherName = match.group(1);
            BlockCipher blockCipher = BlockCipher(blockCipherName);
            return BlockCtrRandom(blockCipher);
          });

  final BlockCipher cipher;

  Uint8List _input;
  Uint8List _output;
  int _used;

  BlockCtrRandom(this.cipher) {
    _input = Uint8List(cipher.blockSize);
    _output = Uint8List(cipher.blockSize);
    _used = _output.length;
  }

  String get algorithmName => "${cipher.algorithmName}/CTR/PRNG";

  @override
  void seed(CipherParameters params) {
    _used = _output.length;
    if (params is ParametersWithIV) {
      _input.setAll(0, params.iv);
      cipher.init(true, params.parameters);
    } else {
      cipher.init(true, params);
    }
  }

  @override
  int nextUint8() {
    if (_used == _output.length) {
      cipher.processBlock(_input, 0, _output, 0);
      _used = 0;
      _incrementInput();
    }

    return clip8(_output[_used++]);
  }

  void _incrementInput() {
    int offset = _input.length;
    do {
      offset--;
      _input[offset] += 1;
    } while (_input[offset] == 0);
  }
}
