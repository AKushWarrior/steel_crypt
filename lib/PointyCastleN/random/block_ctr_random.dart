// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.impl.secure_random.block_ctr_random;

import "dart:typed_data";

import '../api.dart';
import '../src/registry/registry.dart';
import '../src/ufixnum.dart';
import '../src/impl/secure_random_base.dart';

class BlockCtrRandom extends SecureRandomBase implements SecureRandom {
  /// Intended for internal use.
  static final FactoryConfig FACTORY_CONFIG = new DynamicFactoryConfig.regex(
      SecureRandom,
      r"^(.*)/CTR/PRNG$",
      (_, final Match match) => () {
            String blockCipherName = match.group(1);
            BlockCipher blockCipher = new BlockCipher(blockCipherName);
            return new BlockCtrRandom(blockCipher);
          });

  final BlockCipher cipher;

  Uint8List _input;
  Uint8List _output;
  var _used;

  BlockCtrRandom(this.cipher) {
    _input = new Uint8List(cipher.blockSize);
    _output = new Uint8List(cipher.blockSize);
    _used = _output.length;
  }

  String get algorithmName => "${cipher.algorithmName}/CTR/PRNG";

  void seed(CipherParameters params) {
    _used = _output.length;
    if (params is ParametersWithIV) {
      _input.setAll(0, params.iv);
      cipher.init(true, params.parameters);
    } else {
      cipher.init(true, params);
    }
  }

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
