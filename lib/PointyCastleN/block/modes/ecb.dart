// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

// ignore_for_file: omit_local_variable_types, prefer_single_quotes, non_constant_identifier_names, directives_ordering

library pointycastle.impl.block_cipher.modes.ecb;

import "dart:typed_data";

import '../../api.dart';
import '../../src/impl/base_block_cipher.dart';
import '../../src/registry/registry.dart';

/// Implementation of Electronic Code Book (ECB) mode on top of a [BlockCipher].
class ECBBlockCipher extends BaseBlockCipher {
  /// Intended for internal use.
  static final FactoryConfig FACTORY_CONFIG = DynamicFactoryConfig.suffix(
      BlockCipher,
      "/ECB",
      (_, final Match match) => () {
            BlockCipher underlying = BlockCipher(match.group(1));
            return ECBBlockCipher(underlying);
          });

  final BlockCipher _underlyingCipher;

  ECBBlockCipher(this._underlyingCipher);

  @override
  String get algorithmName => "${_underlyingCipher.algorithmName}/ECB";

  @override
  int get blockSize => _underlyingCipher.blockSize;

  @override
  void reset() {
    _underlyingCipher.reset();
  }

  @override
  void init(bool forEncryption, CipherParameters params) {
    _underlyingCipher.init(forEncryption, params);
  }

  @override
  int processBlock(Uint8List inp, int inpOff, Uint8List out, int outOff) =>
      _underlyingCipher.processBlock(inp, inpOff, out, outOff);
}
