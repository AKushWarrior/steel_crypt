// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.
library pointycastle.impl.block_cipher.modes.cbc;

// ignore_for_file: omit_local_variable_types, prefer_single_quotes, non_constant_identifier_names, directives_ordering

import "dart:typed_data";

import '../../api.dart';
import '../../src/impl/base_block_cipher.dart';
import '../../src/registry/registry.dart';

/// Implementation of Cipher-Block-Chaining (CBC) mode on top of a [BlockCipher].
class CBCBlockCipher extends BaseBlockCipher {
  /// Intended for internal use.
  // ignore: non_constant_identifier_names
  static final FactoryConfig FACTORY_CONFIG = DynamicFactoryConfig.suffix(
      BlockCipher,
      '/CBC',
      (_, final Match match) => () {
        var underlying = BlockCipher(match.group(1));
            return CBCBlockCipher(underlying);
          });

  final BlockCipher _underlyingCipher;

  Uint8List _IV;
  Uint8List _cbcV;
  Uint8List _cbcNextV;

  bool _encrypting;

  CBCBlockCipher(this._underlyingCipher) {
    _IV = Uint8List(blockSize);
    _cbcV = Uint8List(blockSize);
    _cbcNextV = Uint8List(blockSize);
  }

  @override
  String get algorithmName => '${_underlyingCipher.algorithmName}/CBC';

  @override
  int get blockSize => _underlyingCipher.blockSize;

  @override
  void reset() {
    _cbcV.setAll(0, _IV);
    _cbcNextV.fillRange(0, _cbcNextV.length, 0);

    _underlyingCipher.reset();
  }

  @override
  void init(bool forEncryption, covariant ParametersWithIV params) {
    if (params.iv.length != blockSize) {
      throw ArgumentError(
          'Initialization vector must be the same length as block size');
    }

    _encrypting = forEncryption;
    _IV.setAll(0, params.iv);

    reset();

    _underlyingCipher.init(forEncryption, params.parameters);
  }

  @override
  int processBlock(Uint8List inp, int inpOff, Uint8List out, int outOff) =>
      _encrypting
          ? _encryptBlock(inp, inpOff, out, outOff)
          : _decryptBlock(inp, inpOff, out, outOff);

  int _encryptBlock(Uint8List inp, int inpOff, Uint8List out, int outOff) {
    if ((inpOff + blockSize) > inp.length) {
      throw ArgumentError('Input buffer too short');
    }

    // XOR the cbcV and the input, then encrypt the cbcV
    for (var i = 0; i < blockSize; i++) {
      _cbcV[i] ^= inp[inpOff + i];
    }

    var length = _underlyingCipher.processBlock(_cbcV, 0, out, outOff);

    // copy ciphertext to cbcV
    _cbcV.setRange(0, blockSize, out.sublist(outOff));

    return length;
  }

  int _decryptBlock(Uint8List inp, int inpOff, Uint8List out, int outOff) {
    if ((inpOff + blockSize) > inp.length) {
      throw ArgumentError('Input buffer too short');
    }

    _cbcNextV.setRange(0, blockSize, inp.sublist(inpOff));

    var length = _underlyingCipher.processBlock(inp, inpOff, out, outOff);

    // XOR the cbcV and the output
    for (var i = 0; i < blockSize; i++) {
      out[outOff + i] ^= _cbcV[i];
    }

    // swap the back up buffer into next position
    Uint8List tmp;

    tmp = _cbcV;
    _cbcV = _cbcNextV;
    _cbcNextV = tmp;

    return length;
  }
}
