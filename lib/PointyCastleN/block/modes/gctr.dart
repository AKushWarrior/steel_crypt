// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

// ignore_for_file: omit_local_variable_types, prefer_single_quotes, non_constant_identifier_names, directives_ordering

library pointycastle.impl.block_cipher.modes.gctr;

import "dart:typed_data";

import '../../api.dart';
import '../../src/impl/base_block_cipher.dart';
import '../../src/registry/registry.dart';
import '../../src/ufixnum.dart';

/// Implementation of GOST 28147 OFB counter mode (GCTR) on top of a [BlockCipher].
class GCTRBlockCipher extends BaseBlockCipher {
  /// Intended for internal use.
  // ignore: non_constant_identifier_names
  static final FactoryConfig FACTORY_CONFIG = DynamicFactoryConfig.suffix(
      BlockCipher,
      '/GCTR',
      (_, final Match match) => () {
        var underlying = BlockCipher(match.group(1));
            return GCTRBlockCipher(underlying);
          });

  static const C1 = 16843012; //00000001000000010000000100000100
  static const C2 = 16843009; //00000001000000010000000100000001

  final BlockCipher _underlyingCipher;

  // ignore: non_constant_identifier_names
  Uint8List _IV;
  Uint8List _ofbV;
  Uint8List _ofbOutV;

  bool _firstStep = true;

  // ignore: non_constant_identifier_names
  int _N3;

  // ignore: non_constant_identifier_names
  int _N4;

  GCTRBlockCipher(this._underlyingCipher) {
    if (blockSize != 8) {
      throw ArgumentError('GCTR can only be used with 64 bit block ciphers');
    }

    _IV = Uint8List(_underlyingCipher.blockSize);
    _ofbV = Uint8List(_underlyingCipher.blockSize);
    _ofbOutV = Uint8List(_underlyingCipher.blockSize);
  }

  @override
  int get blockSize => _underlyingCipher.blockSize;

  @override
  String get algorithmName => '${_underlyingCipher.algorithmName}/GCTR';

  @override
  void reset() {
    _ofbV.setRange(0, _IV.length, _IV);
    _underlyingCipher.reset();
  }

  @override
  void init(bool encrypting, CipherParameters params) {
    _firstStep = true;
    _N3 = 0;
    _N4 = 0;

    if (params is ParametersWithIV) {
      var ivParam = params;
      var iv = ivParam.iv;

      if (iv.length < _IV.length) {
        // prepend the supplied IV with zeros (per FIPS PUB 81)
        var offset = _IV.length - iv.length;
        _IV.fillRange(0, offset, 0);
        _IV.setRange(offset, _IV.length, iv);
      } else {
        _IV.setRange(0, _IV.length, iv);
      }

      reset();

      // if params is null we reuse the current working key.
      if (ivParam.parameters != null) {
        _underlyingCipher.init(true, ivParam.parameters);
      }
    } else {
      reset();

      // if params is null we reuse the current working key.
      if (params != null) {
        _underlyingCipher.init(true, params);
      }
    }
  }

  @override
  int processBlock(Uint8List inp, int inpOff, Uint8List out, int outOff) {
    if ((inpOff + blockSize) > inp.length) {
      throw ArgumentError('Input buffer too short');
    }

    if ((outOff + blockSize) > out.length) {
      throw ArgumentError('Output buffer too short');
    }

    if (_firstStep) {
      _firstStep = false;
      _underlyingCipher.processBlock(_ofbV, 0, _ofbOutV, 0);
      _N3 = _bytesToint(_ofbOutV, 0);
      _N4 = _bytesToint(_ofbOutV, 4);
    }
    _N3 += C2;
    _N4 += C1;
    _intTobytes(_N3, _ofbV, 0);
    _intTobytes(_N4, _ofbV, 4);

    _underlyingCipher.processBlock(_ofbV, 0, _ofbOutV, 0);

    // XOR the ofbV with the plaintext producing the cipher text (and the next input block).
    for (var i = 0; i < blockSize; i++) {
      out[outOff + i] = _ofbOutV[i] ^ inp[inpOff + i];
    }

    // change over the input block.
    var offset = _ofbV.length - blockSize;
    _ofbV.setRange(0, offset, _ofbV.sublist(blockSize));
    _ofbV.setRange(offset, _ofbV.length, _ofbOutV);

    return blockSize;
  }

  int _bytesToint(Uint8List inp, int inpOff) {
    return unpack32(inp, inpOff, Endian.little);
  }

  void _intTobytes(int num, Uint8List out, int outOff) {
    pack32(num, out, outOff, Endian.little);
  }
}
