// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

// ignore_for_file: omit_local_variable_types, prefer_single_quotes, non_constant_identifier_names, directives_ordering

library pointycastle.impl.block_cipher.modes.ofb;

import "dart:typed_data";

import '../../api.dart';
import '../../src/impl/base_block_cipher.dart';
import '../../src/registry/registry.dart';

/// Implementation of Output FeedBack mode (OFB) on top of a [BlockCipher].
class OFBBlockCipher extends BaseBlockCipher {
  /// Intended for internal use.
  // ignore: non_constant_identifier_names
  static final FactoryConfig FACTORY_CONFIG = DynamicFactoryConfig.regex(
      BlockCipher,
      r'^(.+)/OFB-([0-9]+)$',
      (_, final Match match) => () {
        var underlying = BlockCipher(match.group(1));
        var blockSizeInBits = int.parse(match.group(2));
            if ((blockSizeInBits % 8) != 0) {
              throw RegistryFactoryException.invalid(
                  'Bad OFB block size: $blockSizeInBits (must be a multiple of 8)');
            }
            return OFBBlockCipher(underlying, blockSizeInBits ~/ 8);
          });

  @override
  final int blockSize;

  final BlockCipher _underlyingCipher;

  // ignore: non_constant_identifier_names
  Uint8List _IV;
  Uint8List _ofbV;
  Uint8List _ofbOutV;

  OFBBlockCipher(this._underlyingCipher, this.blockSize) {
    _IV = Uint8List(_underlyingCipher.blockSize);
    _ofbV = Uint8List(_underlyingCipher.blockSize);
    _ofbOutV = Uint8List(_underlyingCipher.blockSize);
  }

  @override
  String get algorithmName =>
      '${_underlyingCipher.algorithmName}/OFB-${blockSize * 8}';

  @override
  void reset() {
    _ofbV.setRange(0, _IV.length, _IV);
    _underlyingCipher.reset();
  }

  @override
  void init(bool forEncryption, CipherParameters params) {
    if (params is ParametersWithIV) {
      var ivParam = params;
      var iv = ivParam.iv;

      if (iv.length < _IV.length) {
        // prepend the supplied IV with zeros (per FIPS PUB 81)
        var offset = _IV.length - iv.length;
        _IV.fillRange(0, offset, 0);
        _IV.setAll(offset, iv);
      } else {
        _IV.setRange(0, _IV.length, iv);
      }

      reset();

      // if null it's an IV changed only.
      if (ivParam.parameters != null) {
        _underlyingCipher.init(true, ivParam.parameters);
      }
    } else {
      _underlyingCipher.init(true, params);
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
}
