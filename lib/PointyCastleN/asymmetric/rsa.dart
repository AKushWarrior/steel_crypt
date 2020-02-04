// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.impl.asymmetric_block_cipher.rsa;

// ignore_for_file: omit_local_variable_types, prefer_single_quotes, non_constant_identifier_names, directives_ordering

import 'dart:typed_data';

import '../api.dart';
import '../src/impl/base_asymmetric_block_cipher.dart';
import '../src/registry/registry.dart';
import '../src/utils.dart' as utils;
import 'api.dart';

class RSAEngine extends BaseAsymmetricBlockCipher {
  static final FactoryConfig FACTORY_CONFIG =
  StaticFactoryConfig(AsymmetricBlockCipher, 'RSA', () => RSAEngine());

  bool _forEncryption;
  RSAAsymmetricKey _key;
  BigInt _dP;
  BigInt _dQ;
  BigInt _qInv;

  @override
  String get algorithmName => 'RSA';

  @override
  int get inputBlockSize {
    if (_key == null) {
      throw StateError(
          'Input block size cannot be calculated until init() called');
    }

    var bitSize = _key.modulus.bitLength;
    if (_forEncryption) {
      return ((bitSize + 7) ~/ 8) - 1;
    } else {
      return (bitSize + 7) ~/ 8;
    }
  }

  @override
  int get outputBlockSize {
    if (_key == null) {
      throw StateError(
          'Output block size cannot be calculated until init() called');
    }

    var bitSize = _key.modulus.bitLength;
    if (_forEncryption) {
      return (bitSize + 7) ~/ 8;
    } else {
      return ((bitSize + 7) ~/ 8) - 1;
    }
  }

  @override
  void reset() {}

  @override
  void init(bool forEncryption,
      covariant AsymmetricKeyParameter<RSAAsymmetricKey> params) {
    _forEncryption = forEncryption;
    _key = params.key;

    if (_key is RSAPrivateKey) {
      var privKey = (_key as RSAPrivateKey);
      var pSub1 = (privKey.p - BigInt.one);
      var qSub1 = (privKey.q - BigInt.one);
      _dP = privKey.d.remainder(pSub1);
      _dQ = privKey.d.remainder(qSub1);
      _qInv = privKey.q.modInverse(privKey.p);
    }
  }

  @override
  int processBlock(Uint8List inp, int inpOff, int len, Uint8List out, int outOff) {
    var input = _convertInput(inp, inpOff, len);
    var output = _processBigInteger(input);
    return _convertOutput(output, out, outOff);
  }

  BigInt _convertInput(Uint8List inp, int inpOff, int len) {
    var inpLen = inp.length;

    if (inpLen > (inputBlockSize + 1)) {
      throw ArgumentError('Input too large for RSA cipher');
    }

    if ((inpLen == (inputBlockSize + 1)) && !_forEncryption) {
      throw ArgumentError('Input too large for RSA cipher');
    }

    var res = utils.decodeBigInt(inp.sublist(inpOff, inpOff + len));
    if (res >= _key.modulus) {
      throw ArgumentError('Input too large for RSA cipher');
    }

    return res;
  }

  int _convertOutput(BigInt result, Uint8List out, int outOff) {
    final output = utils.encodeBigInt(result);

    if (_forEncryption) {
      if ((output[0] == 0) && (output.length > outputBlockSize)) {
        // have ended up with an extra zero byte, copy down.
        var len = (output.length - 1);
        out.setRange(outOff, outOff + len, output.sublist(1));
        return len;
      }
      if (output.length < outputBlockSize) {
        // have ended up with less bytes than normal, lengthen
        var len = outputBlockSize;
        out.setRange((outOff + len - output.length), (outOff + len), output);
        return len;
      }
    } else {
      if (output[0] == 0) {
        // have ended up with an extra zero byte, copy down.
        var len = (output.length - 1);
        out.setRange(outOff, outOff + len, output.sublist(1));
        return len;
      }
    }

    out.setAll(outOff, output);
    return output.length;
  }

  BigInt _processBigInteger(BigInt input) {
    if (_key is RSAPrivateKey) {
      var privKey = (_key as RSAPrivateKey);
      BigInt mP, mQ, h, m;

      mP = (input.remainder(privKey.p)).modPow(_dP, privKey.p);

      mQ = (input.remainder(privKey.q)).modPow(_dQ, privKey.q);

      h = mP - mQ;
      h = h * _qInv;
      h = h % privKey.p;

      m = h * privKey.q;
      m = m + mQ;

      return m;
    } else {
      return input.modPow(_key.exponent, _key.modulus);
    }
  }
}
