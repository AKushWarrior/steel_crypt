// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

// ignore_for_file: omit_local_variable_types, prefer_single_quotes, non_constant_identifier_names, directives_ordering, prefer_typing_uninitialized_variables

library pointycastle.impl.key_derivator.pbkdf2;

import "dart:typed_data";

import '../api.dart';
import '../src/impl/base_key_derivator.dart';
import '../src/registry/registry.dart';
import 'api.dart';

class PBKDF2KeyDerivator extends BaseKeyDerivator {
  /// Intended for internal use.
  static final FactoryConfig FACTORY_CONFIG = DynamicFactoryConfig.suffix(
      KeyDerivator,
      "/PBKDF2",
      (_, final Match match) => () {
            Mac mac = Mac(match.group(1));
            return PBKDF2KeyDerivator(mac);
          });

  Pbkdf2Parameters _params;
  final Mac _mac;
  Uint8List _state;

  PBKDF2KeyDerivator(this._mac) {
    _state = Uint8List(_mac.macSize);
  }

  @override
  String get algorithmName => "${_mac.algorithmName}/PBKDF2";

  @override
  int get keySize => _params.desiredKeyLength;

  void reset() {
    _mac.reset();
    _state.fillRange(0, _state.length, 0);
  }

  @override
  void init(covariant Pbkdf2Parameters params) {
    _params = params;
  }

  @override
  int deriveKey(Uint8List inp, int inpOff, Uint8List out, int outOff) {
    var dkLen = _params.desiredKeyLength;
    var hLen = _mac.macSize;
    var l = (dkLen + hLen - 1) ~/ hLen;
    var iBuf = Uint8List(4);
    var outBytes = Uint8List(l * hLen);
    var outPos = 0;

    CipherParameters param = KeyParameter(inp.sublist(inpOff));
    _mac.init(param);

    for (var i = 1; i <= l; i++) {
      // Increment the value in 'iBuf'
      for (var pos = 3;; pos--) {
        iBuf[pos]++;
        if (iBuf[pos] != 0) break;
      }

      _F(_params.salt, _params.iterationCount, iBuf, outBytes, outPos);
      outPos += hLen;
    }

    out.setRange(outOff, outOff + dkLen, outBytes);

    return keySize;
  }

  void _F(Uint8List S, int c, Uint8List iBuf, Uint8List out, int outOff) {
    if (c <= 0) {
      throw ArgumentError("Iteration count must be at least 1.");
    }

    if (S != null) {
      _mac.update(S, 0, S.length);
    }

    _mac.update(iBuf, 0, iBuf.length);
    _mac.doFinal(_state, 0);

    out.setRange(outOff, outOff + _state.length, _state);

    for (var count = 1; count < c; count++) {
      _mac.update(_state, 0, _state.length);
      _mac.doFinal(_state, 0);

      for (var j = 0; j != _state.length; j++) {
        out[outOff + j] ^= _state[j];
      }
    }
  }
}
