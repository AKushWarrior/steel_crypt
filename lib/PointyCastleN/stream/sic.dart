// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.impl.stream_cipher.sic;

import "dart:typed_data";

import '../api.dart';
import '../src/impl/base_stream_cipher.dart';
import '../src/ufixnum.dart';
import '../src/registry/registry.dart';

class SICStreamCipher extends BaseStreamCipher {
  /// Intended for internal use.
  static final FactoryConfig FACTORY_CONFIG = DynamicFactoryConfig.suffix(
      StreamCipher,
      "/SIC",
      (_, final Match match) => () {
            String digestName = match.group(1);
            return SICStreamCipher(BlockCipher(digestName));
          });

  final BlockCipher underlyingCipher;

  Uint8List _iv;
  Uint8List _counter;
  Uint8List _counterOut;
  int _consumed;

  SICStreamCipher(this.underlyingCipher) {
    _iv = Uint8List(underlyingCipher.blockSize);
    _counter = Uint8List(underlyingCipher.blockSize);
    _counterOut = Uint8List(underlyingCipher.blockSize);
  }

  String get algorithmName => "${underlyingCipher.algorithmName}/SIC";

  void reset() {
    underlyingCipher.reset();
    _counter.setAll(0, _iv);
    _counterOut.fillRange(0, _counterOut.length, 0);
    _consumed = _counterOut.length;
  }

  void init(bool forEncryption, covariant ParametersWithIV params) {
    _iv.setAll(0, params.iv);
    reset();
    underlyingCipher.init(true, params.parameters);
  }

  void processBytes(
      Uint8List inp, int inpOff, int len, Uint8List out, int outOff) {
    for (var i = 0; i < len; i++) {
      out[outOff + i] = returnByte(inp[inpOff + i]);
    }
  }

  int returnByte(int inp) {
    _feedCounterIfNeeded();
    return clip8(inp) ^ _counterOut[_consumed++];
  }

  /// Calls [_feedCounter] if all [_counterOut] bytes have been consumed
  void _feedCounterIfNeeded() {
    if (_consumed >= _counterOut.length) {
      _feedCounter();
    }
  }

  void _feedCounter() {
    underlyingCipher.processBlock(_counter, 0, _counterOut, 0);
    _incrementCounter();
    _consumed = 0;
  }

  /// Increments [_counter] by 1
  void _incrementCounter() {
    var i;
    for (i = _counter.lengthInBytes - 1; i >= 0; i--) {
      var val = _counter[i];
      val++;
      _counter[i] = val;
      if (_counter[i] != 0) break;
    }
  }
}
