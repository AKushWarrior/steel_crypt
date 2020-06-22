// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

// ignore_for_file: omit_local_variable_types, prefer_single_quotes
// ignore_for_file: non_constant_identifier_names, directives_ordering
// ignore_for_file: prefer_typing_uninitialized_variables, camel_case_types
// ignore_for_file: annotate_overrides

library pointycastle.impl.stream_cipher.sic;

import 'dart:typed_data';

import '../api.dart';
import '../src/impl/base_stream_cipher.dart';
import '../src/registry/registry.dart';
import '../src/ufixnum.dart';

class SICStreamCipher extends BaseStreamCipher {
  /// Intended for internal use.
  static final FactoryConfig FACTORY_CONFIG = DynamicFactoryConfig.suffix(
      StreamCipher,
      '/SIC',
      (_, final Match match) => () {
            var digestName = match.group(1);
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

  @override
  String get algorithmName => '${underlyingCipher.algorithmName}/SIC';

  @override
  void reset() {
    underlyingCipher.reset();
    _counter.setAll(0, _iv);
    _counterOut.fillRange(0, _counterOut.length, 0);
    _consumed = _counterOut.length;
  }

  @override
  void init(bool forEncryption, covariant ParametersWithIV params) {
    _iv.setAll(0, params.iv);
    reset();
    underlyingCipher.init(true, params.parameters);
  }

  @override
  void processBytes(
      Uint8List inp, int inpOff, int len, Uint8List out, int outOff) {
    for (var i = 0; i < len; i++) {
      out[outOff + i] = returnByte(inp[inpOff + i]);
    }
  }

  @override
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
    for (var i = _counter.lengthInBytes - 1; i >= 0; i--) {
      var val = _counter[i];
      val++;
      _counter[i] = val;
      if (_counter[i] != 0) break;
    }
  }
}
