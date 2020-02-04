// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

// ignore_for_file: omit_local_variable_types, prefer_single_quotes
// ignore_for_file: non_constant_identifier_names, directives_ordering
// ignore_for_file: prefer_typing_uninitialized_variables, camel_case_types
// ignore_for_file: annotate_overrides
library pointycastle.impl.stream_cipher.hc256;

import "dart:typed_data";

import '../api.dart';
import '../src/impl/base_stream_cipher.dart';
import '../src/registry/registry.dart';

class HC256Engine extends BaseStreamCipher {
  // ignore: non_constant_identifier_names
  static final FactoryConfig FACTORY_CONFIG =
  StaticFactoryConfig(StreamCipher, 'HC-256', () => HC256Engine());

  static Uint8List p = Uint8List(1024);
  static Uint8List q = Uint8List(1024);
  static int cnt = 0;

  @override
  final String algorithmName = 'HC-256';

  static int step() {
    var j = cnt & 0x3FF;
    int ret;
    if (cnt < 1024) {
      var x = p[(j - 3 & 0x3FF)];
      var y = p[(j - 1023 & 0x3FF)];
      p[j] += p[(j - 10 & 0x3FF)] +
          (rotateRight(x, 10) ^ rotateRight(y, 23)) +
          q[((x ^ y) & 0x3FF)];
      x = p[(j - 12 & 0x3FF)];
      ret = (q[x & 0xFF] +
              q[((x >> 8) & 0xFF) + 256] +
              q[((x >> 16) & 0xFF) + 512] +
              q[((x >> 24) & 0xFF) + 768]) ^
          p[j];
    } else {
      var x = q[(j - 3 & 0x3FF)];
      var y = q[(j - 1023 & 0x3FF)];
      q[j] += q[(j - 10 & 0x3FF)] +
          (rotateRight(x, 10) ^ rotateRight(y, 23)) +
          p[((x ^ y) & 0x3FF)];

      x = q[(j - 12 & 0x3FF)];
      ret = (p[x & 0xFF] +
              p[((x >> 8) & 0xFF) + 256] +
              p[((x >> 16) & 0xFF) + 512] +
              p[((x >> 24) & 0xFF) + 768]) ^
          q[j];
    }
    cnt = cnt + 1 & 0x7FF;
    return ret;
  }

  static Uint8List key;
  static Uint8List iv;
  static bool initialized;

  static void initialize() {
    if (key.length != 32 && key.length != 16) {
      throw ArgumentError('The key must be 128/256 bits long');
    }

    if (iv.length < 16) {
      throw ArgumentError('The IV must be at least 128 bits long');
    }

    if (iv.length < 32) {
      var newIV = Uint8List(32);
      for (var i = 0; i < iv.length; i++) {
        newIV[i] = iv[i];
      }
      for (var i = 0; i < 32 - iv.length; i++) {
        newIV[i + iv.length] = iv[i];
      }
      iv = newIV;
    }

    idx = 0;
    cnt = 0;

    var w = Uint8List(2560);

    for (var i = 0; i < 32; i++) {
      w[i >> 2] |= (key[i] & 0xff) << (8 * (i & 0x3));
    }

    for (var i = 0; i < 32; i++) {
      w[(i >> 2) + 8] |= (iv[i] & 0xff) << (8 * (i & 0x3));
    }

    for (var i = 16; i < 2560; i++) {
      var x = w[i - 2];
      var y = w[i - 15];
      w[i] = (rotateRight(x, 17) ^ rotateRight(x, 19) ^ (x >> 10)) +
          w[i - 7] +
          (rotateRight(y, 7) ^ rotateRight(y, 18) ^ (y >> 3)) +
          w[i - 16] +
          i;
    }

    for (var i = 512; i < 512 + 1024; i++) {
      p[i - 512] = w[i];
    }

    for (var i = 1536; i < 1536 + 1024; i++) {
      p[i - 1536] = w[i];
    }

    for (var i = 0; i < 4096; i++) {
      step();
    }
    ;

    cnt = 0;
  }

  static Uint8List buf = Uint8List(4);
  static int idx = 0;

  static int getByte() {
    if (idx == 0) {
      var astep = step();
      buf[0] = (astep & 0xFF);
      astep >>= 8;
      buf[1] = (astep & 0xFF);
      astep >>= 8;
      buf[2] = (astep & 0xFF);
      astep >>= 8;
      buf[3] = (astep & 0xFF);
    }
    var ret = buf[idx];
    idx = idx + 1 & 0x3;
    return ret;
  }

  @override
  void init(bool forEncryption,
      covariant ParametersWithIV<KeyParameter> params) {
    var uparams = params.parameters;
    iv = params.iv;
    key = uparams.key;
    initialized = true;
  }

  @override
  void processBytes(Uint8List inp, int inOff, int len, Uint8List out,
      int outOff) {
    if (!initialized) {
      throw StateError('HC-256 not initialised');
    }

    if ((inOff + len) > inp.length) {
      throw ArgumentError('input buffer too short');
    }

    if ((outOff + len) > out.length) {
      throw ArgumentError('output buffer too short');
    }

    for (var i = 0; i < len; i++) {
      out[outOff + i] = inp[inOff + i] ^ getByte();
    }
  }

  @override
  void reset() {
    initialize();
  }

  @override
  int returnByte(int inp) {
    return (inp ^ getByte());
  }

  static int rotateRight(int n, int count) {
    const bitCount = 64;
    assert(count >= 0 && count < bitCount);
    if (count == 0) return n;
    return (n >> count) |
    ((n >= 0) ? n << (bitCount - count) : ~(~n << (bitCount - count)));
  }
}
