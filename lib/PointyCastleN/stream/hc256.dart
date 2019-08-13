// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.impl.stream_cipher.hc256;

import "dart:typed_data";

import '../api.dart';
import '../src/impl/base_stream_cipher.dart';
import '../src/registry/registry.dart';

class HC256Engine extends BaseStreamCipher {
  static final FactoryConfig FACTORY_CONFIG =
      StaticFactoryConfig(StreamCipher, "HC-256", () => HC256Engine());

  static Uint8List p = Uint8List(1024);
  static Uint8List q = Uint8List(1024);
  static int cnt = 0;

  final String algorithmName = "HC-256";

  static int step() {
    int j = cnt & 0x3FF;
    int ret;
    if (cnt < 1024) {
      int x = p[(j - 3 & 0x3FF)];
      int y = p[(j - 1023 & 0x3FF)];
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
      int x = q[(j - 3 & 0x3FF)];
      int y = q[(j - 1023 & 0x3FF)];
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

  static initialize() {
    if (key.length != 32 && key.length != 16) {
      throw ArgumentError("The key must be 128/256 bits long");
    }

    if (iv.length < 16) {
      throw ArgumentError("The IV must be at least 128 bits long");
    }

    if (iv.length < 32) {
      Uint8List newIV = Uint8List(32);
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

    Uint8List w = Uint8List(2560);

    for (int i = 0; i < 32; i++) {
      w[i >> 2] |= (key[i] & 0xff) << (8 * (i & 0x3));
    }

    for (int i = 0; i < 32; i++) {
      w[(i >> 2) + 8] |= (iv[i] & 0xff) << (8 * (i & 0x3));
    }

    for (int i = 16; i < 2560; i++) {
      int x = w[i - 2];
      int y = w[i - 15];
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

    for (int i = 0; i < 4096; i++) {
      step();
    }
    ;

    cnt = 0;
  }

  static Uint8List buf = Uint8List(4);
  static int idx = 0;

  static int getByte() {
    if (idx == 0) {
      int astep = step();
      buf[0] = (astep & 0xFF);
      astep >>= 8;
      buf[1] = (astep & 0xFF);
      astep >>= 8;
      buf[2] = (astep & 0xFF);
      astep >>= 8;
      buf[3] = (astep & 0xFF);
    }
    int ret = buf[idx];
    idx = idx + 1 & 0x3;
    return ret;
  }

  init(bool forEncryption, covariant ParametersWithIV<KeyParameter> params) {
    var uparams = params.parameters;
    iv = params.iv;
    key = uparams.key;
    initialized = true;
  }

  void processBytes(Uint8List inp, int inOff, int len, Uint8List out, int outOff) {
    if (!initialized) {
      throw StateError('HC-256' + " not initialised");
    }

    if ((inOff + len) > inp.length) {
      throw ArgumentError("input buffer too short");
    }

    if ((outOff + len) > out.length) {
      throw ArgumentError("output buffer too short");
    }

    for (int i = 0; i < len; i++) {
      out[outOff + i] = inp[inOff + i] ^ getByte();
    }
  }

  void reset()
  {
    initialize();
  }

  int returnByte(int inp)
  {
  return (inp ^ getByte());
  }

  static int rotateRight(int x, int n) {
    return (x >> n) ^ (x << (32 - n));
  }
}
