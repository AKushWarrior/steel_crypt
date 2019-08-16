// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.impl.stream_cipher.isaac;

import "dart:typed_data";

import '../api.dart';
import '../src/impl/base_stream_cipher.dart';
import '../src/registry/registry.dart';


class ISAACEngine extends BaseStreamCipher {
  static final FactoryConfig FACTORY_CONFIG =
  StaticFactoryConfig(StreamCipher, "ISAAC", () => ISAACEngine());

  // Constants
  static int sizeL = 8;
  static int stateArraySize = sizeL << 5; // 256

  String algorithmName = "ISAAC";

  // Cipher's internal state
  Uint8List engineState; // mm
  Uint8List results; // randrsl
  int a = 0,
      b = 0,
      c = 0;

  // Engine state
  int index = 0;
  Uint8List keyStream = Uint8List(
      stateArraySize << 2); // results expanded into bytes
  Uint8List workingKey;
  bool initialised = false;

  void init(bool forEncryption, covariant KeyParameter params) {
    setKey(params.key);
    return;
  }

  int returnByte(int inp) {
    if (index == 0) {
      isaac();
      keyStream = uintToBigEndian(results);
    }
    int out = (keyStream[index] ^ inp);
    index = (index + 1) & 1023;

    return out;
  }

  static Uint8List uintToBigEndian(Uint8List n) {
    Uint8List bs = Uint8List(4 * n.length);
    uintToBigEndianimpl(n, bs, 0);
    return bs;
  }

  static void uintToBigEndianimpl(Uint8List n, Uint8List bs, int off) {
    for (int i = 0; i < n.length; ++i) {
      intToBigEndian(n[i], bs, off);
      off += 4;
    }
  }

  static void intToBigEndian(int n, Uint8List bs, int off) {
    bs[ off] = (n >> 24);
    bs[++off] = (n >> 16);
    bs[++off] = (n >> 8);
    bs[++off] = (n);
  }

  static int littleEndianToInt(Uint8List bs, int off)
  {
  int n = bs[off] & 0xff;
  n |= (bs[++off] & 0xff) << 8;
  n |= (bs[++off] & 0xff) << 16;
  n |= bs[++off] << 24;
  return n;
  }

  int processBytes(Uint8List inp, int inOff, int len, Uint8List out,
      int outOff) {
    if (!initialised) {
      throw StateError("ISAAC" + " not initialised");
    }

    if ((inOff + len) > inp.length) {
      throw ArgumentError("input buffer too short");
    }

    if ((outOff + len) > out.length) {
      throw ArgumentError("output buffer too short");
    }

    for (int i = 0; i < len; i++) {
      if (index == 0) {
        isaac();
        keyStream = uintToBigEndian(results);
      }
      out[i + outOff] = (keyStream[index] ^ inp[i + inOff]);
      index = (index + 1) & 1023;
    }

    return len;
  }


  void reset() {
    setKey(workingKey);
  }

  // Private implementation
  void setKey(Uint8List keyBytes) {
    workingKey = keyBytes;

    if (engineState == null) {
      engineState = Uint8List(stateArraySize);
    }

    if (results == null) {
      results = Uint8List(stateArraySize);
    }

    int i, j, k;

    // Reset state
    for (i = 0; i < stateArraySize; i++) {
      engineState[i] = results[i] = 0;
    }
    a = b = c = 0;

    // Reset index counter for output
    index = 0;

    // Convert the key bytes to ints and put them into results[] for initialization
    Uint8List t = Uint8List(keyBytes.length + (keyBytes.length & 3));
    var counter = 0;
    for (var i in keyBytes) {
      t[counter] = i;
      counter ++;
    }
    for (i = 0; i < t.length; i += 4) {
      results[i >> 2] = littleEndianToInt(t, i);
    }

    // It has begun?
    Uint8List abcdefgh = Uint8List(sizeL);

    for (i = 0; i < sizeL; i++) {
      abcdefgh[i] = 0x9e3779b9; // Phi (golden ratio)
    }

    for (i = 0; i < 4; i++) {
      mix(abcdefgh);
    }

    for (i = 0; i < 2; i++) {
      for (j = 0; j < stateArraySize; j += sizeL) {
        for (k = 0; k < sizeL; k++) {
          abcdefgh[k] += (i < 1) ? results[j + k] : engineState[j + k];
        }

        mix(abcdefgh);

        for (k = 0; k < sizeL; k++) {
          engineState[j + k] = abcdefgh[k];
        }
      }
    }

    isaac();

    initialised = true;
  }

  void isaac() {
    int i, x, y;

    b += ++c;
    for (i = 0; i < stateArraySize; i++) {
      x = engineState[i];
      switch (i & 3) {
        case 0:
          a ^= (a << 13);
          break;
        case 1:
          a ^= (a >> 6);
          break;
        case 2:
          a ^= (a << 2);
          break;
        case 3:
          a ^= (a >> 16);
          break;
      }
      a += engineState[(i + 128) & 0xFF];
      engineState[i] = y = engineState[(x >> 2) & 0xFF] + a + b;
      results[i] = b = engineState[(y >> 10) & 0xFF] + x;
    }
  }

  void mix (Uint8List x)
  {
  x[0]^=x[1]<< 11; x[3]+=x[0]; x[1]+=x[2];
  x[1]^=x[2]>> 2; x[4]+=x[1]; x[2]+=x[3];
  x[2]^=x[3]<< 8; x[5]+=x[2]; x[3]+=x[4];
  x[3]^=x[4]>>16; x[6]+=x[3]; x[4]+=x[5];
  x[4]^=x[5]<< 10; x[7]+=x[4]; x[5]+=x[6];
  x[5]^=x[6]>> 4; x[0]+=x[5]; x[6]+=x[7];
  x[6]^=x[7]<< 8; x[1]+=x[6]; x[7]+=x[0];
  x[7]^=x[0]>> 9; x[2]+=x[7]; x[0]+=x[1];
  }
}