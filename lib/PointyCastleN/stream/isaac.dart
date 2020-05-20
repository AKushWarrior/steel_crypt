// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

// ignore_for_file: omit_local_variable_types, prefer_single_quotes
// ignore_for_file: non_constant_identifier_names, directives_ordering
// ignore_for_file: prefer_typing_uninitialized_variables, camel_case_types
// ignore_for_file: annotate_overrides
library pointycastle.impl.stream_cipher.isaac;

import 'dart:typed_data';

import '../api.dart';
import '../src/impl/base_stream_cipher.dart';
import '../src/registry/registry.dart';
import '../src/ufixnum.dart';

class ISAACEngine extends BaseStreamCipher {
  static final FactoryConfig FACTORY_CONFIG =
  StaticFactoryConfig(StreamCipher, 'ISAAC', () => ISAACEngine());

  // Constants
  static int sizeL = 8;
  static int stateArraySize = shiftl32(sizeL, 5); // 256

  @override
  String algorithmName = 'ISAAC';

  // Cipher's internal state
  List<int> engineState; // mm
  List<int> results; // randrsl
  int a = 0,
      b = 0,
      c = 0;

  // Engine state
  int index = 0;
  Uint8List keyStream = Uint8List(shiftl32(stateArraySize, 2));
  Uint8List workingKey;
  bool initialised = false;

  @override
  void init(bool forEncryption, covariant KeyParameter params) {
    setKey(params.key);
    return;
  }

  @override
  int returnByte(int inp) {
    if (index == 0) {
      isaac();
      keyStream = _intToBigEndian(results);
    }
    var out = toByte(keyStream[index] ^ inp);
    index = (index + 1) & 1023;

    return out;
  }

  @override
  int processBytes(Uint8List inp, int inOff, int len, Uint8List out,
      int outOff) {
    if (!initialised) {
      throw StateError('ISAAC not initialised');
    }

    if ((inOff + len) > inp.length) {
      throw ArgumentError('input buffer too short');
    }

    if ((outOff + len) > out.length) {
      throw ArgumentError('output buffer too short');
    }

    for (var i = 0; i < len; i++) {
      if (index == 0) {
        isaac();
        keyStream = _intToBigEndian(results);
      }
      out[i + outOff] = toByte(keyStream[index] ^ inp[i + inOff]);
      index = (index + 1) & 1023;
    }

    return len;
  }

  @override
  void reset() {
    setKey(workingKey);
  }

  // Private implementation
  void setKey(Uint8List keyBytes) {
    workingKey = keyBytes;

    engineState ??= Uint8List(stateArraySize);

    results ??= Uint8List(stateArraySize);

    int i, j, k;

    // Reset state
    for (i = 0; i < stateArraySize; i++) {
      engineState[i] = 0;
      results[i] = 0;
    }
    a = b = c = 0;

    // Reset index counter for output
    index = 0;

    // Convert the key bytes to ints and put them into results[] for initialization
    var t = Uint8List(keyBytes.length + (keyBytes.length & 3));
    var counter = 0;
    for (var i in keyBytes) {
      t[counter] = i;
      counter++;
    }
    for (i = 0; i < t.length; i += 4) {
      results[cshiftr32(i, 2)] = littleEndianToInt(t, i);
    }

    // It has begun?
    var abcdefgh = List<int>(sizeL);

    for (i = 0; i < sizeL; i++) {
      abcdefgh[i] = 0x9e3779b9; // Phi (golden ratio)
    }

    for (i = 0; i < 4; i++) {
      mix(abcdefgh);
    }

    for (i = 0; i < 2; i++) {
      for (j = 0; j < stateArraySize; j = j + sizeL) {
        for (k = 0; k < sizeL; k++) {
          abcdefgh[k] = sum32(
              abcdefgh[k], ((i < 1) ? results[j + k] : engineState[j + k]));
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

    b = b + ++c;
    for (i = 0; i < stateArraySize; i++) {
      x = engineState[i];
      switch (i & 3) {
        case 0:
          a ^= shiftl32(a, 13);
          break;
        case 1:
          a ^= cshiftr32(a, 6);
          break;
        case 2:
          a ^= shiftl32(a, 2);
          break;
        case 3:
          a ^= cshiftr32(a, 16);
          break;
      }
      a = sum32(a, engineState[(i + 128).toUnsigned(8)]);
      engineState[i] = engineState[cshiftr32(x, 2).toUnsigned(8)] + a + b;
      y = engineState[cshiftr32(x, 2).toUnsigned(8)] + a + b;
      results[i] = engineState[cshiftr32(y, 10).toUnsigned(8)] + x;
      b = engineState[cshiftr32(y, 10).toUnsigned(8)] + x;
    }
  }

  void mix(List<int> x) {
    x[0] ^= shiftl32(x[1], 11);
    x[3] = sum32(x[3], x[0]);
    x[1] = sum32(x[1], x[2]);
    x[1] ^= cshiftr32(x[2], 2);
    x[4] = sum32(x[4], x[1]);
    x[2] = sum32(x[2], x[3]);
    x[2] ^= shiftl32(x[3], 8);
    x[5] = sum32(x[5], x[2]);
    x[3] = sum32(x[3], x[4]);
    x[3] ^= cshiftr32(x[4], 16);
    x[6] = sum32(x[6], x[3]);
    x[4] = sum32(x[4], x[5]);
    x[4] ^= shiftl32(x[5], 10);
    x[7] = sum32(x[7], x[4]);
    x[5] = sum32(x[5], x[6]);
    x[5] ^= cshiftr32(x[6], 4);
    x[0] = sum32(x[0], x[5]);
    x[6] = sum32(x[6], x[7]);
    x[6] ^= shiftl32(x[7], 8);
    x[1] = sum32(x[1], x[6]);
    x[7] = sum32(x[7], x[0]);
    x[7] ^= cshiftr32(x[0], 9);
    x[2] = sum32(x[2], x[7]);
    x[0] = sum32(x[0], x[1]);
  }
}

Uint8List _intToBigEndian(List<int> ns) {
  Uint8List bs = Uint8List(4 * ns.length);
  var off = 0;
  for (int i = 0; i < ns.length; ++i) {
    intEndianUtil(ns[i], bs, off);
    off = off + 4;
  }
  return bs;
}

void intEndianUtil(int n, Uint8List bs, int off) {
  bs[off] = cshiftr32(n, 24).toUnsigned(8);
  bs[++off] = cshiftr32(n, 16).toUnsigned(8);
  bs[++off] = cshiftr32(n, 8).toUnsigned(8);
  bs[++off] = n.toSigned(8);
}

int littleEndianToInt(Uint8List bs, int off) {
  int n = bs[off].toUnsigned(8);
  n |= shiftl32((bs[++off].toUnsigned(8)), 8);
  n |= shiftl32((bs[++off].toUnsigned(8)), 16);
  n |= shiftl32(bs[++off], 24);
  return n;
}

int toByte(int param) {
  return param.toSigned(8);
}
