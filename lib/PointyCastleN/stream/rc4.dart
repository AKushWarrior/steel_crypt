// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.impl.stream_cipher.rc4;

import '../api.dart';
import '../src/impl/base_stream_cipher.dart';
import '../src/registry/registry.dart';

class RC4Engine extends BaseStreamCipher {
  static final FactoryConfig FACTORY_CONFIG =
      StaticFactoryConfig(StreamCipher, "RC4", () => RC4Engine());

  static int STATE_LENGTH = 256;
  List<int> engineState;
  int x = 0;
  int y = 0;
  List<int> workingKey;

  String get algorithmName => "RC4";

  void init(bool forEncryption, covariant KeyParameter params) {
    workingKey = params.key;
    setKey(workingKey);
  }

  int returnByte(int inp) {
    x = (x + 1) & 0xff;
    y = (engineState[x] + y) & 0xff;

    // swap
    int tmp = engineState[x];
    engineState[x] = engineState[y];
    engineState[y] = tmp;

    // xor
    return (inp ^ engineState[(engineState[x] + engineState[y]) & 0xff]);
  }

  int processBytes(
      List<int> inp, int inOff, int len, List<int> out, int outOff) {
    if ((inOff + len) > inp.length) {
      throw ArgumentError("input buffer too short");
    }

    if ((outOff + len) > out.length) {
      throw ArgumentError("output buffer too short");
    }

    for (int i = 0; i < len; i++) {
      x = (x + 1) & 0xff;
      y = (engineState[x] + y) & 0xff;

      // swap
      int tmp = engineState[x];
      engineState[x] = engineState[y];
      engineState[y] = tmp;

      // xor
      out[i + outOff] = (inp[i + inOff] ^
          engineState[(engineState[x] + engineState[y]) & 0xff]);
    }
    return len;
  }

  void reset() {
    setKey(workingKey);
  }

  void setKey(List<int> keyBytes) {
    workingKey = keyBytes;

    // System.out.println("the key length is ; "+ workingKey.length);

    x = 0;
    y = 0;

    if (engineState == null) {
      engineState = List<int>(STATE_LENGTH);
    }

    // reset the state of the engine
    for (int i = 0; i < STATE_LENGTH; i++) {
      engineState[i] = i;
    }

    int i1 = 0;
    int i2 = 0;

    for (int i = 0; i < STATE_LENGTH; i++) {
      i2 = ((keyBytes[i1] & 0xff) + engineState[i] + i2) & 0xff;
      // do the byte-swap inline
      int tmp = engineState[i];
      engineState[i] = engineState[i2];
      engineState[i2] = tmp;
      i1 = (i1 + 1) % keyBytes.length;
    }
  }
}
