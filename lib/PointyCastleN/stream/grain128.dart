// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.impl.stream_cipher.grain128;

import "dart:typed_data";

import '../api.dart';
import '../src/impl/base_stream_cipher.dart';
import '../src/registry/registry.dart';

class Grain128Engine extends BaseStreamCipher {
  static final FactoryConfig FACTORY_CONFIG =
      StaticFactoryConfig(StreamCipher, "Grain-128", () => Grain128Engine());

  String algorithmName = 'Grain-128';

  static final int STATE_SIZE = 4;
  static Uint8List workingKey;
  static Uint8List workingIV = Uint8List(16);
  static Uint8List out;
  static Uint8List lfsr;
  static Uint8List nfsr;
  static int output;
  static int index = 4;

  static bool initialised = false;

  init(bool forEncryption, covariant ParametersWithIV<KeyParameter> params) {
    var keyparam = params.parameters;
    Uint8List iv = params.iv;
    if (iv == null || iv.length != 12) {
      throw ArgumentError("Grain-128  requires exactly 12 bytes of IV");
    }
    for (var i = 0; i< 12; i++) {
      workingIV[i] = iv[i];
    }
    workingKey = keyparam.key.sublist(0, keyparam.key.length);
    lfsr = Uint8List(STATE_SIZE);
    nfsr = Uint8List(STATE_SIZE);
    out = Uint8List(4);

    reset();
  }

  static void initGrain() {
    for (int i = 0; i < 8; i++) {
      output = getOutput();
      nfsr = shift(nfsr, getOutputNFSR() ^ lfsr[0] ^ output);
      lfsr = shift(lfsr, getOutputLFSR() ^ output);
    }
    initialised = true;
  }

  static int getOutputNFSR() {
    int b0 = nfsr[0];
    int b3 = nfsr[0] >> 3 | nfsr[1] << 29;
    int b11 = nfsr[0] >> 11 | nfsr[1] << 21;
    int b13 = nfsr[0] >> 13 | nfsr[1] << 19;
    int b17 = nfsr[0] >> 17 | nfsr[1] << 15;
    int b18 = nfsr[0] >> 18 | nfsr[1] << 14;
    int b26 = nfsr[0] >> 26 | nfsr[1] << 6;
    int b27 = nfsr[0] >> 27 | nfsr[1] << 5;
    int b40 = nfsr[1] >> 8 | nfsr[2] << 24;
    int b48 = nfsr[1] >> 16 | nfsr[2] << 16;
    int b56 = nfsr[1] >> 24 | nfsr[2] << 8;
    int b59 = nfsr[1] >> 27 | nfsr[2] << 5;
    int b61 = nfsr[1] >> 29 | nfsr[2] << 3;
    int b65 = nfsr[2] >> 1 | nfsr[3] << 31;
    int b67 = nfsr[2] >> 3 | nfsr[3] << 29;
    int b68 = nfsr[2] >> 4 | nfsr[3] << 28;
    int b84 = nfsr[2] >> 20 | nfsr[3] << 12;
    int b91 = nfsr[2] >> 27 | nfsr[3] << 5;
    int b96 = nfsr[3];

    return b0 ^
        b26 ^
        b56 ^
        b91 ^
        b96 ^
        b3 & b67 ^
        b11 & b13 ^
        b17 & b18 ^
        b27 & b59 ^
        b40 & b48 ^
        b61 & b65 ^
        b68 & b84;
  }

  static int getOutputLFSR() {
    int s0 = lfsr[0];
    int s7 = lfsr[0] >> 7 | lfsr[1] << 25;
    int s38 = lfsr[1] >> 6 | lfsr[2] << 26;
    int s70 = lfsr[2] >> 6 | lfsr[3] << 26;
    int s81 = lfsr[2] >> 17 | lfsr[3] << 15;
    int s96 = lfsr[3];

    return s0 ^ s7 ^ s38 ^ s70 ^ s81 ^ s96;
  }

  static int getOutput() {
    int b2 = nfsr[0] >> 2 | nfsr[1] << 30;
    int b12 = nfsr[0] >> 12 | nfsr[1] << 20;
    int b15 = nfsr[0] >> 15 | nfsr[1] << 17;
    int b36 = nfsr[1] >> 4 | nfsr[2] << 28;
    int b45 = nfsr[1] >> 13 | nfsr[2] << 19;
    int b64 = nfsr[2];
    int b73 = nfsr[2] >> 9 | nfsr[3] << 23;
    int b89 = nfsr[2] >> 25 | nfsr[3] << 7;
    int b95 = nfsr[2] >> 31 | nfsr[3] << 1;
    int s8 = lfsr[0] >> 8 | lfsr[1] << 24;
    int s13 = lfsr[0] >> 13 | lfsr[1] << 19;
    int s20 = lfsr[0] >> 20 | lfsr[1] << 12;
    int s42 = lfsr[1] >> 10 | lfsr[2] << 22;
    int s60 = lfsr[1] >> 28 | lfsr[2] << 4;
    int s79 = lfsr[2] >> 15 | lfsr[3] << 17;
    int s93 = lfsr[2] >> 29 | lfsr[3] << 3;
    int s95 = lfsr[2] >> 31 | lfsr[3] << 1;

    return b12 & s8 ^
        s13 & s20 ^
        b95 & s42 ^
        s60 & s79 ^
        b12 & b95 & s95 ^
        s93 ^
        b2 ^
        b15 ^
        b36 ^
        b45 ^
        b64 ^
        b73 ^
        b89;
  }

  static void setKey(Uint8List keyBytes, Uint8List ivBytes) {
    for (var i =0; i<12;i++) {
      workingIV[i] = ivBytes[i];
    }
    workingIV[12] = 0xFF;
    workingIV[13] = 0xFF;
    workingIV[14] = 0xFF;
    workingIV[15] = 0xFF;
    workingKey = keyBytes;


    /**
   * Load NFSR and LFSR
   */
    int j = 0;
    for (int i = 0; i < nfsr.length; i++) {
      nfsr[i] = ((workingKey[j + 3]) << 24) |
          ((workingKey[j + 2]) << 16) & 0x00FF0000 |
          ((workingKey[j + 1]) << 8) & 0x0000FF00 |
          ((workingKey[j]) & 0x000000FF);

      lfsr[i] = ((workingIV[j + 3]) << 24) |
          ((workingIV[j + 2]) << 16) & 0x00FF0000 |
          ((workingIV[j + 1]) << 8) & 0x0000FF00 |
          ((workingIV[j]) & 0x000000FF);
      j += 4;
    }
  }

  void processBytes(
      Uint8List inp, int inOff, int len, Uint8List out, int outOff) {
    if (!initialised) {
      throw StateError('Grain-128' + " not initialised");
    }

    if ((inOff + len) > inp.length) {
      throw ArgumentError("input buffer too short");
    }

    if ((outOff + len) > out.length) {
      throw ArgumentError("output buffer too short");
    }

    for (int i = 0; i < len; i++) {
      out[outOff + i] = (inp[inOff + i] ^ getKeyStream());
    }
  }

  void reset() {
    index = 4;
    setKey(workingKey, workingIV);
    initGrain();
  }

  static void oneRound() {
    output = getOutput();
    out[0] = output;
    out[1] = (output >> 8);
    out[2] = (output >> 16);
    out[3] = (output >> 24);

    nfsr = shift(nfsr, getOutputNFSR() ^ lfsr[0]);
    lfsr = shift(lfsr, getOutputLFSR());
  }

  int returnByte(int inp) {
    if (!initialised) {
      throw StateError('Grain-128' + " not initialised");
    }
    return (inp ^ getKeyStream());
  }

  static int getKeyStream()
  {
    if (index > 3)
    {
      oneRound();
      index = 0;
    }
    return out[index++];
  }

  static Uint8List shift(Uint8List array, int val) {
    array[0] = array[1];
    array[1] = array[2];
    array[2] = array[3];
    array[3] = val;
    return array;
  }
}
