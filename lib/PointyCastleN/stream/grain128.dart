// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

// ignore_for_file: omit_local_variable_types, prefer_single_quotes
// ignore_for_file: non_constant_identifier_names, directives_ordering
// ignore_for_file: prefer_typing_uninitialized_variables, camel_case_types
// ignore_for_file: annotate_overrides
library pointycastle.impl.stream_cipher.grain128;

import 'dart:typed_data';

import '../api.dart';
import '../src/impl/base_stream_cipher.dart';
import '../src/registry/registry.dart';

class Grain128Engine extends BaseStreamCipher {
  static final FactoryConfig FACTORY_CONFIG =
  StaticFactoryConfig(StreamCipher, 'Grain-128', () => Grain128Engine());

  @override
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

  @override
  void init(bool forEncryption,
      covariant ParametersWithIV<KeyParameter> params) {
    var keyparam = params.parameters;
    var iv = params.iv;
    if (iv == null || iv.length != 12) {
      throw ArgumentError('Grain-128 requires exactly 12 bytes of IV');
    }
    for (var i = 0; i < 12; i++) {
      workingIV[i] = iv[i];
    }
    workingKey = keyparam.key.sublist(0, keyparam.key.length);
    lfsr = Uint8List(STATE_SIZE);
    nfsr = Uint8List(STATE_SIZE);
    out = Uint8List(4);

    reset();
  }

  static void initGrain() {
    for (var i = 0; i < 8; i++) {
      output = getOutput();
      nfsr = shift(nfsr, getOutputNFSR() ^ lfsr[0] ^ output);
      lfsr = shift(lfsr, getOutputLFSR() ^ output);
    }
    initialised = true;
  }

  static int getOutputNFSR() {
    var b0 = nfsr[0];
    var b3 = nfsr[0] >> 3 | nfsr[1] << 29;
    var b11 = nfsr[0] >> 11 | nfsr[1] << 21;
    var b13 = nfsr[0] >> 13 | nfsr[1] << 19;
    var b17 = nfsr[0] >> 17 | nfsr[1] << 15;
    var b18 = nfsr[0] >> 18 | nfsr[1] << 14;
    var b26 = nfsr[0] >> 26 | nfsr[1] << 6;
    var b27 = nfsr[0] >> 27 | nfsr[1] << 5;
    var b40 = nfsr[1] >> 8 | nfsr[2] << 24;
    var b48 = nfsr[1] >> 16 | nfsr[2] << 16;
    var b56 = nfsr[1] >> 24 | nfsr[2] << 8;
    var b59 = nfsr[1] >> 27 | nfsr[2] << 5;
    var b61 = nfsr[1] >> 29 | nfsr[2] << 3;
    var b65 = nfsr[2] >> 1 | nfsr[3] << 31;
    var b67 = nfsr[2] >> 3 | nfsr[3] << 29;
    var b68 = nfsr[2] >> 4 | nfsr[3] << 28;
    var b84 = nfsr[2] >> 20 | nfsr[3] << 12;
    var b91 = nfsr[2] >> 27 | nfsr[3] << 5;
    var b96 = nfsr[3];

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
    var s0 = lfsr[0];
    var s7 = lfsr[0] >> 7 | lfsr[1] << 25;
    var s38 = lfsr[1] >> 6 | lfsr[2] << 26;
    var s70 = lfsr[2] >> 6 | lfsr[3] << 26;
    var s81 = lfsr[2] >> 17 | lfsr[3] << 15;
    var s96 = lfsr[3];

    return s0 ^ s7 ^ s38 ^ s70 ^ s81 ^ s96;
  }

  static int getOutput() {
    var b2 = nfsr[0] >> 2 | nfsr[1] << 30;
    var b12 = nfsr[0] >> 12 | nfsr[1] << 20;
    var b15 = nfsr[0] >> 15 | nfsr[1] << 17;
    var b36 = nfsr[1] >> 4 | nfsr[2] << 28;
    var b45 = nfsr[1] >> 13 | nfsr[2] << 19;
    var b64 = nfsr[2];
    var b73 = nfsr[2] >> 9 | nfsr[3] << 23;
    var b89 = nfsr[2] >> 25 | nfsr[3] << 7;
    var b95 = nfsr[2] >> 31 | nfsr[3] << 1;
    var s8 = lfsr[0] >> 8 | lfsr[1] << 24;
    var s13 = lfsr[0] >> 13 | lfsr[1] << 19;
    var s20 = lfsr[0] >> 20 | lfsr[1] << 12;
    var s42 = lfsr[1] >> 10 | lfsr[2] << 22;
    var s60 = lfsr[1] >> 28 | lfsr[2] << 4;
    var s79 = lfsr[2] >> 15 | lfsr[3] << 17;
    var s93 = lfsr[2] >> 29 | lfsr[3] << 3;
    var s95 = lfsr[2] >> 31 | lfsr[3] << 1;

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
    for (var i = 0; i < 12; i++) {
      workingIV[i] = ivBytes[i];
    }
    workingIV[12] = 0xFF;
    workingIV[13] = 0xFF;
    workingIV[14] = 0xFF;
    workingIV[15] = 0xFF;
    workingKey = keyBytes;

    /// Load NFSR and LFSR
    var j = 0;
    for (var i = 0; i < nfsr.length; i++) {
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

  @override
  void processBytes(Uint8List inp, int inOff, int len, Uint8List out,
      int outOff) {
    if (!initialised) {
      throw StateError('Grain-128 not initialised');
    }

    if ((inOff + len) > inp.length) {
      throw ArgumentError('input buffer too short');
    }

    if ((outOff + len) > out.length) {
      throw ArgumentError('output buffer too short');
    }

    for (var i = 0; i < len; i++) {
      out[outOff + i] = (inp[inOff + i] ^ getKeyStream());
    }
  }

  @override
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

  @override
  int returnByte(int inp) {
    if (!initialised) {
      throw StateError('Grain-128 not initialised');
    }
    return (inp ^ getKeyStream());
  }

  static int getKeyStream() {
    if (index > 3) {
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
