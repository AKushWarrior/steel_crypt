// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

// ignore_for_file: omit_local_variable_types, prefer_single_quotes, non_constant_identifier_names, directives_ordering

library pointycastle.impl.block_cipher.tea;

import 'dart:typed_data';

import '../api.dart';
import '../src/impl/base_block_cipher.dart';
import '../src/registry/registry.dart';
import '../src/ufixnum.dart';

class TeaEngine extends BaseBlockCipher {
  static final FactoryConfig FACTORY_CONFIG =
      StaticFactoryConfig(BlockCipher, 'Tea', () => TeaEngine());

  static final int rounds = 32,
      block_size = 8,
      delta = 0x9E3779B,
      d_sum = 0xC6EF3720;

  int _a, _b, _c, _d;
  bool _initialised;
  bool _forEncryption;

  TeaEngine() {
    _initialised = false;
  }

  @override
  String get algorithmName => 'Tea';

  @override
  int get blockSize => block_size;

  @override
  void init(bool forEncryption, covariant KeyParameter params) {
    _forEncryption = forEncryption;
    _initialised = true;
    setKey(params.key);
  }

  @override
  int processBlock(Uint8List inp, int inpOff, Uint8List out, int outOff) {
    if (!_initialised) {
      throw StateError('TEA not initialized!');
    }
    if ((inpOff + block_size) > inp.length) {
      throw ArgumentError('Input buffer too short!');
    }
    if ((outOff + block_size) > out.length) {
      throw ArgumentError('Output buffer too short!');
    }
    return (_forEncryption)
        ? encryptBlock(inp, inpOff, out, outOff)
        : decryptBlock(inp, inpOff, out, outOff);
  }

  void setKey(Uint8List key) {
    if (key.length != 16) {
      throw ArgumentError("Key size must be 128 bits.");
    }

    _a = bytesToInt(key, 0);
    _b = bytesToInt(key, 4);
    _c = bytesToInt(key, 8);
    _d = bytesToInt(key, 12);
  }

  int encryptBlock(Uint8List inp, int inOff, Uint8List out, int outOff) {
    // Pack bytes into integers
    int v0 = bytesToInt(inp, inOff);
    int v1 = bytesToInt(inp, inOff + 4);

    int sum = 0;

    for (int i = 0; i != rounds; i++) {
      sum += delta;
      v0 += ((v1 << 4) + _a) ^ (v1 + sum) ^ (shiftr32(v1, 5) + _b);
      v1 += ((v0 << 4) + _c) ^ (v0 + sum) ^ (shiftr32(v0, 5) + _d);
    }

    unpackInt(v0, out, outOff);
    unpackInt(v1, out, outOff + 4);

    return block_size;
  }

  int decryptBlock(Uint8List inp, int inOff, Uint8List out, int outOff) {
    // Pack bytes into integers
    int v0 = bytesToInt(inp, inOff);
    int v1 = bytesToInt(inp, inOff + 4);

    int sum = d_sum;

    for (int i = 0; i != rounds; i++) {
      v1 -= ((v0 << 4) + _c) ^ (v0 + sum) ^ (shiftr32(v0, 5) + _d);
      v0 -= ((v1 << 4) + _a) ^ (v1 + sum) ^ (shiftr32(v1, 5) + _b);
      sum -= delta;
    }

    unpackInt(v0, out, outOff);
    unpackInt(v1, out, outOff + 4);

    return block_size;
  }

  int bytesToInt(Uint8List inp, int inOff) {
    return ((inp[inOff++]) << 24) |
        ((inp[inOff++] & 255) << 16) |
        ((inp[inOff++] & 255) << 8) |
        ((inp[inOff] & 255));
  }

  void unpackInt(int v, Uint8List out, int outOff) {
    out[outOff++] = shiftr32(v, 24);
    out[outOff++] = shiftr32(v, 16);
    out[outOff++] = shiftr32(v, 8);
    out[outOff] = v;
  }

  @override
  void reset() {}
}
