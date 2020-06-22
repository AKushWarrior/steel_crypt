// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

// ignore_for_file: omit_local_variable_types, prefer_single_quotes, non_constant_identifier_names, directives_ordering, prefer_typing_uninitialized_variables

library pointycastle.impl.key_derivator.scrypt;

import "dart:typed_data";

import '../api.dart';
import '../macs/hmac.dart';
import '../src/impl/base_key_derivator.dart';
import '../src/registry/registry.dart';
import '../src/ufixnum.dart';
import 'api.dart';
import 'pbkdf2.dart';

class Scrypt extends BaseKeyDerivator {
  // ignore: non_constant_identifier_names
  static final FactoryConfig FACTORY_CONFIG =
      StaticFactoryConfig(KeyDerivator, 'scrypt', () => Scrypt());

  // ignore: non_constant_identifier_names
  static final int _MAX_VALUE = 0x7fffffff;

  ScryptParameters _params;

  @override
  final String algorithmName = 'scrypt';

  @override
  int get keySize => _params.desiredKeyLength;

  void reset() {
    _params = null;
  }

  @override
  void init(covariant ScryptParameters params) {
    _params = params;
  }

  @override
  int deriveKey(Uint8List inp, int inpOff, Uint8List out, int outOff) {
    var key = _scryptJ(Uint8List.fromList(inp.sublist(inpOff)), _params.salt,
        _params.N, _params.r, _params.p, _params.desiredKeyLength);

    out.setRange(0, keySize, key);

    return keySize;
  }

  Uint8List _scryptJ(
      Uint8List passwd, Uint8List salt, int N, int r, int p, int dkLen) {
    if (N < 2 || (N & (N - 1)) != 0) {
      throw ArgumentError('N must be a power of 2 greater than 1');
    }

    if (N > _MAX_VALUE / 128 / r) {
      throw ArgumentError('Parameter N is too large');
    }

    if (r > _MAX_VALUE / 128 / p) {
      throw ArgumentError('Parameter r is too large');
    }

    // ignore: non_constant_identifier_names
    final DK = Uint8List(dkLen);

    final B = Uint8List(128 * r * p);
    // ignore: non_constant_identifier_names
    final XY = Uint8List(256 * r);
    final V = Uint8List(128 * r * N);

    final pbkdf2 = PBKDF2KeyDerivator(HMac(Digest('RIPEMD-160'), 64));

    pbkdf2.init(Pbkdf2Parameters(salt, 1, p * 128 * r));
    pbkdf2.deriveKey(passwd, 0, B, 0);

    for (var i = 0; i < p; i++) {
      _smix(B, i * 128 * r, r, N, V, XY);
    }

    pbkdf2.init(Pbkdf2Parameters(B, 1, dkLen));
    pbkdf2.deriveKey(passwd, 0, DK, 0);

    return DK;
  }

  void _smix(Uint8List B, int Bi, int r, int N, Uint8List V, Uint8List XY) {
    // ignore: non_constant_identifier_names
    var Xi = 0;
    // ignore: non_constant_identifier_names
    var Yi = 128 * r;

    _arraycopy(B, Bi, XY, Xi, 128 * r);

    for (var i = 0; i < N; i++) {
      _arraycopy(XY, Xi, V, i * (128 * r), 128 * r);
      _blockmix_salsa8(XY, Xi, Yi, r);
    }

    for (var i = 0; i < N; i++) {
      var j = _integerify(XY, Xi, r) & (N - 1);
      _blockxor(V, j * (128 * r), XY, Xi, 128 * r);
      _blockmix_salsa8(XY, Xi, Yi, r);
    }

    _arraycopy(XY, Xi, B, Bi, 128 * r);
  }

  // ignore: non_constant_identifier_names
  void _blockmix_salsa8(Uint8List BY, int Bi, int Yi, int r) {
    final X = Uint8List(64);

    _arraycopy(BY, Bi + (2 * r - 1) * 64, X, 0, 64);

    for (var i = 0; i < 2 * r; i++) {
      _blockxor(BY, i * 64, X, 0, 64);
      _salsa20_8(X);
      _arraycopy(X, 0, BY, Yi + (i * 64), 64);
    }

    for (var i = 0; i < r; i++) {
      _arraycopy(BY, Yi + (i * 2) * 64, BY, Bi + (i * 64), 64);
    }

    for (var i = 0; i < r; i++) {
      _arraycopy(BY, Yi + (i * 2 + 1) * 64, BY, Bi + (i + r) * 64, 64);
    }
  }

  void _salsa20_8(Uint8List B) {
    // ignore: non_constant_identifier_names
    final B32 = Uint32List(16);
    final x = Uint32List(16);

    for (var i = 0; i < 16; i++) {
      B32[i] = unpack32(B, i * 4, Endian.little);
    }

    _arraycopy(B32, 0, x, 0, 16);

    for (var i = 8; i > 0; i -= 2) {
      x[4] ^= crotl32(x[0] + x[12], 7);
      x[8] ^= crotl32(x[4] + x[0], 9);
      x[12] ^= crotl32(x[8] + x[4], 13);
      x[0] ^= crotl32(x[12] + x[8], 18);
      x[9] ^= crotl32(x[5] + x[1], 7);
      x[13] ^= crotl32(x[9] + x[5], 9);
      x[1] ^= crotl32(x[13] + x[9], 13);
      x[5] ^= crotl32(x[1] + x[13], 18);
      x[14] ^= crotl32(x[10] + x[6], 7);
      x[2] ^= crotl32(x[14] + x[10], 9);
      x[6] ^= crotl32(x[2] + x[14], 13);
      x[10] ^= crotl32(x[6] + x[2], 18);
      x[3] ^= crotl32(x[15] + x[11], 7);
      x[7] ^= crotl32(x[3] + x[15], 9);
      x[11] ^= crotl32(x[7] + x[3], 13);
      x[15] ^= crotl32(x[11] + x[7], 18);
      x[1] ^= crotl32(x[0] + x[3], 7);
      x[2] ^= crotl32(x[1] + x[0], 9);
      x[3] ^= crotl32(x[2] + x[1], 13);
      x[0] ^= crotl32(x[3] + x[2], 18);
      x[6] ^= crotl32(x[5] + x[4], 7);
      x[7] ^= crotl32(x[6] + x[5], 9);
      x[4] ^= crotl32(x[7] + x[6], 13);
      x[5] ^= crotl32(x[4] + x[7], 18);
      x[11] ^= crotl32(x[10] + x[9], 7);
      x[8] ^= crotl32(x[11] + x[10], 9);
      x[9] ^= crotl32(x[8] + x[11], 13);
      x[10] ^= crotl32(x[9] + x[8], 18);
      x[12] ^= crotl32(x[15] + x[14], 7);
      x[13] ^= crotl32(x[12] + x[15], 9);
      x[14] ^= crotl32(x[13] + x[12], 13);
      x[15] ^= crotl32(x[14] + x[13], 18);
    }

    for (var i = 0; i < 16; i++) {
      B32[i] = x[i] + B32[i];
    }

    for (var i = 0; i < 16; i++) {
      pack32(B32[i], B, i * 4, Endian.little);
    }
  }

  // ignore: non_constant_identifier_names
  void _blockxor(Uint8List S, int Si, Uint8List D, int Di, int len) {
    for (var i = 0; i < len; i++) {
      D[Di + i] ^= S[Si + i];
    }
  }

  int _integerify(Uint8List B, int Bi, int r) {
    Bi += (2 * r - 1) * 64;
    return unpack32(B, Bi, Endian.little);
  }

  void _arraycopy(
          List<int> inp, int inpOff, List<int> out, int outOff, int len) =>
      out.setRange(outOff, outOff + len, inp.sublist(inpOff));
}
