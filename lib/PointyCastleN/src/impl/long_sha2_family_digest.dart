// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.src.impl.digests.long_sha2_family_digest;

import "dart:typed_data";

import '../ufixnum.dart';
import 'base_digest.dart';

/// Base implementation of SHA-2 family algorithms SHA-384 and SHA-512.
abstract class LongSHA2FamilyDigest extends BaseDigest {
  static const _BYTE_LENGTH = 128;

  static final _MAX_BYTE_COUNT1 = Register64(0x1fffffff, 0xffffffff);

  final H1 = Register64();
  final H2 = Register64();
  final H3 = Register64();
  final H4 = Register64();
  final H5 = Register64();
  final H6 = Register64();
  final H7 = Register64();
  final H8 = Register64();

  final _wordBuffer = Uint8List(8);
  int _wordBufferOffset = 0;

  final _W = Register64List(80);
  int _wOff = 0;

  final _byteCount1 = Register64();
  final _byteCount2 = Register64();

  LongSHA2FamilyDigest() {
    reset();
  }

  int get byteLength => _BYTE_LENGTH;

  void reset() {
    _byteCount1.set(0);
    _byteCount2.set(0);

    _wordBufferOffset = 0;
    _wordBuffer.fillRange(0, _wordBuffer.length, 0);

    _wOff = 0;
    _W.fillRange(0, _W.length, 0);
  }

  void updateByte(int inp) {
    _wordBuffer[_wordBufferOffset++] = inp;

    if (_wordBufferOffset == _wordBuffer.length) {
      _processWord(_wordBuffer, 0);
      _wordBufferOffset = 0;
    }

    _byteCount1.sum(1);
  }

  void update(Uint8List inp, int inpOff, int len) {
    // fill the current word
    while ((_wordBufferOffset != 0) && (len > 0)) {
      updateByte(inp[inpOff]);

      inpOff++;
      len--;
    }

    // process whole words.
    while (len > _wordBuffer.length) {
      _processWord(inp, inpOff);

      inpOff += _wordBuffer.length;
      len -= _wordBuffer.length;
      _byteCount1.sum(_wordBuffer.length);
    }

    // load in the remainder.
    while (len > 0) {
      updateByte(inp[inpOff]);

      inpOff++;
      len--;
    }
  }

  void finish() {
    _adjustByteCounts();

    var lowBitLength = Register64(_byteCount1)..shiftl(3);
    var hiBitLength = _byteCount2;

    // add the pad bytes.
    updateByte(128);

    while (_wordBufferOffset != 0) {
      updateByte(0);
    }

    _processLength(lowBitLength, hiBitLength);

    _processBlock();
  }

  void _processWord(Uint8List inp, int inpOff) {
    _W[_wOff++].unpack(inp, inpOff, Endian.big);

    if (_wOff == 16) {
      _processBlock();
    }
  }


  void _adjustByteCounts() {
    if (_byteCount1 > _MAX_BYTE_COUNT1) {
      _byteCount2.sum(Register64(_byteCount1)..shiftr(61));
      _byteCount1.and(_MAX_BYTE_COUNT1);
    }
  }

  void _processLength(Register64 lowW, Register64 hiW) {
    if (_wOff > 14) {
      _processBlock();
    }

    _W[14].set(hiW);
    _W[15].set(lowW);
  }

  void _processBlock() {
    _adjustByteCounts();

    // expand 16 word block into 80 word blocks.
    for (var t = 16; t < 80; t++) {
      // _W[t] = _Sigma1(_W[t - 2]) + _W[t - 7] + _Sigma0(_W[t - 15]) + _W[t - 16];
      _W[t].set(_Sigma1(_W[t - 2])
        ..sum(_W[t - 7])
        ..sum(_Sigma0(_W[t - 15]))
        ..sum(_W[t - 16]));
    }

    var a = Register64(H1);
    var b = Register64(H2);
    var c = Register64(H3);
    var d = Register64(H4);
    var e = Register64(H5);
    var f = Register64(H6);
    var g = Register64(H7);
    var h = Register64(H8);

    var t = 0;
    for (var i = 0; i < 10; i++) {
      // t = 8 * i
      h..sum(_Sum1(e))..sum(_Ch(e, f, g))..sum(_K[t])..sum(_W[t++]);
      d.sum(h);
      h..sum(_Sum0(a))..sum(_Maj(a, b, c));

      // t = 8 * i + 1
      g..sum(_Sum1(d))..sum(_Ch(d, e, f))..sum(_K[t])..sum(_W[t++]);
      c.sum(g);
      g..sum(_Sum0(h))..sum(_Maj(h, a, b));

      // t = 8 * i + 2
      f..sum(_Sum1(c))..sum(_Ch(c, d, e))..sum(_K[t])..sum(_W[t++]);
      b.sum(f);
      f..sum(_Sum0(g))..sum(_Maj(g, h, a));

      // t = 8 * i + 3
      e..sum(_Sum1(b))..sum(_Ch(b, c, d))..sum(_K[t])..sum(_W[t++]);
      a.sum(e);
      e..sum(_Sum0(f))..sum(_Maj(f, g, h));

      // t = 8 * i + 4
      d..sum(_Sum1(a))..sum(_Ch(a, b, c))..sum(_K[t])..sum(_W[t++]);
      h.sum(d);
      d..sum(_Sum0(e))..sum(_Maj(e, f, g));

      // t = 8 * i + 5
      c..sum(_Sum1(h))..sum(_Ch(h, a, b))..sum(_K[t])..sum(_W[t++]);
      g.sum(c);
      c..sum(_Sum0(d))..sum(_Maj(d, e, f));

      // t = 8 * i + 6
      b..sum(_Sum1(g))..sum(_Ch(g, h, a))..sum(_K[t])..sum(_W[t++]);
      f.sum(b);
      b..sum(_Sum0(c))..sum(_Maj(c, d, e));

      // t = 8 * i + 7
      a..sum(_Sum1(f))..sum(_Ch(f, g, h))..sum(_K[t])..sum(_W[t++]);
      e.sum(a);
      a..sum(_Sum0(b))..sum(_Maj(b, c, d));
    }

    H1.sum(a);
    H2.sum(b);
    H3.sum(c);
    H4.sum(d);
    H5.sum(e);
    H6.sum(f);
    H7.sum(g);
    H8.sum(h);

    // reset the offset and clean out the word buffer.
    _wOff = 0;
    _W.fillRange(0, 16, 0);
  }

  Register64 _Ch(Register64 x, Register64 y, Register64 z) {
    // r += ((x & y) ^ ((~x) & z));
    Register64 r0 = Register64(x);
    r0.and(y);

    Register64 r1 = Register64(x);
    r1.not();
    r1.and(z);

    r0.xor(r1);
    return r0;
  }

  Register64 _Maj(Register64 x, Register64 y, Register64 z) {
    // r += ((x & y) ^ (x & z) ^ (y & z));
    Register64 r0 = Register64(x);
    r0.and(y);

    Register64 r1 = Register64(x);
    r1.and(z);

    Register64 r2 = Register64(y);
    r2.and(z);

    r0.xor(r1);
    r0.xor(r2);

    return r0;
  }

  Register64 _Sum0(Register64 x) {
    // r += ((x << 36)|(x >> 28)) ^ ((x << 30)|(x >> 34)) ^ ((x << 25)|(x >> 39));
    Register64 r0 = Register64(x);
    r0.rotl(36);

    Register64 r1 = Register64(x);
    r1.rotl(30);

    Register64 r2 = Register64(x);
    r2.rotl(25);

    r0.xor(r1);
    r0.xor(r2);

    return r0;
  }

  Register64 _Sum1(Register64 x) {
    // r += ((x << 50)|(x >> 14)) ^ ((x << 46)|(x >> 18)) ^ ((x << 23)|(x >> 41));
    Register64 r0 = Register64(x);
    r0.rotl(50);

    Register64 r1 = Register64(x);
    r1.rotl(46);

    Register64 r2 = Register64(x);
    r2.rotl(23);

    r0.xor(r1);
    r0.xor(r2);

    return r0;
  }

  Register64 _Sigma0(Register64 x) {
    // r = (((x << 63)|(x >> 1)) ^ ((x << 56)|(x >> 8)) ^ (x >> 7));
    Register64 r0 = Register64(x);
    r0.rotl(63);

    Register64 r1 = Register64(x);
    r1.rotl(56);

    Register64 r2 = Register64(x);
    r2.shiftr(7);

    r0.xor(r1);
    r0.xor(r2);

    return r0;
  }

  Register64 _Sigma1(Register64 x) {
    // r = (((x << 45)|(x >> 19)) ^ ((x << 3)|(x >> 61)) ^ (x >> 6));
    Register64 r0 = Register64(x);
    r0.rotl(45);

    Register64 r1 = Register64(x);
    r1.rotl(3);

    Register64 r2 = Register64(x);
    r2.shiftr(6);

    r0.xor(r1);
    r0.xor(r2);

    return r0;
  }

  static final _K = <Register64>[
    Register64(0x428a2f98, 0xd728ae22),
    Register64(0x71374491, 0x23ef65cd),
    Register64(0xb5c0fbcf, 0xec4d3b2f),
    Register64(0xe9b5dba5, 0x8189dbbc),
    Register64(0x3956c25b, 0xf348b538),
    Register64(0x59f111f1, 0xb605d019),
    Register64(0x923f82a4, 0xaf194f9b),
    Register64(0xab1c5ed5, 0xda6d8118),
    Register64(0xd807aa98, 0xa3030242),
    Register64(0x12835b01, 0x45706fbe),
    Register64(0x243185be, 0x4ee4b28c),
    Register64(0x550c7dc3, 0xd5ffb4e2),
    Register64(0x72be5d74, 0xf27b896f),
    Register64(0x80deb1fe, 0x3b1696b1),
    Register64(0x9bdc06a7, 0x25c71235),
    Register64(0xc19bf174, 0xcf692694),
    Register64(0xe49b69c1, 0x9ef14ad2),
    Register64(0xefbe4786, 0x384f25e3),
    Register64(0x0fc19dc6, 0x8b8cd5b5),
    Register64(0x240ca1cc, 0x77ac9c65),
    Register64(0x2de92c6f, 0x592b0275),
    Register64(0x4a7484aa, 0x6ea6e483),
    Register64(0x5cb0a9dc, 0xbd41fbd4),
    Register64(0x76f988da, 0x831153b5),
    Register64(0x983e5152, 0xee66dfab),
    Register64(0xa831c66d, 0x2db43210),
    Register64(0xb00327c8, 0x98fb213f),
    Register64(0xbf597fc7, 0xbeef0ee4),
    Register64(0xc6e00bf3, 0x3da88fc2),
    Register64(0xd5a79147, 0x930aa725),
    Register64(0x06ca6351, 0xe003826f),
    Register64(0x14292967, 0x0a0e6e70),
    Register64(0x27b70a85, 0x46d22ffc),
    Register64(0x2e1b2138, 0x5c26c926),
    Register64(0x4d2c6dfc, 0x5ac42aed),
    Register64(0x53380d13, 0x9d95b3df),
    Register64(0x650a7354, 0x8baf63de),
    Register64(0x766a0abb, 0x3c77b2a8),
    Register64(0x81c2c92e, 0x47edaee6),
    Register64(0x92722c85, 0x1482353b),
    Register64(0xa2bfe8a1, 0x4cf10364),
    Register64(0xa81a664b, 0xbc423001),
    Register64(0xc24b8b70, 0xd0f89791),
    Register64(0xc76c51a3, 0x0654be30),
    Register64(0xd192e819, 0xd6ef5218),
    Register64(0xd6990624, 0x5565a910),
    Register64(0xf40e3585, 0x5771202a),
    Register64(0x106aa070, 0x32bbd1b8),
    Register64(0x19a4c116, 0xb8d2d0c8),
    Register64(0x1e376c08, 0x5141ab53),
    Register64(0x2748774c, 0xdf8eeb99),
    Register64(0x34b0bcb5, 0xe19b48a8),
    Register64(0x391c0cb3, 0xc5c95a63),
    Register64(0x4ed8aa4a, 0xe3418acb),
    Register64(0x5b9cca4f, 0x7763e373),
    Register64(0x682e6ff3, 0xd6b2b8a3),
    Register64(0x748f82ee, 0x5defb2fc),
    Register64(0x78a5636f, 0x43172f60),
    Register64(0x84c87814, 0xa1f0ab72),
    Register64(0x8cc70208, 0x1a6439ec),
    Register64(0x90befffa, 0x23631e28),
    Register64(0xa4506ceb, 0xde82bde9),
    Register64(0xbef9a3f7, 0xb2c67915),
    Register64(0xc67178f2, 0xe372532b),
    Register64(0xca273ece, 0xea26619c),
    Register64(0xd186b8c7, 0x21c0c207),
    Register64(0xeada7dd6, 0xcde0eb1e),
    Register64(0xf57d4f7f, 0xee6ed178),
    Register64(0x06f067aa, 0x72176fba),
    Register64(0x0a637dc5, 0xa2c898a6),
    Register64(0x113f9804, 0xbef90dae),
    Register64(0x1b710b35, 0x131c471b),
    Register64(0x28db77f5, 0x23047d84),
    Register64(0x32caab7b, 0x40c72493),
    Register64(0x3c9ebe0a, 0x15c9bebc),
    Register64(0x431d67c4, 0x9c100d4c),
    Register64(0x4cc5d4be, 0xcb3e42b6),
    Register64(0x597f299c, 0xfc657e2a),
    Register64(0x5fcb6fab, 0x3ad6faec),
    Register64(0x6c44198c, 0x4a475817)
  ];
}
