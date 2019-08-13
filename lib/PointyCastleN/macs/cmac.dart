// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.impl.mac.cmac;

import "dart:typed_data";

import '../api.dart';
import '../src/registry/registry.dart';
import '../src/impl/base_mac.dart';
import '../paddings/iso7816d4.dart';
import '../block/modes/cbc.dart';

///
/// CMAC - as specified at www.nuee.nagoya-u.ac.jp/labs/tiwata/omac/omac.html
///<p>
/// * CMAC is analogous to OMAC1 - see also en.wikipedia.org/wiki/CMAC
/// * </p><p>
/// * CMAC is a NIST recomendation - see
/// * csrc.nist.gov/CryptoToolkit/modes/800-38_Series_Publications/SP800-38B.pdf
/// * </p><p>
////// * CMAC/OMAC1 is a blockcipher-based message authentication code designed and
/// * analyzed by Tetsu Iwata and Kaoru Kurosawa.
/// * </p><p>
/// * CMAC/OMAC1 is a simple variant of the CBC MAC (Cipher Block Chaining Message
/// * Authentication Code). OMAC stands for One-Key CBC MAC.
/// * </p><p>
/// * It supports 128- or 64-bits block ciphers, with any key size, and returns
/// * a MAC with dimension less or equal to the block size of the underlying
/// * cipher.
/// * </p>
/// */

class CMac extends BaseMac {
  static final FactoryConfig FACTORY_CONFIG = DynamicFactoryConfig.suffix(
      Mac,
      "/CMAC",
      (_, final Match match) => () {
            BlockCipher cipher = BlockCipher(match.group(1));
            return CMac.fromCipher(cipher);
          });

  Uint8List _poly;
  Uint8List _ZEROES;

  Uint8List _mac;

  Uint8List _buf;
  int _bufOff;
  final BlockCipher _cipher;

  final int _macSize;

  Uint8List _Lu, _Lu2;

  ParametersWithIV _params;

  ///
  ///* create a standard MAC based on a CBC block cipher (64 or 128 bit block).
  /// * This will produce an authentication code the length of the block size
  ///* of the cipher.
  ///*
  ///* @param cipher the cipher to be used as the basis of the MAC generation.

  CMac.fromCipher(BlockCipher cipher) : this(cipher, cipher.blockSize * 8);


  ///* create a standard MAC based on a block cipher with the size of the
  ///* MAC been given in bits.
  ///* <p>
  ///* Note: the size of the MAC must be at least 24 bits (FIPS Publication 81),
  ///* or 16 bits if being used as a data authenticator (FIPS Publication 113),
  ///* and in general should be less than the size of the block cipher as it
  ///* reduces the chance of an exhaustive attack (see Handbook of Applied
  ///* Cryptography).
  ///*
  ///* @param cipher        the cipher to be used as the basis of the MAC generation.
  ///* @param macSizeInBits the size of the MAC in bits, must be a multiple of 8 and &lt;= 128.

  CMac(BlockCipher cipher, int macSizeInBits)
      : this._macSize = macSizeInBits ~/ 8,
        this._cipher = CBCBlockCipher(cipher) {
    if ((macSizeInBits % 8) != 0) {
      throw ArgumentError("MAC size must be multiple of 8");
    }

    if (macSizeInBits > (_cipher.blockSize * 8)) {
      throw ArgumentError(
          "MAC size must be less or equal to ${_cipher.blockSize * 8}");
    }

    _poly = lookupPoly(cipher.blockSize);

    _mac = Uint8List(cipher.blockSize);

    _buf = Uint8List(cipher.blockSize);

    _ZEROES = Uint8List(cipher.blockSize);

    _bufOff = 0;
  }

  @override
  String get algorithmName {
    String blockCipherAlgorithmName = _cipher.algorithmName.split("/").first;
    return "${blockCipherAlgorithmName}/CMAC";
  }

  static int shiftLeft(Uint8List block, Uint8List output) {
    int i = block.length;
    int bit = 0;
    while (--i >= 0) {
      int b = block[i] & 0xff;
      output[i] = ((b << 1) | bit);
      bit = (b >> 7) & 1;
    }
    return bit;
  }

  Uint8List _doubleLu(Uint8List inp) {
    Uint8List ret = Uint8List(inp.length);
    int carry = shiftLeft(inp, ret);

    // NOTE: This construction is an attempt at a constant-time implementation.
    int mask = (-carry) & 0xff;
    ret[inp.length - 3] ^= _poly[1] & mask;
    ret[inp.length - 2] ^= _poly[2] & mask;
    ret[inp.length - 1] ^= _poly[3] & mask;

    return ret;
  }

  static Uint8List lookupPoly(int blockSizeLength) {
    int xor;
    switch (blockSizeLength * 8) {
      case 64:
        xor = 0x1B;
        break;
      case 128:
        xor = 0x87;
        break;
      case 160:
        xor = 0x2D;
        break;
      case 192:
        xor = 0x87;
        break;
      case 224:
        xor = 0x309;
        break;
      case 256:
        xor = 0x425;
        break;
      case 320:
        xor = 0x1B;
        break;
      case 384:
        xor = 0x100D;
        break;
      case 448:
        xor = 0x851;
        break;
      case 512:
        xor = 0x125;
        break;
      case 768:
        xor = 0xA0011;
        break;
      case 1024:
        xor = 0x80043;
        break;
      case 2048:
        xor = 0x86001;
        break;
      default:
        throw ArgumentError(
            "Unknown block size for CMAC: ${blockSizeLength * 8}");
    }

    final out = Uint8List(4);
    out[3] = (xor >> 0);
    out[2] = (xor >> 8);
    out[1] = (xor >> 16);
    out[0] = (xor >> 24);
    return out;
  }

  @override
  void init(covariant KeyParameter keyParams) {
    final zeroIV = Uint8List(keyParams.key.length).sublist(0,8);
    this._params = ParametersWithIV(keyParams, zeroIV);

    // Initialize before computing L, Lu, Lu2
    _cipher.init(true, _params);

    //initializes the L, Lu, Lu2 numbers
    Uint8List L = Uint8List(_ZEROES.length);
    _cipher.processBlock(_ZEROES, 0, L, 0);
    _Lu = _doubleLu(L);
    _Lu2 = _doubleLu(_Lu);

    // Reset _buf/_cipher state after computing L, Lu, Lu2
    reset();
  }

  @override
  get macSize => _macSize;

  @override
  void updateByte(int inp) {
    if (_bufOff == _buf.length) {
      _cipher.processBlock(_buf, 0, _mac, 0);
      _bufOff = 0;
    }

    _buf[_bufOff++] = inp;
  }

  @override
  void update(Uint8List inp, int inOff, int len) {
    if (len < 0) {
      throw ArgumentError("Can't have a negative input length!");
    }

    int blockSize = _cipher.blockSize;
    int gapLen = blockSize - _bufOff;

    if (len > gapLen) {
      _buf.setRange(_bufOff, _bufOff + gapLen, inp.sublist(inOff));

      _cipher.processBlock(_buf, 0, _mac, 0);

      _bufOff = 0;
      len -= gapLen;
      inOff += gapLen;

      while (len > blockSize) {
        _cipher.processBlock(inp, inOff, _mac, 0);

        len -= blockSize;
        inOff += blockSize;
      }
    }

    _buf.setRange(_bufOff, _bufOff + len, inp.sublist(inOff));

    _bufOff += len;
  }

  @override
  int doFinal(Uint8List out, int outOff) {
    int blockSize = _cipher.blockSize;

    Uint8List lu;
    if (_bufOff == blockSize) {
      lu = _Lu;
    } else {
      ISO7816d4Padding().addPadding(_buf, _bufOff);
      lu = _Lu2;
    }

    for (int i = 0; i < _mac.length; i++) {
      _buf[i] ^= lu[i];
    }

    _cipher.processBlock(_buf, 0, _mac, 0);

    out.setRange(outOff, outOff + _macSize, _mac);

    reset();

    return _macSize;
  }

  /// Reset the mac generator.
  @override
  void reset() {
    // clean the buffer.
    for (int i = 0; i < _buf.length; i++) {
      _buf[i] = 0;
    }

    _bufOff = 0;

    // reset the underlying cipher.
    _cipher.reset();

    if (_params != null) {
      _cipher.init(true, _params);
    }
  }
}
