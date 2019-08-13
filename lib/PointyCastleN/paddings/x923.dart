// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.impl.padding.x923;

import "dart:typed_data" show Uint8List;
import 'dart:math' show Random;

import 'package:steel_crypt/PointyCastleN/export.dart';

import '../api.dart';
import '../src/impl/base_padding.dart';
import '../src/registry/registry.dart';

///A padder that adds X9.23 padding to a block - if a SecureRandom is
///passed in random padding is assumed, otherwise padding with zeros is used.

class x923Padding extends BasePadding {
  static final FactoryConfig FACTORY_CONFIG =
  StaticFactoryConfig(Padding, "X9.23", () => x923Padding());

  String get algorithmName => "X9.23";

  SecureRandom random;

  @override
  void init([CipherParameters params]) {

  }

  /// add the pad bytes to the passed in block, returning the
  /// number of bytes added.
  @override
  int addPadding(Uint8List data, int offset) {
    if (random == null) {
      var secureRandom = FortunaRandom();
      var Rand = Random.secure();
      var seeds = List<int>.generate(32, (i) => Rand.nextInt(256));
      secureRandom.seed(KeyParameter(Uint8List.fromList(seeds)));
      random = secureRandom;
    }
    int code = data.length - offset;
    while (offset < data.length - 1) {
      data[offset] = random.nextUint8();
      offset++;
    }
    data[offset] = code;
    return code;
  }

  /// return the number of pad bytes present in the block.
  @override
  int padCount(Uint8List data) {
    int count = data[data.length-1] & 0xff;
    if (count > data.length)
    {
      throw UnsupportedError("pad block corrupted");
    }
    return count;
  }
}
