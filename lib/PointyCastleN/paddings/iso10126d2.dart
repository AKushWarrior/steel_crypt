// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.impl.padding.iso10126d2;

import 'dart:math' show Random;
import "dart:typed_data" show Uint8List;

import 'package:steel_crypt/PointyCastleN/export.dart';

import '../api.dart';
import '../src/impl/base_padding.dart';
import '../src/registry/registry.dart';

/// A padder that adds the padding according to the scheme referenced in
/// ISO 7814-4 - scheme 2 from ISO 9797-1. The first byte is 0x80, rest is 0x00
class ISO10126d2Padding extends BasePadding {
  static final FactoryConfig FACTORY_CONFIG =
  StaticFactoryConfig(Padding, "ISO10126-2", () => ISO10126d2Padding());

  String get algorithmName => "ISO10126-2";

  SecureRandom random;

  @override
  void init([CipherParameters params]) {
    // nothing to do.
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
    int code = (data.length - offset);

    while (offset < (data.length - 1)) {
      data[offset] = random.nextUint32();
      ;
      offset++;
    }

    data[offset] = code;

    return code;
  }

  /// return the number of pad bytes present in the block.
  @override
  int padCount(Uint8List data) {
    int count = data[data.length - 1] & 0xff;

    if (count > data.length) {
      throw ArgumentError("pad block corrupted");
    }

    return count;
  }
}
