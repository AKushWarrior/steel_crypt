// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.impl.padding.tbc;

import "dart:typed_data" show Uint8List;

import '../api.dart';
import '../src/impl/base_padding.dart';
import '../src/registry/registry.dart';

///A padder that adds Trailing-Bit-Compliment padding to a block.
///This padding pads the block out with the compliment of the last bit of the plain text.

class TBCPadding extends BasePadding {
  static final FactoryConfig FACTORY_CONFIG =
  StaticFactoryConfig(Padding, "TBC", () => TBCPadding());

  String get algorithmName => "TBC";

  @override
  void init([CipherParameters params]) {
    // nothing to do.
  }

  /// add the pad bytes to the passed in block, returning the
  /// number of bytes added.
  @override
  int addPadding(Uint8List data, int offset) {
    int count = data.length-offset;
    int code;
    if (offset>0) {
      code = ((data[offset - 1] & 0x01) == 0 ? 0xff : 0x00);
    }
    else {
      code = ((data[data.length - 1] & 0x01) == 0 ? 0xff : 0x00);
    }
    while (offset < data.length) {
      data[offset] = code;
      offset++;
    }
    return count;
  }

  /// return the number of pad bytes present in the block.
  @override
  int padCount(Uint8List data) {
    int code = data[data.length-1];
    int index = data.length-1;
    while (index > 0 && data[index-1] == code) {
      index -= 1;
    }
    return data.length -index;
  }
}
