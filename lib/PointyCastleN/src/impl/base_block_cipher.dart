// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.src.impl.base_block_cipher;

import "dart:typed_data";

import '../../api.dart';

/// Base implementation of [BlockCipher] which provides shared methods.
abstract class BaseBlockCipher implements BlockCipher {
  Uint8List process(Uint8List data) {
    var out = new Uint8List(blockSize);
    var len = processBlock(data, 0, out, 0);
    return out.sublist(0, len);
  }
}
