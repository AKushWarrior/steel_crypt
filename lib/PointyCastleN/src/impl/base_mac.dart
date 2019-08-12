// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.src.impl.base_mac;

import "dart:typed_data";

import '../../api.dart';

/// Base implementation of [Mac] which provides shared methods.
abstract class BaseMac implements Mac {
  Uint8List process(Uint8List data) {
    update(data, 0, data.length);
    var out = new Uint8List(macSize);
    var len = doFinal(out, 0);
    return out.sublist(0, len);
  }
}
