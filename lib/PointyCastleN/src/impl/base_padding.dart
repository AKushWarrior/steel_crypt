// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.src.impl.base_padding;

import "dart:typed_data";

import '../../api.dart';

/// Base implementation of [Padding] which provides shared methods.
abstract class BasePadding implements Padding {
  Uint8List process(bool pad, Uint8List data) {
    if (pad) {
      var out = new Uint8List.fromList(data);
      return out;
    } else {
      var len = padCount(data);
      return new Uint8List.fromList(data.sublist(0, len));
    }
  }
}
