// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.
// ignore_for_file: omit_local_variable_types, prefer_single_quotes
// ignore_for_file: non_constant_identifier_names, directives_ordering
// ignore_for_file: prefer_typing_uninitialized_variables, camel_case_types
// ignore_for_file: annotate_overrides
library pointycastle.src.impl.base_padding;

import "dart:typed_data";

import '../../api.dart';

/// Base implementation of [Padding] which provides shared methods.
abstract class BasePadding implements Padding {
  @override
  Uint8List process(bool pad, Uint8List data) {
    if (pad) {
      var out = Uint8List.fromList(data);
      return out;
    } else {
      var len = padCount(data);
      return Uint8List.fromList(data.sublist(0, len));
    }
  }
}
