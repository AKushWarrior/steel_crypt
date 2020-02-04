// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.
// ignore_for_file: omit_local_variable_types, prefer_single_quotes
// ignore_for_file: non_constant_identifier_names, directives_ordering
// ignore_for_file: prefer_typing_uninitialized_variables, camel_case_types
// ignore_for_file: annotate_overrides
library pointycastle.src.impl.base_digest;

import "dart:typed_data";

import '../../api.dart';

/// Base implementation of [Digest] which provides shared methods.
abstract class BaseDigest implements Digest {
  @override
  Uint8List process(Uint8List data) {
    update(data, 0, data.length);
    var out = Uint8List(digestSize);
    var len = doFinal(out, 0);
    return out.sublist(0, len);
  }
}
