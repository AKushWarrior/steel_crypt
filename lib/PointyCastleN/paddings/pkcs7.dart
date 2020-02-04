// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

// ignore_for_file: omit_local_variable_types, prefer_single_quotes, non_constant_identifier_names, directives_ordering, prefer_typing_uninitialized_variables

library pointycastle.impl.padding.pkcs7;

import "dart:typed_data";

import '../api.dart';
import '../src/impl/base_padding.dart';
import '../src/registry/registry.dart';
import '../src/ufixnum.dart';

// ignore_for_file: omit_local_variable_types, prefer_single_quotes
// ignore_for_file: non_constant_identifier_names, directives_ordering
// ignore_for_file: prefer_typing_uninitialized_variables, camel_case_types
// ignore_for_file: annotate_overrides

/// A [Padding] that adds PKCS7/PKCS5 padding to a block.
class PKCS7Padding extends BasePadding {
  static final FactoryConfig FACTORY_CONFIG =
      StaticFactoryConfig(Padding, "PKCS7", () => PKCS7Padding());

  String get algorithmName => "PKCS7";

  void init([CipherParameters params]) {
    // nothing to do.
  }

  int addPadding(Uint8List data, int offset) {
    var code = (data.length - offset);

    while (offset < data.length) {
      data[offset] = code;
      offset++;
    }

    return code;
  }

  int padCount(Uint8List data) {
    var count = clip8(data[data.length - 1]);

    if (count > data.length || count == 0) {
      throw ArgumentError("Invalid or corrupted pad block");
    }

    for (var i = 1; i <= count; i++) {
      if (data[data.length - i] != count) {
        throw ArgumentError("Invalid or corrupted pad block");
      }
    }

    return count;
  }
}
