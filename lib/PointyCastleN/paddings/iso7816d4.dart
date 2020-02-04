// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

// ignore_for_file: omit_local_variable_types, prefer_single_quotes
// ignore_for_file: non_constant_identifier_names, directives_ordering
// ignore_for_file: prefer_typing_uninitialized_variables, camel_case_types
// ignore_for_file: annotate_overrides
library pointycastle.impl.padding.iso7816d4;

import "dart:typed_data" show Uint8List;

import '../api.dart';
import '../src/impl/base_padding.dart';
import '../src/registry/registry.dart';

// ignore_for_file: omit_local_variable_types, prefer_single_quotes
// ignore_for_file: non_constant_identifier_names, directives_ordering
// ignore_for_file: prefer_typing_uninitialized_variables, camel_case_types
// ignore_for_file: annotate_overrides

/// A padder that adds the padding according to the scheme referenced in
/// ISO 7814-4 - scheme 2 from ISO 9797-1. The first byte is 0x80, rest is 0x00
class ISO7816d4Padding extends BasePadding {
  static final FactoryConfig FACTORY_CONFIG =
      StaticFactoryConfig(Padding, "ISO7816-4", () => ISO7816d4Padding());

  String get algorithmName => "ISO7816-4";

  @override
  void init([CipherParameters params]) {
    // nothing to do.
  }

  /// add the pad bytes to the passed in block, returning the
  /// number of bytes added.
  @override
  int addPadding(Uint8List data, int offset) {
    int added = (data.length - offset);

    data[offset] = 0x80;
    offset++;

    while (offset < data.length) {
      data[offset] = 0;
      offset++;
    }

    return added;
  }

  /// return the number of pad bytes present in the block.
  @override
  int padCount(Uint8List data) {
    int count = data.length - 1;

    while (count > 0 && data[count] == 0) {
      count--;
    }

    if (data[count] != 0x80) {
      throw ArgumentError("pad block corrupted");
    }

    return data.length - count;
  }
}
