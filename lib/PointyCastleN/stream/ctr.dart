// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

// ignore_for_file: omit_local_variable_types, prefer_single_quotes
// ignore_for_file: non_constant_identifier_names, directives_ordering
// ignore_for_file: prefer_typing_uninitialized_variables, camel_case_types
// ignore_for_file: annotate_overrides
library pointycastle.impl.stream_cipher.ctr;

import '../api.dart';
import '../src/registry/registry.dart';
import 'sic.dart';

/// Just an alias to be able to create SIC as CTR
class CTRStreamCipher extends SICStreamCipher {
  /// Intended for internal use.
  static final FactoryConfig FACTORY_CONFIG = DynamicFactoryConfig.suffix(
      StreamCipher,
      "/CTR",
      (_, final Match match) => () {
            String digestName = match.group(1);
            return CTRStreamCipher(BlockCipher(digestName));
          });

  CTRStreamCipher(BlockCipher underlyingCipher) : super(underlyingCipher);

  @override
  String get algorithmName => "${underlyingCipher.algorithmName}/CTR";
}
