// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

// ignore_for_file: omit_local_variable_types, prefer_single_quotes, non_constant_identifier_names, directives_ordering, prefer_typing_uninitialized_variables

library pointycastle.api.key_generators;

import '../api.dart';

/// Abstract [CipherParameters] to init an RSA key generator.
class RSAKeyGeneratorParameters extends KeyGeneratorParameters {
  final BigInt publicExponent;
  final int certainty;

  RSAKeyGeneratorParameters(
      this.publicExponent, int bitStrength, this.certainty)
      : super(bitStrength);
}
