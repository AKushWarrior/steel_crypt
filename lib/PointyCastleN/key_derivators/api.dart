// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

// ignore_for_file: omit_local_variable_types, prefer_single_quotes, non_constant_identifier_names, directives_ordering, prefer_typing_uninitialized_variables

library pointycastle.api.key_derivators;

import "dart:typed_data";

import '../api.dart';

/// [CipherParameters] used by PBKDF2.
class Pbkdf2Parameters extends CipherParameters {
  final Uint8List salt;
  final int iterationCount;
  final int desiredKeyLength;

  Pbkdf2Parameters(this.salt, this.iterationCount, this.desiredKeyLength);
}

/// [CipherParameters] for the scrypt password based key derivation function.
class ScryptParameters implements CipherParameters {
  final int N;
  final int r;
  final int p;
  final int desiredKeyLength;
  final Uint8List salt;

  ScryptParameters(this.N, this.r, this.p, this.desiredKeyLength, this.salt);
}
