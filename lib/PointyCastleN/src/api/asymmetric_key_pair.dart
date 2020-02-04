// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

// ignore_for_file: omit_local_variable_types, prefer_single_quotes
// ignore_for_file: non_constant_identifier_names, directives_ordering
// ignore_for_file: prefer_typing_uninitialized_variables, camel_case_types
// ignore_for_file: annotate_overrides

part of pointycastle.api;

/// A pair of public and private asymmetric keys.
class AsymmetricKeyPair<B extends PublicKey, V extends PrivateKey> {
  final B publicKey;
  final V privateKey;

  AsymmetricKeyPair(this.publicKey, this.privateKey);
}
