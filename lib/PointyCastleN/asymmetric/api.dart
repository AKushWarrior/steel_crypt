// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.
// ignore_for_file: omit_local_variable_types, prefer_single_quotes
// ignore_for_file: non_constant_identifier_names, directives_ordering
// ignore_for_file: prefer_typing_uninitialized_variables, camel_case_types
// ignore_for_file: annotate_overrides
library pointycastle.api.asymmetric;

import "dart:typed_data";

import '../api.dart';

/// Base class for asymmetric keys in RSA
abstract class RSAAsymmetricKey implements AsymmetricKey {
  // The parameters of this key
  final BigInt modulus;
  final BigInt exponent;

  /// Create an asymmetric key for the given domain parameters
  RSAAsymmetricKey(this.modulus, this.exponent);

  /// Get modulus [n] = p·q
  BigInt get n => modulus;
}

/// Private keys in RSA
class RSAPrivateKey extends RSAAsymmetricKey implements PrivateKey {
  // The secret prime factors of n
  final BigInt p;
  final BigInt q;

  /// Create an RSA private key for the given parameters.
  RSAPrivateKey(BigInt modulus, BigInt exponent, this.p, this.q)
      : super(modulus, exponent);

  /// Get private exponent [d] = e^-1
  BigInt get d => exponent;

  @override
  bool operator ==(other) {
    // ignore: avoid_null_checks_in_equality_operators
    if (other == null) return false;
    if (other is! RSAPrivateKey) return false;
    return (other.n == n) && (other.d == d);
  }

  @override
  int get hashCode => modulus.hashCode + exponent.hashCode;
}

/// Public keys in RSA
class RSAPublicKey extends RSAAsymmetricKey implements PublicKey {
  /// Create an RSA public key for the given parameters.
  RSAPublicKey(BigInt modulus, BigInt exponent) : super(modulus, exponent);

  /// Get public exponent [e]
  BigInt get e => exponent;

  @override
  bool operator ==(other) {
    // ignore: avoid_null_checks_in_equality_operators
    if (other == null) {
      return false;
    }
    if (other is! RSAPublicKey) return false;
    return (other.n == n) && (other.e == e);
  }

  @override
  int get hashCode => modulus.hashCode + exponent.hashCode;
}

/// A [Signature] created with RSA.
class RSASignature implements Signature {
  final Uint8List bytes;

  RSASignature(this.bytes);

  @override
  String toString() => bytes.toString();

  @override
  bool operator ==(other) {
    // ignore: avoid_null_checks_in_equality_operators
    if (other == null) return false;
    if (other is! RSASignature) return false;
    if (other.bytes.length != bytes.length) return false;

    for (var i = 0; i < bytes.length; i++) {
      if (bytes[i] != other.bytes[i]) {
        return false;
      }
    }
    return true;
  }

  @override
  int get hashCode => bytes.hashCode;
}
