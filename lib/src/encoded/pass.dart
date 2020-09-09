//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2020 Aditya Kishore

part of '../steel_crypt_base.dart';

/// Class for password hashing in scrypt and PBKDF2.
///
/// This version of PassCrypt is encoded, meaning that it expects all keys and IVs to be
/// base64, and returns base64 encoded Strings. Plaintext should be UTF-8. For more flexibility, PassCryptRaw is recommended.
class PassCrypt {
  String _algorithm;
  Map<String, int> params;
  KeyDerivator _keyDerivator;
  HMac _hmac;

  PassCrypt() {
    throw UnimplementedError('Use PassCrypt.scrypt() or PassCrypt.pbkdf2()');
  }

  ///Initialize a Scrypt-based PassCrypt().
  ///
  /// cpu is the cpu difficulty. This  is the security vs. time tradeoff:
  /// increasing increases both time and security. This must be a power
  /// of two. If you want to speed up hashing/increase security, decrease/
  /// increase this parameter.
  ///
  /// mem is the memory difficulty. This should not be changed unless you have
  /// a specific reason for doing so (memory constraints). The lowest recommended
  /// value is 8.
  ///
  /// par is the parallel difficulty. Higher values for p compute more hashes
  /// in the same time, but should only be used if you're cpu-restricted and
  /// can't up the cpu difficulty any further.
  PassCrypt.scrypt({int cpu = 16384, int mem = 16, int par = 1}) {
    params = {'N': cpu, 'r': mem, 'p': par};
    _algorithm = 'S';
  }

  /// Initialize a PBKDF2-based PassCrypt.
  ///
  /// Iterations is the number of hashes that will be performed. This is a typical
  /// time v. security tradeoff.
  PassCrypt.pbkdf2({int iterations = 10000, @required HmacHash algo}) {
    params = {'N': iterations};
    _algorithm = 'P';
    _hmac = parsePBKDF2(algo);
  }

  ///Hashes password given salt, text, and length.
  String hash({@required String salt, @required String inp, int len = 32}) {
    return base64.encode(hashBytes(
        salt: base64Decode(salt),
        input: utf8.encode(inp) as Uint8List,
        len: len));
  }

  ///Hashes password given salt, text, and length.
  Uint8List hashBytes(
      {@required Uint8List salt, @required Uint8List input, int len = 32}) {
    if (_algorithm == 'S') {
      _keyDerivator = Scrypt();
    } else {
      _keyDerivator = PBKDF2KeyDerivator(_hmac);
    }
    var passhash = _keyDerivator;
    if (_algorithm == 'P') {
      var params = Pbkdf2Parameters(salt, this.params['N'], len);
      passhash.init(params);
    } else {
      final params = ScryptParameters(
          this.params['N'], this.params['r'], this.params['p'], len, salt);
      passhash.init(params);
    }
    var key = _keyDerivator.process(input);
    return key;
  }

  ///Checks hashed password given salt, plaintext, length, and hashedtext.
  bool check(
      {@required String plain,
      @required String hashed,
      @required String salt,
      int len = 32}) {
    var hashplain = hash(salt: salt, inp: plain, len: len);
    return hashplain == hashed;
  }
}
