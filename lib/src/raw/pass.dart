//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2021 Aditya Kishore

part of '../steel_crypt_base.dart';

/// Class for password hashing in scrypt and PBKDF2.
///
/// This version of PassCrypt is raw, meaning that it expects all inputs to be
/// Uint8List, and returns Uint8Lists. For a higher-level solution, PassCrypt
/// is recommended.
class PassCryptRaw {
  int _algorithm;
  Map<String, int> _params;
  HMac? _hmac;

  ///Initialize a Scrypt-based PassCrypt().
  ///
  /// cpu is the cpu difficulty. This is the security vs. time tradeoff:
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
  PassCryptRaw.scrypt({int cpu = 16384, int mem = 16, int par = 1})
      : _algorithm = 0,
        _params = {'N': cpu, 'r': mem, 'p': par};

  /// Initialize a PBKDF2-based PassCrypt.
  ///
  /// Iterations is the number of hashes that will be performed. This is a typical
  /// time v. security tradeoff.
  PassCryptRaw.pbkdf2({int iterations = 10000, required HmacHash hmac})
      : _algorithm = 1,
        _params = {'N': iterations} {
    _hmac = parsePBKDF2(hmac);
  }

  ///Hashes password given salt, text, and length.
  Uint8List hash(
      {required Uint8List salt, required Uint8List plain, int len = 32}) {
    var passhash = _algorithm == 0 ? Scrypt() : PBKDF2KeyDerivator(_hmac!);
    if (_algorithm == 1) {
      var params = Pbkdf2Parameters(salt, _params['N']!, len);
      passhash.init(params);
    } else {
      final params = ScryptParameters(
          _params['N']!, _params['r']!, _params['p']!, len, salt);
      passhash.init(params);
    }
    return passhash.process(plain);
  }

  ///Checks hashed password given salt, plaintext, length, and hashedtext.
  bool check(
      {required Uint8List plain,
      required Uint8List hashed,
      required Uint8List salt,
      int len = 32}) {
    var hashplain = hash(salt: salt, plain: plain, len: len);
    return hashplain == hashed;
  }
}
