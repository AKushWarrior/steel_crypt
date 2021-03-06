//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2021 Aditya Kishore

part of '../steel_crypt_base.dart';

/// Class for password hashing in scrypt and PBKDF2.
///
/// This version of PassCrypt is encoded, meaning that it expects all keys and IVs to be
/// base64, and returns base64 encoded Strings. Plaintext should be UTF-8. For more flexibility, PassCryptRaw is recommended.
class PassCrypt {
  final int _algorithm;
  Map<String, int> params;
  final KeyDerivator _keyDerivator;
  HMac? _hmac;

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
  PassCrypt.scrypt({int cpu = 16384, int mem = 16, int par = 1})
      : params = {'N': cpu, 'r': mem, 'p': par},
        _algorithm = 0,
        _keyDerivator = Scrypt();

  /// Initialize a PBKDF2-based PassCrypt.
  ///
  /// Iterations is the number of hashes that will be performed. This is a typical
  /// time v. security tradeoff.
  PassCrypt.pbkdf2({int iterations = 10000, required HmacHash algo})
      : params = {'N': iterations},
        _algorithm = 1,
        _hmac = parsePBKDF2(algo),
        _keyDerivator = PBKDF2KeyDerivator(parsePBKDF2(algo));

  /// Hashes password given salt, text, and length.
  ///
  /// [salt] should be base64-encoded. This method returns a base-64 encoded
  /// key.
  String hash({required String salt, required String inp, int len = 32}) {
    CipherParameters params;
    if (_algorithm == 1) {
      params = Pbkdf2Parameters(base64Decode(salt), this.params['N']!, len);
    } else {
      params = ScryptParameters(this.params['N']!, this.params['r']!,
          this.params['p']!, len, base64Decode(salt));
    }
    _keyDerivator.init(params);
    var bytes = utf8.encode(inp) as Uint8List;
    var key = _keyDerivator.process(bytes);
    return base64.encode(key);
  }

  /// Checks hashed password given salt, plaintext, length, and hashedtext.
  bool check(
      {required String plain,
      required String hashed,
      required String salt,
      int len = 32}) {
    var hashplain = hash(salt: salt, inp: plain, len: len);
    return hashplain == hashed;
  }
}
