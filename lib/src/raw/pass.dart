//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2020 Aditya Kishore

part of '../steel_crypt_base.dart';

/// Class for password hashing in scrypt and PBKDF2.
///
/// This version of PassCrypt is raw, meaning that it expects all inputs to be
/// Uint8List, and returns Uint8Lists. For a higher-level solution, PassCrypt
/// is recommended.
class PassCryptRaw {
  String _algorithm;
  Map<String, int> params;
  KeyDerivator _keyDerivator;
  HMac _hmac;

  PassCryptRaw() {
    throw UnimplementedError('Use PassCrypt.scrypt() or PassCrypt.pbkdf2()');
  }

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
  PassCryptRaw.scrypt({int cpu = 16384, int mem = 16, int par = 1}) {
    params = {'N': cpu, 'r': mem, 'p': par};
    _algorithm = 'S';
  }

  /// Initialize a PBKDF2-based PassCrypt.
  ///
  /// Iterations is the number of hashes that will be performed. This is a typical
  /// time v. security tradeoff.
  PassCryptRaw.pbkdf2({int iterations = 10000, HmacHash hmac}) {
    params = {'N': iterations};
    _algorithm = 'P';
    _hmac = parsePBKDF2(hmac);
  }

  ///Hashes password given salt, text, and length.
  Uint8List hashPass(Uint8List salt, Uint8List pass, {int length = 32}) {
    if (_algorithm == 'S') {
      _keyDerivator = Scrypt();
    } else {
      _keyDerivator = PBKDF2KeyDerivator(_hmac);
    }
    var passhash = _keyDerivator;
    if (_algorithm == 'P') {
      var params = Pbkdf2Parameters(salt, this.params['N'], length);
      passhash.init(params);
    } else {
      final params = ScryptParameters(
          this.params['N'], this.params['r'], this.params['p'], length, salt);
      passhash.init(params);
    }
    return _keyDerivator.process(pass);
  }

  ///Checks hashed password given salt, plaintext, length, and hashedtext.
  bool checkPassKey(Uint8List salt, Uint8List plain, Uint8List hashed,
      {int length = 32}) {
    var hashplain = hashPass(salt, plain, length: length);
    return hashplain == hashed;
  }
}
