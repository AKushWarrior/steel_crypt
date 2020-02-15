//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2019 Aditya Kishore

part of 'steel_crypt_base.dart';

///Class specifically for password hashing.
class PassCrypt {
  String _algorithm;
  KeyDerivator _keyDerivator;

  ///Initialize a PassCrypt() with an _algorithm.
  PassCrypt([String _algorithm = 'scrypt']) {
    if (_algorithm == 'scrypt' || _algorithm.contains('PBKDF2')) {
      this._algorithm = _algorithm;
      _keyDerivator = KeyDerivator(_algorithm);
    } else {
      throw ArgumentError(
          'invalid algorithm, refer to README for valid algorithms');
    }
  }

  ///Hashes password given salt, text, and length.
  String hashPass(String salt, String pass, [int length = 32]) {
    var passhash = _keyDerivator;
    if (_algorithm.contains('PBKDF2')) {
      var params =
      Pbkdf2Parameters(Uint8List.fromList(salt.codeUnits), 10000, length);
      passhash.init(params);
    } else {
      final params = ScryptParameters(
          16384, 16, 2, length, Uint8List.fromList(salt.codeUnits));
      passhash.init(params);
    }
    var bytes = Uint8List.fromList(utf8.encode(pass));
    var key = _keyDerivator.process(Uint8List.fromList(bytes));
    return base64.encode(key);
  }

  ///Checks hashed password given salt, plaintext, length, and hashedtext.
  bool checkPassKey(String salt, String plain, String hashed,
      [int length = 32]) {
    var hashplain = hashPass(salt, plain, length);
    return hashplain == hashed;
  }
}
