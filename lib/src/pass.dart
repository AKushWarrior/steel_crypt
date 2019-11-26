//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2019 Aditya Kishore

part of 'steel_crypt_base.dart';

///Class specifically for password hashing.
class PassCrypt {
  String algorithm;
  KeyDerivator _keyDerivator;

  PassCrypt([String algorithm = 'scrypt']) {
    this.algorithm = algorithm;
    if (algorithm == "scrypt" || algorithm.contains("PBKDF2")) {
      _keyDerivator = KeyDerivator(algorithm);
    } else {
      throw ArgumentError(
          "invalid algorithm, refer to README for valid algorithms");
    }
  }

  ///Hashes password given salt, text, and length.
  String hashPass(String salt, String pass, [int length = 32]) {
    var passhash = this._keyDerivator;
    if (algorithm.contains("PBKDF2")) {
      var params = Pbkdf2Parameters(utf8.encode(salt), 10000, length);
      passhash..init(params);
    } else {
      var params = ScryptParameters(16384, 16, 2, length, utf8.encode(salt));
      passhash..init(params);
    }
    var bytes;
    bytes = Utf8Codec().encode(pass);
    var key = _keyDerivator.process(bytes);
    return base64.encode(key);
  }

  ///Checks hashed password given salt, plaintext, length, and hashedtext.
  bool checkPassKey(String salt, String plain, String hashed,
      [int length = 32]) {
    var hashplain = hashPass(salt, plain, length);
    return hashplain == hashed;
  }
}
