//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2019 Aditya Kishore

part of 'steel_crypt_base.dart';

///Class specifically for password hashing
class PassCrypt {
  ///hash password given salt, text, and length
  String hashPass (String salt, String pass, [int length = 32]) {
    var params = Pbkdf2Parameters(utf8.encode(salt), 15000, length);
    var keyDerivator = KeyDerivator("SHA-512/HMAC/PBKDF2")
      ..init( params )
    ;
    var passBytes = base64.decode(pass);
    var key = keyDerivator.process( passBytes );
    return base64.encode(key);
  }

  ///check hashed password
  bool checkPassKey (String salt, String plain, String hashed, [int length = 32]) {
    var hashplain = hashPass(salt, plain, length);
    return hashplain == hashed;
  }
}