//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2019 Aditya Kishore

part of 'steel_crypt_base.dart';

///Class specifically for password hashing
class PassCrypt {
  static List<String> pads = ['nYg'];
  String algorithm;
  KeyDerivator keyDerivator;

  PassCrypt ([String algorithm = 'scrypt']) {
    this.algorithm = algorithm;
    if (algorithm == "scrypt") {
      keyDerivator = KeyDerivator(algorithm);
    }
    else if (algorithm.contains("PBKDF2")) {
      keyDerivator = KeyDerivator(algorithm);
    }
    else {
      throw ArgumentError("invalid algorithm, refer to README for valid algorithms");
    }
  }

  ///hash password given salt, text, and length
  String hashPass (String salt, String pass, [int length = 32]) {
    var passhash = this.keyDerivator;
    if (algorithm.contains("PBKDF2")) {
      var params = Pbkdf2Parameters(utf8.encode(salt), 10000, length);
      passhash
        ..init(params);
    }
    else {
      var params = ScryptParameters(16384, 16, 1, length, utf8.encode(salt));
      passhash
        ..init(params);
    };
    var bytes;
    if (pass.length % 4 == 0) {
      bytes = Base64Codec().decode(pass);
    }
    else {
      var advinput = pass;
      advinput = pass + pads[0];
      advinput = advinput.substring(0, advinput.length-advinput.length%4);
      bytes = Base64Codec().decode(advinput);
    }
    var key = keyDerivator.process(bytes);
    return base64.encode(key);
  }

  ///check hashed password
  bool checkPassKey (String salt, String plain, String hashed, [int length = 32]) {
    var hashplain = hashPass(salt, plain, length);
    return hashplain == hashed;
  }
}