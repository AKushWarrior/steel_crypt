//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2019 Aditya Kishore

part of 'steel_crypt_base.dart';

class LightCrypt {

  ///Type of algorithm
  static core.String type;

  ///Key for encryption
  static core.String key32;

  static var encrypter;

  LightCrypt (core.String inkey32, [core.String intype = "Salsa20"]) {
    type = intype;
    key32 = inkey32;
    if (type == 'Salsa20') {
      encrypter = Encrypter(Salsa20(Key.fromBase64(key32)));
    }
    else if (type == "ChaCha20") {}
    else {
      throw ArgumentError("This algorithm isn't supported. Check for typos, or file a feature request.");
    }
  }

  ///Encrypt (with iv) and return in base 64
  core.String encrypt (core.String input, core.String iv) {
    if (type == 'Salsa20') {
      Encrypted crypted = encrypter.encrypt(input, iv:IV.fromBase64(iv));
      return crypted.base64;
    }
    else if (type == 'ChaCha20') {
      var chacha20 = Chacha20();
      chacha20.initialize(key: base64Url.decode(key32), nonce: base64Url.decode(iv));
      var bytes = base64.decode(input);
      var convert = chacha20.convert(bytes);
      var returner = base64.encode(convert);
      return returner;
    }
    return "";
  }

  ///Decrypt base 64 (with iv) and return original
  core.String decrypt (core.String encrypted, core.String iv) {
    if (type == 'Salsa20') {
      return encrypter.decrypt64(encrypted, iv: IV.fromBase64(iv));
    }
    else if (type == 'ChaCha20') {
      var chacha20 = Chacha20();
      chacha20.initialize(key: base64Url.decode(key32), nonce: base64Url.decode(iv));
      var bytes = base64.decode(encrypted);
      var convert = chacha20.convert(bytes);
      var returner = base64.encode(convert);
      return returner;
    }
    return "";
  }
}