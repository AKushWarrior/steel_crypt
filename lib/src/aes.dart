//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2019 Aditya Kishore

part of 'steel_crypt_base.dart';

///Create symmetric encryption machine (Crypt)
class AesCrypt {
  ///Type of AES
  static core.String type;

  ///Key for encryption
  static core.String key32;

  static var encrypter;

  ///Creates 'Crypt', serves as encrypter/decrypter of text
  AesCrypt (core.String inkey32, [core.String intype = "cbc"]) {
    type = intype;
    key32 = inkey32;
    if (type == 'cbc') {
      encrypter = Encrypter(AES(Key.fromBase64(key32), mode: AESMode.cbc));
    }
    else if (type == 'sic') {
      encrypter = Encrypter(AES(Key.fromBase64(key32), mode: AESMode.sic));
    }
    else if (type == 'cfb-64') {
      encrypter = Encrypter(AES(Key.fromBase64(key32), mode: AESMode.cfb64));
    }
    else if (type == 'ctr') {
      encrypter = Encrypter(AES(Key.fromBase64(key32), mode: AESMode.ctr));
    }
    else if (type == 'ecb') {
      encrypter = Encrypter(AES(Key.fromBase64(key32), mode: AESMode.ecb));
    }
    else if (type == 'ofb-64') {
      encrypter = Encrypter(AES(Key.fromBase64(key32), mode: AESMode.ofb64));
    }
  }

  ///Encrypt (with iv) and return in base 64
  core.String encrypt (core.String input, core.String iv) {
    Encrypted crypted = encrypter.encrypt(input, iv:IV.fromBase64(iv));
    return crypted.base64;
  }

  ///Decrypt base 64 (with iv) and return original
  core.String decrypt (core.String encrypted, core.String iv) {
    return encrypter.decrypt64(encrypted, iv: IV.fromBase64(iv));
  }
}