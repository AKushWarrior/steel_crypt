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

  static String paddingName;

  ///Creates 'Crypt', serves as encrypter/decrypter of text
  AesCrypt (core.String inkey32, [core.String intype = "cbc", core.String padding = 'pkcs7']) {
    type = intype;
    key32 = inkey32;
    paddingName = padding;

    if (type == 'cbc') {
      if (padding == 'iso7816-4') {
        encrypter = CBCBlockCipher(AESFastEngine());
      }
      else if (padding == 'pkcs7') {
        encrypter = Encrypter(AES(Key.fromBase64(key32), mode: AESMode.cbc));
      }
    }

    else if (type == 'sic') {
      paddingName = 'none';
      encrypter = Encrypter(AES(Key.fromBase64(key32), mode: AESMode.sic));
    }

    else if (type == 'cfb-64') {
      paddingName = 'none';
      encrypter = Encrypter(AES(Key.fromBase64(key32), mode: AESMode.cfb64));
    }

    else if (type == 'ctr') {
      paddingName = 'none';
      encrypter = Encrypter(AES(Key.fromBase64(key32), mode: AESMode.ctr));
    }

    else if (type == 'ecb') {
      if (padding == 'iso7816-4') {
        encrypter = ECBBlockCipher(AESFastEngine());
      }
      else if (padding == 'pkcs7') {
        encrypter = Encrypter(AES(Key.fromBase64(key32), mode: AESMode.ecb));
      }
    }

    else if (type == 'ofb-64') {
      paddingName = 'none';
    }
  }

  ///Encrypt (with iv) and return in base 64
  core.String encrypt (core.String input, core.String iv) {
    if (paddingName == "pkcs7" || paddingName == 'none') {
      Encrypted crypted = encrypter.encrypt(input, iv: IV.fromBase64(iv));
      return crypted.base64;
    }
    else if (paddingName == 'iso7816-4'){
      var key = utf8.encode(key32);
      var ivLocal = utf8.encode(iv);
      CipherParameters params = PaddedBlockCipherParameters(ParametersWithIV(KeyParameter(key.sublist(0,32)), ivLocal.sublist(0, 16)), null);
      PaddedBlockCipherImpl cipherImpl = PaddedBlockCipherImpl(Padding('ISO7816-4'), encrypter);
      cipherImpl.init(true, params);
      var inter = cipherImpl.process(utf8.encode(input));
      return base64.encode(inter);
    }
    throw ArgumentError("Padding was invalid!");
  }

  ///Decrypt base 64 (with iv) and return original
  core.String decrypt (core.String encrypted, core.String iv) {
    if (paddingName == 'pkcs7' || paddingName == 'none') {
      return encrypter.decrypt64(encrypted, iv: IV.fromBase64(iv));
    }
    else if (paddingName == 'iso7816-4'){
      var key = utf8.encode(key32);
      var ivLocal = utf8.encode(iv);
      CipherParameters params = PaddedBlockCipherParameters(ParametersWithIV(KeyParameter(key.sublist(0,32)), ivLocal.sublist(0, 16)), null);
      PaddedBlockCipherImpl cipherImpl = PaddedBlockCipherImpl(Padding('ISO7816-4'), encrypter);
      cipherImpl.init(false, params);
      var inter = cipherImpl.process(base64.decode(encrypted));
      return utf8.decode(inter);
    }
    throw ArgumentError("Padding was invalid!");
  }
}