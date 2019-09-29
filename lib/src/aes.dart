//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2019 Aditya Kishore

part of 'steel_crypt_base.dart';

///Create symmetric encryption machine (Crypt).
class AesCrypt {
  ///Mode of AES.
  core.String mode;

  ///Key for encryption.
  core.String key32;

  ///AESFastEngine wrapper.
  var encrypter;

  ///Type of padding.
  String paddingName;

  ///Creates 'Crypt', serves as encrypter/decrypter of text.
  AesCrypt(core.String inkey32,
      [core.String intype = 'cfb-64', core.String padding = 'pkcs7']) {
    mode = intype;
    key32 = inkey32;
    paddingName = padding;

    if (mode == 'cbc') {
      encrypter = CBCBlockCipher(AESFastEngine());
    } else if (mode == 'sic') {
      paddingName = 'none';
      encrypter = SICStreamCipher(AESFastEngine());
    } else if (mode == 'cfb-64') {
      encrypter = CFBBlockCipher(AESFastEngine(), 64);
    } else if (mode == 'ctr') {
      paddingName = 'none';
      encrypter = CTRStreamCipher(AESFastEngine());
    } else if (mode == 'ecb') {
      encrypter = ECBBlockCipher(AESFastEngine());
    } else if (mode == 'ofb-64') {
      encrypter = OFBBlockCipher(AESFastEngine(), 64);
    }
  }

  ///Encrypt (with iv) and return in base 64.
  core.String encrypt(core.String input, core.String iv) {
    if (paddingName == 'none') {
      var localKey = utf8.encode(key32);
      var localIV = utf8.encode(iv);
      var localInput = utf8.encode(input);
      var params = ParametersWithIV<KeyParameter>(
          KeyParameter(localKey.sublist(0, 32)), localIV.sublist(0, 16));
      encrypter..init(true, params);
      var inter = encrypter.process(localInput);
      return base64.encode(inter);
    } else {
      var key = utf8.encode(key32);
      var ivLocal = utf8.encode(iv);
      CipherParameters params = PaddedBlockCipherParameters(
          ParametersWithIV<KeyParameter>(
              KeyParameter(key.sublist(0, 32)), ivLocal.sublist(0, 16)),
          null);
      PaddedBlockCipher cipher = PaddedBlockCipher(
          "AES/" + mode.toUpperCase() + "/" + paddingName.toUpperCase());
      cipher..init(true, params);
      var inter = cipher.process(utf8.encode(input));
      return base64.encode(inter);
    }
  }

  ///Decrypt base 64 (with iv) and return original.
  core.String decrypt(core.String encrypted, core.String iv) {
    if (paddingName == 'none') {
      var localKey = utf8.encode(key32);
      var localIV = utf8.encode(iv);
      var localInput = base64.decode(encrypted);
      var params = ParametersWithIV<KeyParameter>(
          KeyParameter(localKey.sublist(0, 32)), localIV.sublist(0, 16));
      encrypter..init(false, params);
      var inter = encrypter.process(localInput);
      return utf8.decode(inter);
    } else {
      var key = utf8.encode(key32);
      var ivLocal = utf8.encode(iv);
      CipherParameters params = PaddedBlockCipherParameters(
          ParametersWithIV(
              KeyParameter(key.sublist(0, 32)), ivLocal.sublist(0, 16)),
          null);
      PaddedBlockCipher cipher = PaddedBlockCipher(
          "AES/" + mode.toUpperCase() + "/" + paddingName.toUpperCase());
      cipher..init(false, params);
      var inter = cipher.process(base64.decode(encrypted));
      return utf8.decode(inter);
    }
  }
}
