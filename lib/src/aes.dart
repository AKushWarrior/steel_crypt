//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2019 Aditya Kishore

part of 'steel_crypt_base.dart';

///Create symmetric encryption machine (Crypt).
class AesCrypt {
  core.String _mode;
  core.String _key32;
  var _encrypter;
  String _paddingName;

  ///Get this AesCrypt's key;
  String get key {
    return _key32;
  }

  ///Get this AesCrypt's type of padding.
  String get padding {
    return _paddingName;
  }

  ///Get this AesCrypt's mode of AES.
  String get mode {
    return _mode;
  }

  ///Creates 'Crypt', serves as encrypter/decrypter of text.
  AesCrypt(core.String in_key32,
      [core.String intype = 'cfb-64', core.String padding = 'pkcs7']) {
    _mode = intype;
    _key32 = in_key32;
    _paddingName = padding;

    if (_mode == 'cbc') {
      _encrypter = CBCBlockCipher(AESFastEngine());
    } else if (_mode == 'sic') {
      _paddingName = 'none';
      _encrypter = SICStreamCipher(AESFastEngine());
    } else if (_mode == 'cfb-64') {
      _encrypter = CFBBlockCipher(AESFastEngine(), 64);
    } else if (_mode == 'ctr') {
      _paddingName = 'none';
      _encrypter = CTRStreamCipher(AESFastEngine());
    } else if (_mode == 'ecb') {
      _encrypter = ECBBlockCipher(AESFastEngine());
    } else if (_mode == 'ofb-64') {
      _encrypter = OFBBlockCipher(AESFastEngine(), 64);
    }
  }

  ///Encrypt (with iv) and return in base 64.
  core.String encrypt(core.String input, [core.String iv = ""]) {
    if (_mode != "ecb") {
      if (_paddingName == 'none') {
        var localKey = utf8.encode(_key32);
        var localIV = utf8.encode(iv);
        var localInput = utf8.encode(input);
        var params = ParametersWithIV<KeyParameter>(
            KeyParameter(localKey.sublist(0, 32)), localIV.sublist(0, 16));
        _encrypter..init(true, params);
        var inter = _encrypter.process(localInput);
        return base64.encode(inter);
      } else {
        var key = utf8.encode(_key32);
        var ivLocal = utf8.encode(iv);
        CipherParameters params = PaddedBlockCipherParameters(
            ParametersWithIV<KeyParameter>(
                KeyParameter(key.sublist(0, 32)), ivLocal.sublist(0, 16)),
            null);
        PaddedBlockCipher cipher = PaddedBlockCipher(
            "AES/" + _mode.toUpperCase() + "/" + _paddingName.toUpperCase());
        cipher..init(true, params);
        var inter = cipher.process(utf8.encode(input));
        return base64.encode(inter);
      }
    } else {
      var key = utf8.encode(_key32);
      var ivLocal = utf8.encode(iv);
      CipherParameters params =
      PaddedBlockCipherParameters(KeyParameter(key.sublist(0, 32)), null);
      PaddedBlockCipher cipher = PaddedBlockCipher(
          "AES/" + _mode.toUpperCase() + "/" + _paddingName.toUpperCase());
      cipher..init(true, params);
      var inter = cipher.process(utf8.encode(input));
      return base64.encode(inter);
    }
  }

  ///Decrypt base 64 (with iv) and return original.
  core.String decrypt(core.String encrypted, [core.String iv = ""]) {
    if (_mode != "ecb") {
      if (_paddingName == 'none') {
        var localKey = utf8.encode(_key32);
        var localIV = utf8.encode(iv);
        var localInput = base64.decode(encrypted);
        var params = ParametersWithIV<KeyParameter>(
            KeyParameter(localKey.sublist(0, 32)), localIV.sublist(0, 16));
        _encrypter..init(false, params);
        var inter = _encrypter.process(localInput);
        return utf8.decode(inter);
      } else {
        var key = utf8.encode(_key32);
        var ivLocal = utf8.encode(iv);
        CipherParameters params = PaddedBlockCipherParameters(
            ParametersWithIV(
                KeyParameter(key.sublist(0, 32)), ivLocal.sublist(0, 16)),
            null);
        PaddedBlockCipher cipher = PaddedBlockCipher(
            "AES/" + _mode.toUpperCase() + "/" + _paddingName.toUpperCase());
        cipher..init(false, params);
        var inter = cipher.process(base64.decode(encrypted));
        return utf8.decode(inter);
      }
    } else {
      var key = utf8.encode(_key32);
      CipherParameters params =
      PaddedBlockCipherParameters(KeyParameter(key.sublist(0, 32)), null);
      PaddedBlockCipher cipher = PaddedBlockCipher(
          "AES/" + _mode.toUpperCase() + "/" + _paddingName.toUpperCase());
      cipher..init(false, params);
      var inter = cipher.process(base64.decode(encrypted));
      return utf8.decode(inter);
    }
  }
}
