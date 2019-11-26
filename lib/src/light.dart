//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2019 Aditya Kishore

part of 'steel_crypt_base.dart';

///Class containing stream ciphers of every kind.
class LightCrypt {
  core.String _type;
  core.String _key;
  StreamCipher _encrypter;

  ///Get name of this LightCrypt's algorithm.
  String get algorithm {
    return _type;
  }

  ///Get this LightCrypt's key.
  String get key {
    return _key;
  }

  ///Construct encryption machine using key and algorithm.
  LightCrypt(core.String key, [core.String algorithm = "ChaCha20"]) {
    _type = algorithm;
    _key = key;
    if (_type == 'Salsa20' ||
        _type == 'Salsa20/8' ||
        _type == 'Salsa20/12' ||
        _type == "ChaCha20" ||
        _type == "ChaCha20/12" ||
        _type == "ChaCha20/8") {
      _encrypter = StreamCipher(_type);
    } else if (_type == 'Salsa20/20') {
      _type = 'Salsa20';
      _encrypter = StreamCipher(_type);
    } else if (_type == 'ChaCha20/20') {
      _type = 'ChaCha20';
      _encrypter = StreamCipher(_type);
    } else if (_type == "HC-256" ||
        _type == 'Grain-128' ||
        _type == "ISAAC" ||
        _type == "RC4") {
    } else {
      throw ArgumentError(
          "This algorithm isn't supported. Check for typos, or file a feature request.");
    }
  }

  ///Encrypt (with iv) and return in base 64
  core.String encrypt(core.String input, core.String iv) {
    if (_type == 'Salsa20' || _type == 'Salsa20/8' || _type == 'Salsa20/12' ||
        _type == "ChaCha20" ||
        _type == "ChaCha20/12" ||
        _type == "ChaCha20/8") {
      var localKey = utf8.encode(_key);
      var localIV = utf8.encode(iv);
      var localInput = utf8.encode(input);
      var params = ParametersWithIV<KeyParameter>(
          KeyParameter(localKey.sublist(0, 32)), localIV.sublist(0, 8));
      _encrypter..init(true, params);
      var inter = _encrypter.process(localInput);
      return base64.encode(inter);
    } else if (_type == 'Grain-128') {
      var machine = StreamCipher(_type);
      var localKey = utf8.encode(_key);
      var localIV = utf8.encode(iv);
      var localInput = utf8.encode(input);
      var params = ParametersWithIV<KeyParameter>(
          KeyParameter(localKey.sublist(0, 32)), localIV.sublist(0, 12));
      machine..init(false, params);
      var inter = machine.process(localInput);
      return base64.encode(inter);
    } else if (_type == "ISAAC" || _type == "RC4") {
      var machine = StreamCipher(_type);
      var localKey = utf8.encode(_key);
      var localInput = utf8.encode(input);
      var params = KeyParameter(localKey.sublist(0, 32));
      machine..init(false, params);
      var inter = machine.process(localInput);
      return base64.encode(inter);
    } else if (_type == 'HC-256') {
      var machine = StreamCipher(_type);
      var localKey = utf8.encode(_key);
      var localIV = utf8.encode(iv);
      var localInput = utf8.encode(input);
      var params = ParametersWithIV<KeyParameter>(
          KeyParameter(localKey.sublist(0, 32)), localIV.sublist(0, 16));
      machine..init(false, params);
      var inter = machine.process(localInput);
      return base64.encode(inter);
    }
    return "";
  }

  ///Decrypt base 64 (with iv) and return original
  core.String decrypt(core.String encrypted, core.String iv) {
    if (_type == 'Salsa20' || _type == 'Salsa20/8' || _type == 'Salsa20/12' ||
        _type == "ChaCha20" ||
        _type == "ChaCha20/12" ||
        _type == "ChaCha20/8") {
      var localKey = utf8.encode(_key);
      var localIV = utf8.encode(iv);
      var localInput = base64.decode(encrypted);
      var params = ParametersWithIV<KeyParameter>(
          KeyParameter(localKey.sublist(0, 32)), localIV.sublist(0, 8));
      _encrypter..init(false, params);
      var inter = _encrypter.process(localInput);
      return utf8.decode(inter);
    } else if (_type == 'Grain-128') {
      var machine = StreamCipher(_type);
      var localKey = utf8.encode(_key);
      var localIV = utf8.encode(iv);
      var localInput = base64.decode(encrypted);
      var params = ParametersWithIV<KeyParameter>(
          KeyParameter(localKey.sublist(0, 32)), localIV.sublist(0, 12));
      machine..init(false, params);
      var inter = machine.process(localInput);
      return utf8.decode(inter);
    } else if (_type == 'HC-256') {
      var machine = StreamCipher(_type);
      var localKey = utf8.encode(_key);
      var localIV = utf8.encode(iv);
      var localInput = base64.decode(encrypted);
      var params = ParametersWithIV<KeyParameter>(
          KeyParameter(localKey.sublist(0, 32)), localIV.sublist(0, 16));
      machine..init(false, params);
      var inter = machine.process(localInput);
      return utf8.decode(inter);
    } else if (_type == "ISAAC" || _type == "RC4") {
      var machine = StreamCipher(_type);
      var localKey = utf8.encode(_key);
      var localInput = base64.decode(encrypted);
      var params = KeyParameter(localKey.sublist(0, 32));
      machine..init(false, params);
      var inter = machine.process(localInput);
      return utf8.decode(inter);
    }
    return "";
  }
}
