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

  ///Salsa20 encryption machine
  static StreamCipher encrypter;

  ///Construct encrypter
  LightCrypt(core.String inkey32, [core.String intype = "Salsa20"]) {
    type = intype;
    key32 = inkey32;
    if (type == 'Salsa20' || type == 'Salsa20/8' || type == 'Salsa20/12') {
      encrypter = StreamCipher(type);
    } else if (type == 'Salsa20/20') {
      type = 'Salsa20';
      encrypter = StreamCipher(type);
    } else if (type == "ChaCha20" ||
        type == "ChaCha20/20" ||
        type == "ChaCha20/12" ||
        type == "ChaCha20/8" ||
        type == "HC-256" ||
        type == 'Grain-128' ||
        type == "ISAAC") {
    } else {
      throw ArgumentError(
          "This algorithm isn't supported. Check for typos, or file a feature request.");
    }
  }

  ///Encrypt (with iv) and return in base 64
  core.String encrypt(core.String input, core.String iv) {
    if (type == 'Salsa20' || type == 'Salsa20/8' || type == 'Salsa20/12') {
      var localKey = utf8.encode(key32);
      var localIV = utf8.encode(iv);
      var localInput = utf8.encode(input);
      var params = ParametersWithIV<KeyParameter>(
          KeyParameter(localKey.sublist(0, 32)), localIV.sublist(0, 8));
      encrypter..init(true, params);
      var inter = encrypter.process(localInput);
      return base64.encode(inter);
    } else if (type == 'ChaCha20' || type == 'ChaCha20/20') {
      var chacha20 = Chacha20();
      chacha20.initialize(
          key: base64Url.decode(key32), nonce: base64Url.decode(iv));
      var bytes = base64.decode(input);
      var convert = chacha20.convert(bytes);
      var returner = base64.encode(convert);
      return returner;
    } else if (type == 'ChaCha20/12') {
      var chacha20 = Chacha12();
      chacha20.initialize(
          key: base64Url.decode(key32), nonce: base64Url.decode(iv));
      var bytes = base64.decode(input);
      var convert = chacha20.convert(bytes);
      var returner = base64.encode(convert);
      return returner;
    } else if (type == 'ChaCha20/8') {
      var chacha20 = Chacha8();
      chacha20.initialize(
          key: base64Url.decode(key32), nonce: base64Url.decode(iv));
      var bytes = base64.decode(input);
      var convert = chacha20.convert(bytes);
      var returner = base64.encode(convert);
      return returner;
    } else if (type == 'Grain-128') {
      var machine = StreamCipher(type);
      var localKey = utf8.encode(key32);
      var localIV = utf8.encode(iv);
      var localInput = utf8.encode(input);
      var params = ParametersWithIV<KeyParameter>(
          KeyParameter(localKey.sublist(0, 32)), localIV.sublist(0, 12));
      machine..init(false, params);
      var inter = machine.process(localInput);
      return base64.encode(inter);
    } else if (type == "ISAAC") {
      var machine = StreamCipher(type);
      var localKey = utf8.encode(key32);
      var localInput = utf8.encode(input);
      var params = KeyParameter(localKey.sublist(0, 32));
      machine..init(false, params);
      var inter = machine.process(localInput);
      return base64.encode(inter);
    } else if (type == 'HC-256') {
      var machine = StreamCipher(type);
      var localKey = utf8.encode(key32);
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
    if (type == 'Salsa20' || type == 'Salsa20/8' || type == 'Salsa20/12') {
      var localKey = utf8.encode(key32);
      var localIV = utf8.encode(iv);
      var localInput = base64.decode(encrypted);
      var params = ParametersWithIV<KeyParameter>(
          KeyParameter(localKey.sublist(0, 32)), localIV.sublist(0, 8));
      encrypter..init(false, params);
      var inter = encrypter.process(localInput);
      return utf8.decode(inter);
    } else if (type == 'Grain-128') {
      var machine = StreamCipher(type);
      var localKey = utf8.encode(key32);
      var localIV = utf8.encode(iv);
      var localInput = base64.decode(encrypted);
      var params = ParametersWithIV<KeyParameter>(
          KeyParameter(localKey.sublist(0, 32)), localIV.sublist(0, 12));
      machine..init(false, params);
      var inter = machine.process(localInput);
      return utf8.decode(inter);
    } else if (type == 'HC-256') {
      var machine = StreamCipher(type);
      var localKey = utf8.encode(key32);
      var localIV = utf8.encode(iv);
      var localInput = base64.decode(encrypted);
      var params = ParametersWithIV<KeyParameter>(
          KeyParameter(localKey.sublist(0, 32)), localIV.sublist(0, 16));
      machine..init(false, params);
      var inter = machine.process(localInput);
      return utf8.decode(inter);
    } else if (type == "ISAAC") {
      var machine = StreamCipher(type);
      var localKey = utf8.encode(key32);
      var localIV = utf8.encode(iv);
      var localInput = base64.decode(encrypted);
      var params = KeyParameter(localKey.sublist(0, 32));
      machine..init(false, params);
      var inter = machine.process(localInput);
      return utf8.decode(inter);
    } else if (type == 'ChaCha20' || type == 'ChaCha20/20') {
      var chacha20 = Chacha20();
      chacha20.initialize(
          key: base64Url.decode(key32), nonce: base64Url.decode(iv));
      var bytes = base64.decode(encrypted);
      var convert = chacha20.convert(bytes);
      var returner = base64.encode(convert);
      return returner;
    } else if (type == 'ChaCha20/12') {
      var chacha20 = Chacha12();
      chacha20.initialize(
          key: base64Url.decode(key32), nonce: base64Url.decode(iv));
      var bytes = base64.decode(encrypted);
      var convert = chacha20.convert(bytes);
      var returner = base64.encode(convert);
      return returner;
    } else if (type == 'ChaCha20/8') {
      var chacha20 = Chacha8();
      chacha20.initialize(
          key: base64Url.decode(key32), nonce: base64Url.decode(iv));
      var bytes = base64.decode(encrypted);
      var convert = chacha20.convert(bytes);
      var returner = base64.encode(convert);
      return returner;
    }
    return "";
  }
}
