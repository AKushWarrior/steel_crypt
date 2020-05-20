//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2020 Aditya Kishore

part of '../steel_crypt_base.dart';

/// This class is for encrypting and decrypting using various stream ciphers.
///
/// This version of LightCrypt is raw, meaning that it expects keys and IVs to be
/// Uint8List, and returns Uint8List. For more high-level solutions, LightCrypt is recommended.
class LightCryptRaw {
  StreamAlgorithm _type;
  String _stringType;
  Uint8List _key;

  ///Get name of this LightCrypt's algorithm.
  StreamAlgorithm get algorithm {
    return _type;
  }

  ///Get this LightCrypt's key.
  Uint8List get key {
    return _key;
  }

  ///Construct encryption machine using key and algorithm.
  LightCryptRaw(
      {@required StreamAlgorithm algorithm, @required Uint8List key}) {
    _type = algorithm;
    _key = key;
    _stringType = _stringifyType(algorithm);
  }

  /// Encrypt (with iv) and return encrypted Uint8Lists.
  Uint8List encrypt(Uint8List input, Uint8List iv) {
    var machine = StreamCipher(_stringType);
    var params = ParametersWithIV<KeyParameter>(KeyParameter(key), iv);
    machine..init(true, params);
    return machine.process(input);
  }

  /// Decrypt (with iv) and return original Uint8List.
  Uint8List decrypt(Uint8List encrypted, Uint8List iv) {
    var machine = StreamCipher(_stringType);
    var params = ParametersWithIV<KeyParameter>(KeyParameter(key), iv);
    machine..init(false, params);
    return machine.process(encrypted);
  }
}
