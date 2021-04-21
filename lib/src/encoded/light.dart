//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2021 Aditya Kishore

part of '../steel_crypt_base.dart';

/// This class is for encrypting and decrypting using various stream ciphers.
///
/// This version of LightCrypt is encoded, meaning that it expects keys and IVs to be
/// base64, and returns base64 encoded Strings. Plaintext should be UTF-8.
/// For more flexibility, LightCryptRaw is recommended.
class LightCrypt {
  final StreamAlgo _type;
  final String _stringType;
  final String _key;

  ///Get name of this LightCrypt's algorithm.
  StreamAlgo get algorithm {
    return _type;
  }

  ///Get this LightCrypt's key.
  String get key {
    return _key;
  }

  ///Construct encryption machine using key and algorithm.
  LightCrypt({required StreamAlgo algo, required String key})
      : _type = algo,
        _key = key,
        _stringType = stringifyStream(algo);

  /// Encrypt (with iv) and return in base 64.
  ///
  /// If you are using ISAAC, pass a blank String as [iv].
  ///
  /// Input should be encoded using UTF-8. IV should be encoded using base64.
  String encrypt({required String inp, required String iv}) {
    var machine = StreamCipher(_stringType);
    var localKey = base64Decode(key);
    var localInput = utf8.encode(inp);
    var ivList = base64Decode(iv);
    var params = ParametersWithIV(
        KeyParameter(Uint8List.fromList(localKey.sublist(0, 32))), ivList);
    machine.init(false, params);
    var inter = machine.process(Uint8List.fromList(localInput));
    return base64.encode(inter);
  }

  /// Decrypt (with iv) and return original String.
  ///
  /// If you are using ISAAC, pass a blank String as [iv].
  ///
  /// [encrypted] and [iv] should be encoded using base64. Encrypted should have
  /// been generated using the parameters specified in [encrypt].
  String decrypt({required String enc, required String iv}) {
    var machine = StreamCipher(_stringType);
    var localKey = base64Decode(key);
    var localInput = base64.decode(enc);
    var ivList = base64Decode(iv);
    var params = ParametersWithIV(
        KeyParameter(Uint8List.fromList(localKey.sublist(0, 32))), ivList);
    machine.init(false, params);
    var inter = machine.process(localInput);
    return utf8.decode(inter);
  }
}
