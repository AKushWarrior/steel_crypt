//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2020 Aditya Kishore

part of '../steel_crypt_base.dart';

/// This class is for encrypting and decrypting using various stream ciphers.
///
/// This version of LightCrypt is encoded, meaning that it expects keys and IVs to be
/// base64, and returns base64 encoded Strings. Plaintext should be UTF-8.
/// For more flexibility, LightCryptRaw is recommended.
class LightCrypt {
  StreamAlgorithm _type;
  String _stringType;
  String _key;

  ///Get name of this LightCrypt's algorithm.
  StreamAlgorithm get algorithm {
    return _type;
  }

  ///Get this LightCrypt's key.
  String get key {
    return _key;
  }

  ///Construct encryption machine using key and algorithm.
  LightCrypt({@required StreamAlgorithm algorithm, @required String key}) {
    _type = algorithm;
    _key = key;
    _stringType = _stringifyType(algorithm);
  }

  /// Encrypt (with iv) and return in base 64.
  ///
  /// If you are using ISAAC, pass a blank String as [iv].
  ///
  /// Input should be encoded using UTF-8. IV should be encoded using base64.
  String encrypt(String input, String iv) {
    var machine = StreamCipher(_stringType);
    var localKey = Uint8List.fromList(key.codeUnits);
    var localInput = utf8.encode(input);
    var params = KeyParameter(Uint8List.fromList(localKey.sublist(0, 32)));
    machine..init(false, params);
    var inter = machine.process(Uint8List.fromList(localInput));
    return base64.encode(inter);
  }

  /// Decrypt (with iv) and return original String.
  ///
  /// If you are using ISAAC, pass a blank String as [iv].
  ///
  /// [encrypted] and [iv] should be encoded using base64. Encrypted should have
  /// been generated using the parameters specified in [encrypt].
  String decrypt(String encrypted, String iv) {
    var machine = StreamCipher(_stringType);
    var localKey = Uint8List.fromList(key.codeUnits);
    var localInput = base64.decode(encrypted);
    var params = KeyParameter(Uint8List.fromList(localKey.sublist(0, 32)));
    machine..init(false, params);
    var inter = machine.process(localInput);
    return utf8.decode(inter);
  }
}

enum StreamAlgorithm {
  salsa20,
  salsa20_12,
  salsa20_8,
  chacha20,
  chacha20_12,
  chacha20_8,
}

String _stringifyType(StreamAlgorithm algo) {
  switch (algo) {
    case StreamAlgorithm.chacha20:
      return 'ChaCha20';
    case StreamAlgorithm.chacha20_8:
      return 'ChaCha20/8';
    case StreamAlgorithm.chacha20_12:
      return 'ChaCha20/12';
    case StreamAlgorithm.salsa20:
      return 'Salsa20';
    case StreamAlgorithm.salsa20_8:
      return 'Salsa20/8';
    case StreamAlgorithm.salsa20_12:
      return 'Salsa20/12';
  }
  throw ArgumentError('');
}
