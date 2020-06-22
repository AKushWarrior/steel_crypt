//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2020 Aditya Kishore

//ignore_for_file: non_constant_identifier_names

part of '../steel_crypt_base.dart';

///Class containing hashing for Message Authentication Codes.
///
/// This version of MacCrypt is raw, meaning that it expects all inputs to be
/// Uint8List, and returns Uint8Lists.
class MacCryptRaw {
  MacType _type;
  Union2<ModeAES, HmacHash> algorithm;
  dynamic _mac;

  MacCryptRaw(
      {@required Uint8List key,
      @required MacType type,
      @required Union2<ModeAES, HmacHash> algorithm}) {
    _type = type;

    if (_type == MacType.HMAC) {
      _mac = HMAC(key, algorithm.value as HmacHash);
    } else if (_type == MacType.Poly1305) {
      _mac = poly.Poly1305(key, algorithm.value as ModeAES);
    } else {
      _mac = CMAC(key, algorithm.value as ModeAES);
    }
  }

  MacCryptRaw.CMAC({@required Uint8List key, @required ModeAES algorithm}) {
    _type = MacType.CMAC;
    _mac = CMAC(key, algorithm);
  }

  MacCryptRaw.HMAC({@required Uint8List key, @required HmacHash algorithm}) {
    _type = MacType.CMAC;
    _mac = HMAC(key, algorithm);
  }

  MacCryptRaw.Poly1305({@required Uint8List key, @required ModeAES algorithm}) {
    _type = MacType.Poly1305;
    _mac = poly.Poly1305(key, algorithm);
  }

  ///Process and hash string.
  String process(Uint8List input, {Uint8List iv}) {
    if (_type == MacType.Poly1305) return _mac.process(input, iv: iv) as String;
    return _mac.process(input) as String;
  }

  ///Check if plaintext matches previously hashed text
  bool check(Uint8List plaintext,
      {@required Uint8List hashtext, Uint8List iv}) {
    if (_type == MacType.Poly1305) {
      return _mac.check(plaintext, hashtext, iv: iv) as bool;
    }
    return _mac.check(plaintext, hashtext) as bool;
  }
}
