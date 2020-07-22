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
  HmacHash algorithm;
  dynamic _mac;

  MacCryptRaw(
      {@required Uint8List key, @required MacType type, HmacHash algorithm}) {
    _type = type;

    if (_type == MacType.HMAC) {
      _mac = HMAC(key, algorithm);
    } else if (_type == MacType.Poly1305) {
      _mac = poly.Poly1305(key);
    } else {
      _mac = CMAC(key);
    }
  }

  MacCryptRaw.CMAC({@required Uint8List key}) {
    _type = MacType.CMAC;
    _mac = CMAC(key);
  }

  MacCryptRaw.HMAC({@required Uint8List key, @required HmacHash mode}) {
    _type = MacType.CMAC;
    _mac = HMAC(key, algorithm);
  }

  MacCryptRaw.Poly1305({@required Uint8List key}) {
    _type = MacType.Poly1305;
    _mac = poly.Poly1305(key);
  }

  ///Process and hash string.
  Uint8List process({@required Uint8List inp, @required Uint8List iv}) {
    if (_type == MacType.Poly1305)
      return _mac.process(inp, iv: iv) as Uint8List;
    return _mac.process(inp) as Uint8List;
  }

  ///Check if plaintext matches previously hashed text
  bool check(
      {@required Uint8List plain,
      @required Uint8List hashed,
      @required Uint8List iv}) {
    if (_type == MacType.Poly1305) {
      return _mac.check(plain, hashed, iv: iv) as bool;
    }
    return _mac.check(plain, hashed) as bool;
  }
}
