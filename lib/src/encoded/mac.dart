//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2021 Aditya Kishore

//ignore_for_file: non_constant_identifier_names

part of '../steel_crypt_base.dart';

///Class containing hashing for Message Authentication Codes.
///
/// This version of MacCrypt is encoded, meaning that it expects keys and IVs to be
/// base64, and returns base64 encoded Strings. Plaintext should be UTF-8 valid.
/// For more flexibility, MacCryptRaw is recommended.
class MacCrypt {
  MacType _type;
  HmacHash? algorithm;
  dynamic _mac;

  MacCrypt({required String key, required MacType type, this.algorithm}) : _type = type {
    var ukey = base64Decode(key);

    if (_type == MacType.HMAC) {
      _mac = HMAC(ukey, algorithm!);
    } else if (_type == MacType.Poly1305) {
      _mac = poly.Poly1305(ukey);
    } else {
      _mac = CMAC(ukey);
    }
  }

  MacCrypt.CMAC({required String key}) : _type = MacType.CMAC {
    var ukey = base64Decode(key);
    _mac = CMAC(ukey);
  }

  MacCrypt.HMAC({required String key, required HmacHash algo}) : _type = MacType.HMAC {
    var ukey = base64Decode(key);
    _mac = HMAC(ukey, algorithm!);
  }

  MacCrypt.Poly1305({required String key}) : _type = MacType.Poly1305 {
    var ukey = base64Decode(key);
    _mac = poly.Poly1305(ukey);
  }

  ///Process and hash string.
  String process({required String inp, String? iv}) {
    if (_type == MacType.Poly1305) {
      return base64.encode(
          _mac.process(utf8.encode(inp), iv: base64.decode(iv!)) as List<int>);
    }
    return base64.encode(_mac.process(utf8.encode(inp)) as List<int>);
  }

  ///Check if plaintext matches previously hashed text
  bool check({required String plain, required String hashed, String? iv}) {
    if (_type == MacType.Poly1305) {
      return _mac.check(utf8.encode(plain), base64.decode(hashed), iv: iv)
          as bool;
    }
    return _mac.check(utf8.encode(plain), base64.decode(hashed)) as bool;
  }
}
