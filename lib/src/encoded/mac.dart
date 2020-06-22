//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2020 Aditya Kishore

//ignore_for_file: non_constant_identifier_names

part of '../steel_crypt_base.dart';

///Class containing hashing for Message Authentication Codes.
///
/// This version of MacCrypt is encoded, meaning that it expects keys and IVs to be
/// base64, and returns base64 encoded Strings. Plaintext should be UTF-8 valid.
/// For more flexibility, MacCryptRaw is recommended.
class MacCrypt {
  MacType _type;
  Union2<ModeAES, HmacHash> algorithm;
  dynamic _mac;

  MacCrypt(
      {@required String key,
      @required MacType type,
      @required Union2<ModeAES, HmacHash> algorithm}) {
    _type = type;

    var ukey = base64Decode(key);

    if (_type == MacType.HMAC) {
      _mac = HMAC(ukey, algorithm.value as HmacHash);
    } else if (_type == MacType.Poly1305) {
      _mac = poly.Poly1305(ukey, algorithm.value as ModeAES);
    } else {
      _mac = CMAC(ukey, algorithm.value as ModeAES);
    }
  }

  MacCrypt.CMAC({@required String key, @required ModeAES algorithm}) {
    var ukey = base64Decode(key);
    _type = MacType.CMAC;
    _mac = CMAC(ukey, algorithm);
  }

  MacCrypt.HMAC({@required String key, @required HmacHash algorithm}) {
    var ukey = base64Decode(key);
    _type = MacType.CMAC;
    _mac = HMAC(ukey, algorithm);
  }

  MacCrypt.Poly1305({@required String key, @required ModeAES algorithm}) {
    var ukey = base64Decode(key);
    _type = MacType.Poly1305;
    _mac = poly.Poly1305(ukey, algorithm);
  }

  ///Process and hash string.
  String process(String input, {String iv}) {
    if (_type == MacType.Poly1305) {
      return base64.encode(
          _mac.process(utf8.encode(input), iv: base64.decode(iv)) as List<int>);
    }
    return base64.encode(_mac.process(utf8.encode(input)) as List<int>);
  }

  ///Check if plaintext matches previously hashed text
  bool check(String plaintext, {@required String hashtext, String iv}) {
    if (_type == MacType.Poly1305) {
      return _mac.check(utf8.encode(plaintext), base64.decode(hashtext),
          iv: iv) as bool;
    }
    return _mac.check(utf8.encode(plaintext), base64.decode(hashtext))
    as bool;
  }
}

enum MacType { CMAC, HMAC, Poly1305 }

extension Mac on ModeAES {
  Union2<ModeAES, HmacHash> asCMAC() {
    return asFirst();
  }

  Union2<ModeAES, HmacHash> asPoly1305() {
    return asFirst();
  }
}

extension Mac2 on HmacHash {
  Union2<ModeAES, HmacHash> asHMAC() {
    return asSecond();
  }
}
