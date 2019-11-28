//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2019 Aditya Kishore

part of 'steel_crypt_base.dart';

///Class containing hashing for Message Authentication Codes.
class MacCrypt {
  String _key32;
  String _algorithm;
  String _type;
  var _mac;

  MacCrypt(String key, [String inType = 'CMAC', String algo = 'gcm']) {
    _key32 = key;
    _algorithm = algo;
    _type = inType;
    if (_type == 'HMAC') {
      _mac = _HMAC(key, algo);
    } else if (_type == 'CMAC') {
      _mac = _CMAC(key, algo);
    }
  }

  ///Process and hash string
  String process(String input) {
    return _mac.process(input);
  }

  ///Check if plaintext matches previously hashed text
  bool check(String plain, String processed) {
    return _mac.check(plain, processed);
  }
}

class _HMAC {
  KeyParameter _listkey;
  String _algorithm;

  _HMAC(String key, [String algo = 'SHA-3/256']) {
    var _inter = utf8.encode(key).sublist(0, 32);
    _listkey = KeyParameter(_inter);
    _algorithm = algo;
  }

  String process(core.String input) {
    var bytes = utf8.encode(input);
    final _tmp = HMac(Digest(_algorithm), 128)
      ..init(_listkey);
    var val = _tmp.process(bytes);
    return base64.encode(val);
  }

  bool check(String plain, String processed) {
    var newhash = process(plain);
    return newhash == processed;
  }
}

class _CMAC {
  KeyParameter _listkey;
  String _algorithm;

  _CMAC(String key, algo) {
    var _inter = utf8.encode(key).sublist(0, 32);
    _listkey = KeyParameter(_inter);
    _algorithm = algo;
  }

  String process(String input) {
    var bytes = utf8.encode(input);
    final _tmp = CMac(BlockCipher('AES/' + _algorithm.toUpperCase()), 64)
      ..init(_listkey);
    var val = _tmp.process(bytes);
    return base64.encode(val);
  }

  bool check(String plain, String processed) {
    var newhash = process(plain);
    return newhash == processed;
  }
}
