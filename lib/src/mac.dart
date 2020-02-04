//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2019 Aditya Kishore

part of 'steel_crypt_base.dart';

///Class containing hashing for Message Authentication Codes.
class MacCrypt {
  String _type;
  dynamic _mac;

  MacCrypt(String key, [String inType = 'CMAC', String algo = 'gcm']) {
    _type = inType;
    if (_type == 'HMAC') {
      _mac = _HMAC(key, algo);
    } else if (_type == 'CMAC') {
      _mac = _CMAC(key, algo);
    }
  }

  ///Process and hash string
  String process(String input) {
    return _mac.process(input) as String;
  }

  ///Check if plaintext matches previously hashed text
  bool check(String plain, String processed) {
    return _mac.check(plain, processed) as bool;
  }
}

class _HMAC {
  KeyParameter _listkey;
  String _algorithm;

  _HMAC(String key, String algo) {
    _listkey = KeyParameter(Uint8List.fromList(key.codeUnits));
    _algorithm = algo;
  }

  String process(core.String input) {
    var bytes = utf8.encode(input);
    final _tmp = HMac(Digest(_algorithm), 128)
      ..init(_listkey);
    var val = _tmp.process(Uint8List.fromList(bytes));
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
    _listkey = KeyParameter(Uint8List.fromList(key.codeUnits));
    _algorithm = algo as String;
  }

  String process(String input) {
    var bytes = utf8.encode(input);
    final _tmp = CMac(BlockCipher('AES/' + _algorithm.toUpperCase()), 64)
      ..init(_listkey);
    var val = _tmp.process(Uint8List.fromList(bytes));
    return base64.encode(val);
  }

  bool check(String plain, String processed) {
    var newhash = process(plain);
    return newhash == processed;
  }
}
