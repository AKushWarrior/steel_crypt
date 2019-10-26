//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2019 Aditya Kishore

part of 'steel_crypt_base.dart';

///Class containing Message Authentication codes
class MacCrypt {
  String _key32;
  String _algorithm = 'SHA-3/256';
  String _type = 'HMAC';
  _HMAC _mac1;
  _CMAC _mac2;

  MacCrypt(String key, [String inType, String algo]) {
    _key32 = key;
    _algorithm = algo;
    _type = inType;
    if (_type == 'HMAC') {
      _mac1 = _HMAC(key, algo);
    } else if (_type == 'CMAC') {
      _mac2 = _CMAC(key, algo);
    }
  }

  ///Process and hash string
  String process(String input) {
    if (_type == "HMAC") {
      return _mac1.process(input);
    } else if (_type == 'CMAC') {
      return _mac2.process(input);
    }
    return "";
  }

  ///Check if plaintext matches previously hashed text
  bool check(String plain, String processed) {
    if (_type == 'HMAC') {
      return _mac1.check(plain, processed);
    }
    return _mac2.check(plain, processed);
  }
}

class _HMAC {
  KeyParameter _listkey;
  String _algorithm;
  static List<String> _pads = ['aWM'];

  _HMAC(String key, [String algo = 'SHA-3/256']) {
    var _inter = base64.decode(key);
    _listkey = KeyParameter(_inter);
    _algorithm = algo;
  }

  String process(core.String input) {
    var bytes;
    if (input.length % 4 == 0) {
      bytes = Base64Codec().decode(input);
    } else {
      var advinput = input;
      advinput = input + _pads[0];
      advinput = advinput.substring(0, advinput.length - advinput.length % 4);
      bytes = Base64Codec().decode(advinput);
    }
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
  static List<String> _pads = ['Xcv'];
  String _algorithm;

  _CMAC(String key, [algo = 'cfb-64']) {
    var _inter = base64.decode(key);
    _listkey = KeyParameter(_inter);
    _algorithm = algo;
  }

  String process(core.String input) {
    var bytes;
    if (input.length % 4 == 0) {
      bytes = Base64Codec().decode(input);
    } else {
      var advinput = input;
      advinput = input + _pads[0];
      advinput = advinput.substring(0, advinput.length - advinput.length % 4);
      bytes = Base64Codec().decode(advinput);
    }
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
