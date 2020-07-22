import 'dart:typed_data';

import 'package:pc_steelcrypt/api.dart';
import 'package:pc_steelcrypt/export.dart';
import '../enum.dart';

class HMAC {
  KeyParameter _listkey;
  HmacHash _algorithm;

  HMAC(Uint8List key, HmacHash algo) {
    _listkey = KeyParameter(key);
    _algorithm = algo;
  }

  Uint8List process(Uint8List input) {
    final _tmp = parsePBKDF2(_algorithm)..init(_listkey);
    var val = _tmp.process(Uint8List.fromList(input));
    return val;
  }

  bool check(Uint8List plain, Uint8List processed) {
    var newhash = process(plain);
    if (newhash.length != processed.length) {
      return false;
    }
    var i = 0;
    for (var elem in newhash) {
      if (elem != processed[i]) {
        return false;
      }
      i++;
    }
    return true;
  }
}
