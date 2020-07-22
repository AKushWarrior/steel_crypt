import 'dart:typed_data';

import 'package:meta/meta.dart';

import 'package:pc_steelcrypt/api.dart';
import 'package:pc_steelcrypt/export.dart' as exp;

class Poly1305 {
  KeyParameter _listkey;

  Poly1305(Uint8List key) {
    _listkey = KeyParameter(key);
  }

  Uint8List process(Uint8List input, {@required Uint8List iv}) {
    final _tmp = exp.Poly1305.withCipher(BlockCipher('AES'));
    _tmp.init(exp.ParametersWithIV<KeyParameter>(_listkey, iv));
    var val = _tmp.process(input);
    return val;
  }

  bool check(Uint8List plain, Uint8List processed, {@required Uint8List iv}) {
    var newhash = process(plain, iv: iv);
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
