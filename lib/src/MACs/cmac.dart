import 'dart:typed_data';

import 'package:pointycastle/api.dart';
import 'package:pointycastle/export.dart';

class CMAC {
  Uint8List _key;

  CMAC(Uint8List key) {
    if (key.length != 16) {
      throw ArgumentError(
          'Incorrect key length. Expected: length = 16. Got: length = ${key.length}.');
    }
    _key = key;
  }

  Uint8List process(Uint8List input) {
    var cipher = AESFastEngine();
    final _tmp = CMac(cipher, cipher.blockSize)..init(KeyParameter(_key));
    var val = _tmp.process(input);
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
