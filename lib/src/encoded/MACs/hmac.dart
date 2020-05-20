import 'dart:typed_data';

import '../../../PointyCastleN/api.dart';
import '../../../PointyCastleN/export.dart';
import '../../steel_crypt_base.dart';

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
    return newhash == processed;
  }
}
