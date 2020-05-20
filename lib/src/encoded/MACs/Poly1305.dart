import 'dart:typed_data';

import 'package:meta/meta.dart';

import '../../../PointyCastleN/api.dart';
import '../../../PointyCastleN/export.dart' as exp;
import '../../steel_crypt_base.dart';

class Poly1305 {
  KeyParameter _listkey;
  ModeAES _algorithm;

  Poly1305(Uint8List key, ModeAES algo) {
    _listkey = KeyParameter(key);
    _algorithm = algo;
  }

  Uint8List process(Uint8List input, {@required Uint8List iv}) {
    final _tmp = exp.Poly1305.aes(BlockCipher('AES/' + _parseAES(_algorithm)));
    _tmp.init(exp.ParametersWithIV<KeyParameter>(_listkey, iv));
    var val = _tmp.process(Uint8List.fromList(input));
    return val;
  }

  bool check(Uint8List plain, Uint8List processed, {@required Uint8List iv}) {
    var newhash = process(plain, iv: iv);
    return newhash == processed;
  }

  String _parseAES(ModeAES mode) {
    switch (mode) {
      case ModeAES.cfb64:
        return 'CFB-64';
      case ModeAES.ofb64:
        return 'OFB-64';
      case ModeAES.ecb:
        return 'ECB';
      case ModeAES.ctr:
        return 'CTR';
      case ModeAES.cbc:
        return 'CBC';
      case ModeAES.gcm:
        return 'GCM';
      case ModeAES.gctr:
        return 'GCTR';
      case ModeAES.sic:
        return 'SIC';
    }
    throw ArgumentError('invalid mode (internal, file an issue!)');
  }
}
