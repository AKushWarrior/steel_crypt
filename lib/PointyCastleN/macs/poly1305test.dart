import 'dart:typed_data';

import 'package:hex/hex.dart';
import 'package:steel_crypt/PointyCastleN/api.dart';

import '../block/aes_fast.dart';
import 'poly1305.dart';

Poly1305 poly = Poly1305.aes(AESFastEngine());

void main() {
  poly.init(ParametersWithIV(
      KeyParameter(Uint8List.fromList(HEX.decode(
          '0000000000000000000000000000000000000000000000000000000000000000'))),
      Uint8List.fromList(HEX.decode('00000000000000000000000000000000'))));

  var processed = poly.process(Uint8List.fromList(HEX.decode('')));

  assert(HEX.encode(processed) == '66e94bd4ef8a2c3b884cfa59ca342b2e');
}
