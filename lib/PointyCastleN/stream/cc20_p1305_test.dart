// ignore_for_file: directives_ordering

import 'dart:typed_data';

import 'package:hex/hex.dart';
import 'package:steel_crypt/PointyCastleN/src/utils.dart';

import '../api.dart';
import '../macs/poly1305.dart';
import 'chacha20_poly1305.dart';
import 'chacha7539.dart';

void main() {
  chaChaTest();
}

// Test #1: ChaCha20-Poly1305
void chaChaTest() {
  var K = Uint8List.fromList(HEX.decode(
      '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'));
  var P = Uint8List.fromList(HEX.decode(
      '4c616469657320616e642047656e746c656d656e206f66207468652063'
      '6c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6'
      'c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20'
      '776f756c642062652069742e'));
  var A = Uint8List.fromList(HEX.decode('50515253c0c1c2c3c4c5c6c7'));
  var N = Uint8List.fromList(HEX.decode('070000004041424344454647'));
  var C = Uint8List.fromList(HEX.decode(
      'd31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a73'
      '6ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692'
      'ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4'
      'b7a9de576d26586cec64b6116'));
  var T = Uint8List.fromList(HEX.decode('1ae10b594f09e26a7e902ecbd0600691'));

  var parameters = AEADParameters(KeyParameter(K), T.length * 8, N, A);
  var chaChaEngine = ChaCha20Poly1305(ChaCha7539Engine(), Poly1305())
    ..init(true, parameters);
  var chaChaEngineDecrypt = ChaCha20Poly1305(ChaCha7539Engine(), Poly1305())
    ..init(false, parameters);
  var enc = Uint8List(chaChaEngine.getOutputSize(P.length));
  var len = chaChaEngine.processBytes(P, 0, P.length, enc, 0);
  len += chaChaEngine.doFinal(enc, len);
  if (enc.length != len) {
    print('encryption reported incorrect length');
  } else {
    print('correct encryption length');
  }

  var mac = chaChaEngine.mac;
  var data = Uint8List(P.length);
  arrayCopy(enc, 0, data, 0, data.length);
  var tail = Uint8List(enc.length - P.length);
  arrayCopy(enc, P.length, tail, 0, tail.length);

  try {
    for (var i = 0; i < data.length; i++) {
      if (data[i] != C[i]) {
        throw StateError('');
      }
    }
    print('correct encrypt');
  } catch (err) {
    print('incorrect encrypt');
  }

  try {
    for (var i = 0; i < mac.length; i++) {
      if (T[i] != mac[i]) {
        throw StateError('');
      }
    }
    print('correct mac');
  } catch (err) {
    print('incorrect mac');
  }

  var dec = Uint8List(chaChaEngineDecrypt.getOutputSize(enc.length));
  len = chaChaEngineDecrypt.processBytes(enc, 0, enc.length, dec, 0);
  len += chaChaEngineDecrypt.doFinal(dec, len);
  mac = chaChaEngineDecrypt.mac;

  data = Uint8List(C.length);
  arrayCopy(dec, 0, data, 0, data.length);

  try {
    for (var i = 0; i < data.length; i++) {
      if (P[i] != data[i]) {
        throw StateError('');
      }
    }
    print('correct decrypt');
  } catch (err) {
    print('incorrect decrypt');
  }
}
