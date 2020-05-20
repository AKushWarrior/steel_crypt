import 'dart:typed_data';

import 'package:hex/hex.dart';
import 'package:steel_crypt/PointyCastleN/stream/isaac.dart';

import '../api.dart';
import 'chacha20.dart';

void main() {
  chaChaTest();
  isaacTest();
}

// Test #1: ChaCha20
void chaChaTest() {
  var chaChaEngine = ChaCha20Engine();

  var chaChaParams = ParametersWithIV(
      KeyParameter(Uint8List.fromList(HEX.decode(
          '0000000000000000000000000000000000000000000000000000000000000000'))),
      Uint8List.fromList(HEX.decode('0000000000000000')));

  chaChaEngine.init(true, chaChaParams);
  var keyStream = Uint8List(64);

  chaChaEngine.generateKeyStream(keyStream);

  assert(HEX.encode(keyStream).startsWith(
      '76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669'));
}

// Test #2: ISAAC
void isaacTest() {
  var engine = ISAACEngine();

  var out = HEX
      .decode('de3b3f3c19e0629c1fc8b7836695d523e7804edd86ff7ce9b106f52caebae9d9'
          '72f845d49ce17d7da44e49bae954aac0d0b1284b98a88eec1524fb6bc91a16b5'
          '1192ac5334131446ac2442de9ff3d5867b9b9148881ee30a6e87dd88e5d1f7cd'
          '98db31ff36f70d9850cfefaef42abb00ecc39ed308bf4b8030cdc2b6b7e42f0e'
          '908030dd282f96edacc888b3a986e109c129998f89baa1b5da8970b07a6ab012'
          'f10264f23c315c9c8e0c164955c68517b6a4f982b2626db70787f869ac6d551b'
          'e34931627c7058e965c502e18d2cd370e6db3b70d947d61aa9717cf8394f48c6'
          '3c796f3a154950846badb28b70d982f29bc670254e3e5e0f8e36b0a5f6da0a04'
          '6b235ed6a42988c012bde74d879fa8eb5d59f5f40ed5e76601c9847b3edb2690');

  var inp = Uint8List.fromList(List.filled(out.length, 0));
  var enc = Uint8List(out.length);

  var grainParams = KeyParameter(Uint8List.fromList(HEX.decode('ffffffff')));

  engine.init(true, grainParams);
  engine.processBytes(inp, 0, inp.length, enc, 0);

  print('My output: (${enc.length} chars) $enc');
  print('Real output: (${enc.length} chars) $out');
  print(enc == out);
}
