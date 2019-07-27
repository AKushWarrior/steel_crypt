import 'dart:core';
import 'dart:core' as core;
import 'dart:typed_data';
import 'dart:convert';
import 'dart:math';
import 'package:pointycastle/export.dart';
import 'package:pointycastle/api.dart';



class rsa {
  var pair;

  rsa ()  {
    pair = getRsaKeyPair(getSecureRandom());
  }

  PrivateKey get privKey {
    return pair.privateKey;
  }

  PublicKey get pubKey {
    return pair.publicKey;
  }

  static SecureRandom getSecureRandom() {
    var secureRandom = FortunaRandom();
    var random = Random.secure();
    List<int> seeds = [];
    for (int i = 0; i < 32; i++) {
      seeds.add(random.nextInt(255));
    }
    secureRandom.seed(new KeyParameter(new Uint8List.fromList(seeds)));
    return secureRandom;
  }

  static AsymmetricKeyPair<PublicKey, PrivateKey> getRsaKeyPair(
      SecureRandom secureRandom) {
    var rsapars = new RSAKeyGeneratorParameters(BigInt.from(65537), 2048, 5);
    var params = new ParametersWithRandom(rsapars, secureRandom);
    var keyGenerator = new RSAKeyGenerator();
    keyGenerator.init(params);
    return keyGenerator.generateKeyPair();
  }

  String encrypt(String text, RSAPublicKey pubKey) {
    var cipher = OAEPEncoding(RSAEngine());
    cipher.init(true, PublicKeyParameter<RSAPublicKey>(pubKey));
    Uint8List output1 = cipher.process(utf8.encode(text));
    return base64Encode(output1);
  }

  String decrypt(String input, RSAPrivateKey privateKey) {
    var cipher = OAEPEncoding(RSAEngine());
    cipher.init(false, PrivateKeyParameter<RSAPrivateKey>(privateKey));
    Uint8List output = cipher.process(base64Decode(input));
    return utf8.decode(output);
  }
}
