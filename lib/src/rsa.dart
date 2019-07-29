import 'dart:core';
import 'dart:core' as core;
import 'dart:typed_data';
import 'dart:convert';
import 'dart:math';
import 'package:pointycastle/export.dart';
import 'package:pointycastle/api.dart';


///RSA asymmetric encryption machine
class rsa {

  ///Pair of private keys
  var pair;

  ///Construct with keys
  rsa ()  {
    pair = getRsaKeyPair(getSecureRandom());
  }

  ///access private key
  PrivateKey get privKey {
    return pair.privateKey;
  }

  ///access public key
  PublicKey get pubKey {
    return pair.publicKey;
  }

  ///create Random param for RSA keypair
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

  ///create RSA keypair given SecureRandom
  static AsymmetricKeyPair<PublicKey, PrivateKey> getRsaKeyPair(
      SecureRandom secureRandom) {
    var rsapars = new RSAKeyGeneratorParameters(BigInt.from(65537), 2048, 5);
    var params = new ParametersWithRandom(rsapars, secureRandom);
    var keyGenerator = new RSAKeyGenerator();
    keyGenerator.init(params);
    return keyGenerator.generateKeyPair();
  }

  ///encrypt using RSA
  String encrypt(String text, RSAPublicKey pubKey) {
    var cipher = OAEPEncoding(RSAEngine());
    cipher.init(true, PublicKeyParameter<RSAPublicKey>(pubKey));
    Uint8List output1 = cipher.process(utf8.encode(text));
    return base64Encode(output1);
  }

  ///decrypt using RSA
  String decrypt(String input, RSAPrivateKey privateKey) {
    var cipher = OAEPEncoding(RSAEngine());
    cipher.init(false, PrivateKeyParameter<RSAPrivateKey>(privateKey));
    Uint8List output = cipher.process(base64Decode(input));
    return utf8.decode(output);
  }
}
