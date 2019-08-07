//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2019 Aditya Kishore

part of 'steel_crypt_base.dart';

///RSA asymmetric encryption machine
class RsaCrypt {

  ///Pair of private keys
  static var pair;

  ///Construct with keys
  RsaCrypt ()  {
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
    secureRandom.seed(KeyParameter(Uint8List.fromList(seeds)));
    return secureRandom;
  }

  ///create RSA keypair given SecureRandom
  static AsymmetricKeyPair<PublicKey, PrivateKey> getRsaKeyPair(
      SecureRandom secureRandom) {
    var rsapars = RSAKeyGeneratorParameters(BigInt.from(65537), 2048, 5);
    var params = ParametersWithRandom(rsapars, secureRandom);
    var keyGenerator = RSAKeyGenerator();
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
