//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2020 Aditya Kishore

part of 'steel_crypt_base.dart';

@deprecated

/// RSA asymmetric encryption machine. This is deprecated and not maintained, use
/// https://pub.dev/packages/crypton instead.
class RsaCrypt {
  ///Pair of asymmetric keys.
  static AsymmetricKeyPair _pairInstance;

  ///Get existing keypair instance or generate a new one.
  static AsymmetricKeyPair get _pair {
    _pairInstance ??= _generateKeyPair();
    return _pairInstance;
  }

  ///Constant Constructor.
  const RsaCrypt();

  ///Access private key.
  RSAPrivateKey get randPrivKey {
    return _pair.privateKey as RSAPrivateKey;
  }

  ///Access public key.
  RSAPublicKey get randPubKey {
    return _pair.publicKey as RSAPublicKey;
  }

  ///create Random param for RSA keypair.
  static SecureRandom _getSecureRandom() {
    final secureRandom = FortunaRandom();
    final random = Random.secure();
    var seeds = List<int>.of([]);
    for (var i = 0; i < 32; i++) {
      seeds.add(random.nextInt(255));
    }
    secureRandom.seed(KeyParameter(Uint8List.fromList(seeds)));
    return secureRandom;
  }

  ///Create RSA keypair of specified length.
  static AsymmetricKeyPair<PublicKey, PrivateKey> _generateKeyPair(
      [int length = 2048]) {
    final rsapars = RSAKeyGeneratorParameters(BigInt.from(65537), length, 5);
    final params = ParametersWithRandom(rsapars, _getSecureRandom());
    final keyGenerator = RSAKeyGenerator();
    keyGenerator.init(params);
    return keyGenerator.generateKeyPair();
  }

  ///Encrypt using RSA.
  String encrypt(String text, RSAPublicKey pubKey) {
    final cipher = OAEPEncoding(RSAEngine());
    cipher.init(true, PublicKeyParameter<RSAPublicKey>(pubKey));
    final output1 = cipher.process(utf8.encode(text) as Uint8List);
    return base64Encode(output1);
  }

  ///Decrypt using RSA.
  String decrypt(String encrypted, RSAPrivateKey privateKey) {
    final cipher = OAEPEncoding(RSAEngine());
    cipher.init(false, PrivateKeyParameter<RSAPrivateKey>(privateKey));
    final output = cipher.process(base64Decode(encrypted));
    return utf8.decode(output);
  }
}

/// Class containing utils for translating RSA keys. This class uses the
/// PEM format.
class RsaUtils {
  ///Parse key from PEM file.
  static Future<T> parseKeyFromFile<T extends RSAAsymmetricKey>(
      String filename) async {
    final file = File(filename);
    final key = await file.readAsString();
    return _parse(key) as T;
  }

  ///Parse key from PEM string.
  static T parseKeyFromString<T extends RSAAsymmetricKey>(String pemString) {
    return _parse(pemString) as T;
  }

  ///Encode RSA key to a PEM string.
  static String encodeKeyToString(RSAAsymmetricKey key) {
    if (key is RSAPublicKey) {
      final algorithmSeq = ASN1Sequence();
      final algorithmAsn1Obj = ASN1Object.fromBytes(Uint8List.fromList(
          [0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0x1]));
      final paramsAsn1Obj =
      ASN1Object.fromBytes(Uint8List.fromList([0x5, 0x0]));
      algorithmSeq.add(algorithmAsn1Obj);
      algorithmSeq.add(paramsAsn1Obj);

      final publicKeySeq = ASN1Sequence();
      publicKeySeq.add(ASN1Integer(key.modulus));
      publicKeySeq.add(ASN1Integer(key.exponent));
      final publicKeySeqBitString =
      ASN1BitString(Uint8List.fromList(publicKeySeq.encodedBytes));

      final topLevelSeq = ASN1Sequence();
      topLevelSeq.add(algorithmSeq);
      topLevelSeq.add(publicKeySeqBitString);
      final dataBase64 = base64.encode(topLevelSeq.encodedBytes);

      return '-----BEGIN PUBLIC KEY-----\r\n$dataBase64\r\n-----END PUBLIC KEY-----';
    } else {
      final privateKey = key as RSAPrivateKey;
      final version = ASN1Integer(BigInt.from(0));

      final algorithmSeq = ASN1Sequence();
      final algorithmAsn1Obj = ASN1Object.fromBytes(Uint8List.fromList(
          [0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0x1]));
      final paramsAsn1Obj =
      ASN1Object.fromBytes(Uint8List.fromList([0x5, 0x0]));
      algorithmSeq.add(algorithmAsn1Obj);
      algorithmSeq.add(paramsAsn1Obj);

      final privateKeySeq = ASN1Sequence();
      final modulus = ASN1Integer(key.n);
      final publicExponent = ASN1Integer(BigInt.parse('65537'));
      final privateExponent = ASN1Integer(privateKey.d);
      final p = ASN1Integer(privateKey.p);
      final q = ASN1Integer(privateKey.q);
      final dP = privateKey.d % (privateKey.p - BigInt.from(1));
      final exp1 = ASN1Integer(dP);
      final dQ = privateKey.d % (privateKey.q - BigInt.from(1));
      final exp2 = ASN1Integer(dQ);
      final iQ = privateKey.q.modInverse(privateKey.p);
      final co = ASN1Integer(iQ);

      privateKeySeq.add(version);
      privateKeySeq.add(modulus);
      privateKeySeq.add(publicExponent);
      privateKeySeq.add(privateExponent);
      privateKeySeq.add(p);
      privateKeySeq.add(q);
      privateKeySeq.add(exp1);
      privateKeySeq.add(exp2);
      privateKeySeq.add(co);
      final publicKeySeqOctetString =
      ASN1OctetString(Uint8List.fromList(privateKeySeq.encodedBytes));

      final topLevelSeq = ASN1Sequence();
      topLevelSeq.add(version);
      topLevelSeq.add(algorithmSeq);
      topLevelSeq.add(publicKeySeqOctetString);
      final dataBase64 = base64.encode(topLevelSeq.encodedBytes);

      return '-----BEGIN PRIVATE KEY-----\r\n$dataBase64\r\n-----END PRIVATE KEY-----';
    }
  }

  static RSAAsymmetricKey _parse(String key) {
    final rows = key.split(RegExp(r'\r\n?|\n'));
    final header = rows.first;

    if (header == '-----BEGIN RSA PUBLIC KEY-----') {
      return _parsePublic(_parseSequence(rows));
    }

    if (header == '-----BEGIN PUBLIC KEY-----') {
      return _parsePublic(_pkcs8PublicSequence(_parseSequence(rows)));
    }

    if (header == '-----BEGIN RSA PRIVATE KEY-----') {
      return _parsePrivate(_parseSequence(rows));
    }

    if (header == '-----BEGIN PRIVATE KEY-----') {
      return _parsePrivate(_pkcs8PrivateSequence(_parseSequence(rows)));
    }

    throw FormatException('Unable to parse key, invalid format.', header);
  }

  static RSAAsymmetricKey _parsePublic(ASN1Sequence sequence) {
    final modulus = (sequence.elements[0] as ASN1Integer).valueAsBigInteger;
    final exponent = (sequence.elements[1] as ASN1Integer).valueAsBigInteger;

    return RSAPublicKey(modulus, exponent);
  }

  static RSAAsymmetricKey _parsePrivate(ASN1Sequence sequence) {
    final modulus = (sequence.elements[1] as ASN1Integer).valueAsBigInteger;
    final exponent = (sequence.elements[3] as ASN1Integer).valueAsBigInteger;
    final p = (sequence.elements[4] as ASN1Integer).valueAsBigInteger;
    final q = (sequence.elements[5] as ASN1Integer).valueAsBigInteger;

    return RSAPrivateKey(modulus, exponent, p, q);
  }

  static ASN1Sequence _parseSequence(List<String> rows) {
    final keyText = rows
        .skipWhile((row) => row.startsWith('-----BEGIN'))
        .takeWhile((row) => !row.startsWith('-----END'))
        .map((row) => row.trim())
        .join('');

    final keyBytes = Uint8List.fromList(base64.decode(keyText));
    final asn1Parser = ASN1Parser(keyBytes);

    return asn1Parser.nextObject() as ASN1Sequence;
  }

  static ASN1Sequence _pkcs8PublicSequence(ASN1Sequence sequence) {
    var bitString = sequence.elements[1];
    final bytes = bitString.valueBytes().sublist(1);
    final parser = ASN1Parser(Uint8List.fromList(bytes));

    return parser.nextObject() as ASN1Sequence;
  }

  static ASN1Sequence _pkcs8PrivateSequence(ASN1Sequence sequence) {
    var bitString = sequence.elements[2];
    final bytes = bitString.valueBytes();
    final parser = ASN1Parser(bytes);

    return parser.nextObject() as ASN1Sequence;
  }
}
