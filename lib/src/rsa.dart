import 'dart:core';
import 'dart:core' as core;
import 'dart:typed_data';
import 'dart:convert';
import 'package:crypto_keys/crypto_keys.dart';

class rsa {
  var pair;
  var encrypter;

  rsa () {
    pair = KeyPair.generateSymmetric(128);
    encrypter = pair.publicKey.createEncrypter(algorithms.encryption.aes.gcm);
  }
  EncryptionResult encrypt (core.String input, String authText) {
    EncryptionResult v = encrypter.encrypt(
        new Uint8List.fromList(input.codeUnits),
        additionalAuthenticatedData: new Uint8List.fromList(authText.codeUnits)
    );
    return v;
  } //encrypt (with iv) and return in base 64

  core.String decrypt (EncryptionResult encrypted) {
    var decrypter = pair.privateKey.createEncrypter(algorithms.encryption.aes.gcm);
    var decrypted = decrypter.decrypt(encrypted);
    return String.fromCharCodes(decrypted);
  }
  String getString (EncryptionResult encrypted) {
    return base64.encode(encrypted.data);
  }
}
