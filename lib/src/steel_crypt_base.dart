// TODO: Put public facing types in this file.
import 'dart:core';
import 'dart:core' as core;
import 'dart:math';
import 'dart:convert';
import 'package:encrypt/encrypt.dart';
import 'package:pointycastle/pointycastle.dart';

class Crypt {
  core.String type;
  core.String key32;
  Encrypter encrypter;

  Crypt (core.String inkey32, [core.String intype = "AES"]) {
    type = intype;
    key32 = inkey32;
    if (type == 'AES') {
      encrypter = Encrypter(AES(Key.fromUtf8(key32)));
    }
    else if (type == 'Salsa20') {
      encrypter = Encrypter(Salsa20(Key.fromUtf8(key32)));
    }
  } //create 'Vault', serves as encrypter/decrypter

  core.String encrypt (core.String input) {
    var crypted = encrypter.encrypt(input);
    return crypted.base64;
  } //encrypt and return in base 64

  core.String decrypt (core.String encrypted) {
    return encrypter.decrypt64(encrypted);
  } //decrypt base 64 and return original


}

class CryptKey {
  core.String key;
  var random = Random.secure();

  String genKey ([int length = 32]) {
    var values = List<int>.generate(32, (i) => random.nextInt(256));
    return base64Url.encode(values);
  } //gen cryptographically-secure, random key; defaults to length 32
}

class HashCrypt {
  core.String type;
  Digest hasher;
  HashCrypt ([core.String inType = 'SHA-3']) {
    type = inType;
    hasher = new Digest(inType);
  }
  core.String hash (core.String input) {
    var x = AsciiCodec();
    var list = x.encode(input);
    var fin = x.decode(hasher.process(list));
    hasher.reset();
    return fin;
  }
}

