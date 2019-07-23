// TODO: Put public facing types in this file.
import 'dart:core';
import 'dart:core' as core;
import 'dart:math';
import 'dart:convert';
import 'package:encrypt/encrypt.dart';
import 'package:crypto/crypto.dart';

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
  HashCrypt ([core.String inType = 'sha256']) {
    type = inType;
  }
  core.String hash (core.String input) {
    var bytes = utf8.encode(input);
    Digest digest;
    if (type == 'sha1') {
      digest = sha1.convert(bytes);
    }
    else if (type == 'sha256') {
      digest = sha256.convert(bytes);
    }
    else if (type == 'md5') {
      digest = md5.convert(bytes);
    }
    return digest.bytes.toString();
  }
  core.String hashHMAC (core.String input, core.String key) {
    var listkey = utf8.encode(key);
    var bytes = utf8.encode(input);
    
    var hmac;
    if (type == 'sha256') {
      hmac = new Hmac(sha256, listkey);
    }
    if (type == 'sha1') {
      hmac = new Hmac(sha1, listkey);
    }
    if (type == 'md5') {
      hmac = new Hmac(md5, listkey);
    }
    var digest = hmac.convert(bytes);
    return digest.bytes.toString();

  }
}

