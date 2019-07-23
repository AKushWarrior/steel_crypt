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
      encrypter = Encrypter(AES(Key.fromBase64(key32)));
    }
    else if (type == 'Salsa20') {
      encrypter = Encrypter(Salsa20(Key.fromBase64(key32)));
    }
  } //create 'Vault', serves as encrypter/decrypter

  core.String encrypt (core.String input, core.String iv) {
    Encrypted crypted = encrypter.encrypt(input, iv:IV.fromBase64(iv));
    return crypted.base64;
  } //encrypt (with iv) and return in base 64

  core.String decrypt (core.String encrypted, core.String iv) {
    return encrypter.decrypt64(encrypted, iv: IV.fromBase64(iv));
  } //decrypt base 64 (with iv) and return original


}

class CryptKey {
  var random = Random.secure();

  String genKey ([int length = 32]) {
    var values = List<int>.generate(32, (i) => random.nextInt(256));
    return base64Url.encode(values);
  }

  String genIV ([int length = 16]) {
    var values = List<int>.generate(length, (i) => random.nextInt(256));
    return base64Url.encode(values);
  }//gen cryptographically-secure, random key; defaults to length 32
}

class HashCrypt {
  core.String type;
  HashCrypt ([core.String inType = 'sha256']) {
    type = inType;
  }
  core.String hash (core.String input) {
    var bytes = AsciiCodec().encode(input);
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
    return '$digest';
  }
  core.String hashHMAC (core.String input, core.String key) {
    var listkey = AsciiCodec().encode(key);
    var bytes = AsciiCodec().encode(input);
    
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
    return '$digest';

  }
}

