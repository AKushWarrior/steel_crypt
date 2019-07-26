// TODO: Put public facing types in this file.
import 'dart:core';
import 'dart:core' as core;
import 'dart:math';
import 'dart:convert';
import 'package:encrypt/encrypt.dart';
import 'package:steel_crypt/src/rsa.dart';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/export.dart';
import 'rsa.dart';

class SymCrypt {
  core.String type;
  core.String key32;
  Encrypter encrypter;

  SymCrypt (core.String inkey32, [core.String intype = "AES"]) {
    type = intype;
    key32 = inkey32;
    if (type == 'AES') {
      encrypter = Encrypter(AES(Key.fromBase64(key32), mode: AESMode.cbc));
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

class RsaCrypt extends rsa {
  RsaCrypt() : super();
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
  HashCrypt ([core.String inType = 'SHA-3/512']) {
    type = inType;
  }
  core.String hash (core.String input) {
    var bytes = Base64Codec().decode(input);
    Digest digest;
    digest = Digest(type);
    var value = digest.process(bytes);
    return Base64Codec().encode(value);
  }
  core.String hashHMAC (core.String input, core.String key) {
    var listkey = Base64Codec().decode(key);
    var bytes = Base64Codec().decode(input);
    var params = KeyParameter(listkey);
    final _tmp = HMac(Digest(type), 128)..init(params);
    var val = _tmp.process(bytes);
    return Base64Codec().encode(val);
  }
  bool checkpass (core.String plain, core.String hashed) {
    var newhash = hash(plain);
    return newhash == hashed;
  }
  bool checkpassHMAC (core.String plain, core.String hashed, core.String key) {
    var newhash = hashHMAC(plain, key);
    return newhash == hashed;
  }
}

