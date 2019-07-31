//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2019 Aditya Kishore

import 'dart:core';
import 'dart:core' as core;
import 'dart:math';
import 'dart:typed_data';
import 'dart:convert';
import 'package:encrypt/encrypt.dart';
import 'package:steel_crypt/src/rsa.dart';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/export.dart';
import 'rsa.dart';

///Create symmetric encryption machine (Crypt)
class SymCrypt {
  ///Type of algorithm
  static core.String type;

  ///Key for encryption
  static core.String key32;

  static var encrypter;

  ///Creates 'Crypt', serves as encrypter/decrypter of text
  SymCrypt (core.String inkey32, [core.String intype = "AES"]) {
    type = intype;
    key32 = inkey32;
    if (type == 'AES') {
      encrypter = Encrypter(AES(Key.fromBase64(key32), mode: AESMode.cbc));
    }
    else if (type == 'Salsa20') {
      encrypter = Encrypter(Salsa20(Key.fromBase64(key32)));
    }
  }

  ///Encrypt (with iv) and return in base 64
  core.String encrypt (core.String input, core.String iv) {
    Encrypted crypted = encrypter.encrypt(input, iv:IV.fromBase64(iv));
    return crypted.base64;
  }

  ///Decrypt base 64 (with iv) and return original
  core.String decrypt (core.String encrypted, core.String iv) {
    return encrypter.decrypt64(encrypted, iv: IV.fromBase64(iv));
  }
}

///Wrapper for rsa() from rsa.dart
class RsaCrypt extends rsa {
  RsaCrypt() : super();
}

///Class for creating cryptographically secure strings
class CryptKey {
  ///Internal for generating Fortuna Random engine
  static SecureRandom getSecureRandom() {
    var secureRandom = FortunaRandom();
    var random = Random.secure();
    var seeds = List<int>.generate(32, (i) => random.nextInt(256));
    secureRandom.seed(new KeyParameter(new Uint8List.fromList(seeds)));
    return secureRandom;
  }

  ///gen cryptographically-secure, random key; defaults to length 32
  String genKey ([int length = 32]) {
    var rand = getSecureRandom();
    var values = rand.nextBytes(length);
    var stringer = base64Url.encode(values);
    return stringer;
  }

  ///gen cryptographically-secure, random iv; defaults to length 16
  String genIV ([int length = 16]) {
    var rand = getSecureRandom();
    var values = rand.nextBytes(length);
    var stringer = base64Url.encode(values);
    return stringer;
  }
}

///Class specifically for password hashing
class PassCrypt {
  ///hash password given salt, text, and length
  String hashPass (String salt, String pass, [int length = 32]) {
    var params = new Pbkdf2Parameters(utf8.encode(salt), 15000, length);
    var keyDerivator = new KeyDerivator("SHA-512/HMAC/PBKDF2")
      ..init( params )
    ;
    var passBytes = base64.decode(pass);
    var key = keyDerivator.process( passBytes );
    return base64.encode(key);
  }

  ///check hashed password
  bool checkPassKey (String salt, String plain, String hashed, [int length = 32]) {
    var hashplain = hashPass(salt, plain, length);
    return hashplain == hashed;
  }
}

///General hashing class for usage
class HashCrypt {
  ///Type of algorithm
  static core.String type;

  ///Construct with type of algorithm
  HashCrypt ([core.String inType = 'SHA-3/512']) {
    type = inType;
  }

  ///hash with input
  core.String hash (core.String input) {
    var bytes = Base64Codec().decode(input);
    Digest digest;
    digest = Digest(type);
    var value = digest.process(bytes);
    return Base64Codec().encode(value);
  }

  ///HMAC hash with input and key
  core.String hashHMAC (core.String input, core.String key) {
    var listkey = Base64Codec().decode(key);
    var bytes = Base64Codec().decode(input);
    var params = KeyParameter(listkey);
    final _tmp = HMac(Digest(type), 128)..init(params);
    var val = _tmp.process(bytes);
    return Base64Codec().encode(val);
  }

  ///Check hashed against plain
  bool checkhash (core.String plain, core.String hashed) {
    var newhash = hash(plain);
    return newhash == hashed;
  }

  ///Check HMAC hashed against plain
  bool checkhashHMAC (core.String plain, core.String hashed, core.String key) {
    var newhash = hashHMAC(plain, key);
    return newhash == hashed;
  }
}
