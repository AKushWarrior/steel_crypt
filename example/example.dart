//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2019 Aditya Kishore

import 'package:steel_crypt/steel_crypt.dart';

main() {

  var FortunaKey = CryptKey().genFortuna(); //generate 32 byte key generated with Fortuna


  var encrypter = AesCrypt(FortunaKey, 'cbc'); //generate AES encrypter with key


  var encrypter2 = RsaCrypt(); //generate RSA encrypter


  var encrypter3 = LightCrypt(FortunaKey, "ChaCha20"); //generate ChaCha20 encrypter


  var hasher = HashCrypt(); //generate SHA-3/512 hasher

  var hasher2 = HashCrypt('SHA-3/256'); //generate SHA-3/256 hasher


  var passHash = PassCrypt(); //generate PBKDF2 password hasher


  var iv = CryptKey().genDart(16); //generate iv for AES with Dart Random.secure()

  var iv2 = CryptKey().genDart(12); //generate iv for ChaCha20 with Dart Random.secure()


  var salt = CryptKey().genDart(16); //generate salt for password hashing with Dart Random.secure()


  //Print key
  print ("Key:");

  print(FortunaKey);

  print("");


  //SHA-3 512 Hash
  print("SHA-3 512 Hash:");

  print(hasher.hash('words')); //perform hash

  var hash = hasher.hash('words');

  print(hasher.checkhash('words', hash)); //perform check

  print("");


  //HMAC SHA-3 256 Hash
  print("HMAC SHA-3 256 Hash:");

  print(hasher2.hashHMAC('words', FortunaKey)); //perform hash

  var hash2 = hasher2.hashHMAC('words', FortunaKey);

  print(hasher2.checkhashHMAC('words', hash2, FortunaKey)); //perform check

  print("");


  //Password (SHA-256/HMAC/PBKDF2)
  print("Password hash (SHA-256/HMAC/PBKDF2):");

  print(passHash.hashPass(salt, "words")); //perform hash

  var hash3 = passHash.hashPass(salt, "words");

  print(passHash.checkPassKey(salt, "words", hash3)); //perform check

  print("");


  //ChaCha20; Symmetric stream cipher
  print("ChaCha20 Symmetric:");

  print(encrypter3.encrypt('word', iv2)); //encrypt

  String crypted3 = encrypter3.encrypt('word', iv2);

  print(encrypter3.decrypt(crypted3, iv2)); //decrypt

  print("");


  //AES with PKCS7 padding; Symmetric block cipher
  print("AES Symmetric:");

  print(encrypter.encrypt('word', iv)); //encrypt

  String crypted = encrypter.encrypt('word', iv);

  print(encrypter.decrypt(crypted, iv)); //decrypt

  print("");


  //RSA with OAEP padding; Asymmetric
  print("RSA Asymmetric:");

  var crypted2 = encrypter2.encrypt("word", encrypter2.pubKey); //encrypt

  print(crypted2);

  print(encrypter2.decrypt(crypted2, encrypter2.privKey)); //decrypt

  print("");
}