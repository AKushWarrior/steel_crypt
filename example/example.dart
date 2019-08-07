//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2019 Aditya Kishore

import 'package:steel_crypt/steel_crypt.dart';

main() {

  var private = CryptKey().genKey(); //generate 32 byte key


  var encrypter = AesCrypt(private, 'cbc'); //generate AES encrypter with key


  var encrypter2 = RsaCrypt(); //generate RSA encrypter


  var encrypter3 = LightCrypt(private, "ChaCha20"); //generate ChaCha20 encrypter


  var hasher = HashCrypt(); //generate SHA-3/512 hasher

  var hasher2 = HashCrypt('SHA-3/256'); //generate SHA-3/256 hasher


  var passHash = PassCrypt(); //generate PBKDF2 password hasher


  var iv = CryptKey().genIV(16); //generate iv for AES

  var iv2 = CryptKey().genIV(12); //generate iv for ChaCha20


  var salt = CryptKey().genIV(16); //generate salt for password hashing


  //Print key
  print ("Key:");

  print(private);

  print("");


  //SHA-3 512 Hash
  print("SHA-3 512 Hash:");

  print(hasher.hash('word')); //perform hash

  var hash = hasher.hash('pass');

  print(hasher.checkhash('pass', hash)); //perform check

  print("");


  //HMAC SHA-3 256 Hash
  print("HMAC SHA-3 256 Hash:");

  print(hasher2.hashHMAC('word', private)); //perform hash

  var hash2 = hasher2.hashHMAC('word', private);

  print(hasher2.checkhashHMAC('word', hash2, private)); //perform check

  print("");


  //Password (SHA-256/HMAC/PBKDF2)
  print("Password hash (SHA-256/HMAC/PBKDF2):");

  print(passHash.hashPass(salt, "word")); //perform hash

  var hash3 = passHash.hashPass(salt, "word");

  print(passHash.checkPassKey(salt, "word", hash3)); //perform check

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