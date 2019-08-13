//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2019 Aditya Kishore

import 'package:steel_crypt/steel_crypt.dart';

main() {

  var FortunaKey = CryptKey().genFortuna(); //generate 32 byte key generated with Fortuna


  var aesEncrypter = AesCrypt(FortunaKey, 'cbc', 'iso7816-4'); //generate AES CBC block encrypter with key and ISO7816-4 padding

  var aesEncrypter2 = AesCrypt(FortunaKey, 'ofb-64', 'pkcs7'); //generate AES CBC block encrypter with key and PKCS7 padding

  var streamAES = AesCrypt(FortunaKey, 'ctr'); //generate AES CTR stream encrypter with key


  var encrypter2 = RsaCrypt(); //generate RSA encrypter


  var encrypter3 = LightCrypt(FortunaKey, "ChaCha20/12"); //generate ChaCha20/12 encrypter


  var hasher = HashCrypt(); //generate SHA-3/512 hasher

  var hasher3 = MacCrypt(FortunaKey, "CMAC", 'cfb-64'); //CMAC AES CFB-64 Hasher


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

  print(hasher.hash('example')); //perform hash

  var hash = hasher.hash('example');

  print(hasher.checkhash('example', hash)); //perform check

  print("");

  //CMAC AES CFB-64 Hash
  print("CMAC AES CFB-64 Hash:");

  print(hasher3.process('words')); //perform hash

  var hash3 = hasher3.process('words');

  print(hasher3.check('words', hash3)); //perform check

  print("");

  //Password (SHA-256/HMAC/PBKDF2)
  print("Password hash (SHA-256/HMAC/PBKDF2):");

  print(passHash.hashPass(salt, "words")); //perform hash

  var hash4 = passHash.hashPass(salt, "words");

  print(passHash.checkPassKey(salt, "words", hash4)); //perform check

  print("");


  //12-Round ChaCha20; Symmetric stream cipher
  print("ChaCha20 Symmetric:");

  print(encrypter3.encrypt('word', iv2)); //encrypt

  String crypted3 = encrypter3.encrypt('word', iv2);

  print(encrypter3.decrypt(crypted3, iv2)); //decrypt

  print("");


  //AES CBC with ISO7816-4 padding; Symmetric block cipher
  print("AES Symmetric:");

  print(aesEncrypter.encrypt('words', iv)); //encrypt

  String crypted = aesEncrypter.encrypt('words', iv);

  print(aesEncrypter.decrypt(crypted, iv)); //decrypt

  print("");


  //AES OFB-64 with PKCS7 padding; Symmetric block cipher
  print("AES Symmetric:");

  print(aesEncrypter2.encrypt('words', iv)); //encrypt

  String crypted2 = aesEncrypter2.encrypt('words', iv);

  print(aesEncrypter2.decrypt(crypted2, iv)); //decrypt

  print("");


  //AES CTR; Symmetric stream cipher
  print("AES Symmetric:");

  print(streamAES.encrypt('words', iv)); //encrypt

  String crypted5 = streamAES.encrypt('words', iv);

  print(aesEncrypter.decrypt(crypted5, iv)); //decrypt

  print("");


  //RSA with OAEP padding; Asymmetric
  print("RSA Asymmetric:");

  var crypted4 = encrypter2.encrypt("word", encrypter2.pubKey); //encrypt

  print(crypted4);

  print(encrypter2.decrypt(crypted4, encrypter2.privKey)); //decrypt

  print("");
}