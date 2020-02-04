//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2019 Aditya Kishore

import 'package:steel_crypt/steel_crypt.dart';

void main() {
  var FortunaKey =
  CryptKey().genFortuna(); //generate 32 byte key using Fortuna

  var aesEncrypter = AesCrypt(FortunaKey, 'cbc',
      'iso10126-2'); //generate AES block encrypter with key and ISO7816-4 padding

  var aesEncrypter2 = AesCrypt(FortunaKey, 'ofb-64',
      'pkcs7'); //generate AES OFB-64 block encrypter with key and PKCS7 padding

  var streamAES =
      AesCrypt(FortunaKey, 'ctr'); //generate AES CTR stream encrypter with key

  var encrypter2 = RsaCrypt(); //generate RSA encrypter

  var encrypter3 =
  LightCrypt(FortunaKey, 'ChaCha20/12'); //generate ChaCha20/12 encrypter

  var hasher = HashCrypt('SHA-3/512'); //generate SHA-3/512 hasher

  var hasher3 = MacCrypt(FortunaKey, 'CMAC', 'cfb-64'); //CMAC AES CFB-64 Hasher

  var passHash = PassCrypt('scrypt'); //generate scrypt password hasher

  var ivsalt =
  CryptKey().genDart(16); //generate iv for AES using Dart Random.secure()

  var iv2 = CryptKey()
      .genDart(8); //generate iv for ChaCha20 using Dart Random.secure()

  //Print key
  print('Key:');

  print(FortunaKey);

  print('');

  //Print IV
  print('IV (for AES/Scrypt):');

  print(ivsalt);

  print('');

  //Print IV
  print('IV (for ChaCha20):');

  print(iv2);

  print('');

  //SHA-3 512 Hash
  print('SHA-3 512 Hash:');

  var hash = hasher.hash('example'); //perform hash

  print(hash);

  print(hasher.checkhash('example', hash)); //perform check

  print('');

  //CMAC AES CFB-64 Hash
  print('CMAC AES CFB-64 Hash:');

  var hash3 = hasher3.process('words'); //perform hash

  print(hash3);

  print(hasher3.check('words', hash3)); //perform check

  print('');

  //Password (scrypt)
  print('Password hash (scrypt):');

  var hash4 = passHash.hashPass(ivsalt, 'words'); //perform hash

  print(hash4);

  print(passHash.checkPassKey(ivsalt, 'words', hash4)); //perform check

  print('');

  //12-Round ChaCha20; Symmetric stream cipher
  print('ChaCha20 Symmetric:');

  var crypted3 = encrypter3.encrypt('broken', iv2); //encrypt

  print(crypted3);

  print(encrypter3.decrypt(crypted3, iv2)); //decrypt

  print('');

  //AES CBC with ISO7816-4 padding; Symmetric block cipher
  print('AES Symmetric CBC:');

  var crypted = aesEncrypter.encrypt('words', ivsalt); //encrypt

  print(crypted);

  print(aesEncrypter.decrypt(crypted, ivsalt)); //decrypt

  print('');

  //AES OFB-64 with PKCS7 padding; Symmetric block cipher
  print('AES Symmetric OFB-64:');

  var crypted2 = aesEncrypter2.encrypt('words', ivsalt); //encrypt

  print(crypted2);

  print(aesEncrypter2.decrypt(crypted2, ivsalt)); //decrypt

  print('');

  //AES CTR; Symmetric stream cipher
  print('AES Symmetric CTR:');

  var crypted5 = streamAES.encrypt('words', ivsalt); //Encrypt.

  print(crypted5);

  print(streamAES.decrypt(crypted5, ivsalt)); //Decrypt.

  print('');

  //RSA with OAEP padding; Asymmetric
  print('RSA Asymmetric:');

  var crypted4 = encrypter2.encrypt('word', encrypter2.randPubKey); //encrypt

  print(crypted4);

  print(encrypter2.decrypt(crypted4, encrypter2.randPrivKey)); //decrypt

  print('');
}
