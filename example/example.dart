//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2019 Aditya Kishore

import 'package:steel_crypt/steel_crypt.dart';

void main() {
  var FortunaKey =
  CryptKey().genFortuna(); //generate 32 byte key using Fortuna

  var aesEncrypter = AesCrypt(
      mode: ModeAES.cbc, padding: PaddingAES.iso78164, key: FortunaKey);
  //generated AES encrypter with key

  aesEncrypter.mode = ModeAES.gcm;
  //changed mode of encrypter

  var streamAES = AesCrypt(
      mode: ModeAES.ctr, padding: PaddingAES.none, key: FortunaKey);
  //generated AES CTR stream encrypter with key

  var encrypter2 = const RsaCrypt(); //generate RSA encrypter

  var encrypter3 = LightCrypt(key: FortunaKey,
      algorithm: StreamAlgorithm.chacha20_12); //generate ChaCha20/12 encrypter

  var hasher = HashCrypt(ModeHash.Blake2b); //generate SHA-3/512 hasher

  var hasher3 = MacCrypt(key: FortunaKey,
      type: MacType.CMAC,
      algorithm: ModeAES.gcm.asCMAC()); //CMAC AES GCM Hasher

  var passHash = PassCrypt.scrypt(); //generate scrypt password hasher

  var ivsalt = CryptKey().genDart(
      length: 16); //generate iv for AES using Dart Random.secure()

  var iv2 = CryptKey().genDart(
      length: 8); //generate iv for ChaCha20 using Dart Random.secure()

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

  print(hasher3.check('words', hashtext: hash3)); //perform check

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

  var crypted = aesEncrypter.encrypt('words', iv: ivsalt); //encrypt

  print(crypted);

  print(aesEncrypter.decrypt(crypted, iv: ivsalt)); //decrypt

  print('');

  //AES CTR; Symmetric stream cipher
  print('AES Symmetric CTR:');

  var crypted5 = streamAES.encrypt('words', iv: ivsalt); //Encrypt.

  print(crypted5);

  print(streamAES.decrypt(crypted5, iv: ivsalt)); //Decrypt.

  print('');

  //RSA with OAEP padding; Asymmetric
  print('RSA Asymmetric:');

  var crypted4 = encrypter2.encrypt('word', encrypter2.randPubKey); //encrypt

  print(crypted4);

  print(encrypter2.decrypt(crypted4, encrypter2.randPrivKey)); //decrypt

  print('');
}
