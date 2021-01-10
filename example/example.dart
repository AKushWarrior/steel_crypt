//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2021 Aditya Kishore

import 'package:steel_crypt/steel_crypt.dart';

void main() {
  // Generate keys/ivs/nonces
  // --------
  // Key generator
  var keyGen = CryptKey();
  //generate 32 byte key using Fortuna
  var key32 = keyGen.genFortuna(len: 32);
  //generate 16 byte key using Fortuna
  var key16 = keyGen.genFortuna(len: 16);
  //generate iv for AES
  var iv16 = keyGen.genDart(len: 16);
  //generate iv for ChaCha20
  var iv8 = keyGen.genDart(len: 8);

  // Generate cryptography machines
  // --------
  // generated AES encrypter with key + padding
  var aes = AesCrypt(key: key32, padding: PaddingAES.pkcs7);
  // generate ChaCha20/12 encrypter
  var stream = LightCrypt(key: key32, algo: StreamAlgo.chacha20_12);
  // generate Blake2b hasher
  var hasher = HashCrypt(algo: HashAlgo.Blake2b);
  // CMAC AES CBC Hasher
  var mac = MacCrypt(key: key16, type: MacType.CMAC);
  // generate scrypt password hasher
  var passHash = PassCrypt.scrypt();

  // Examples + Debugging
  // --------
  //Print key
  print('Keys:');
  print('key32: $key32 \nkey16: $key16');
  print('');

  //Print IV
  print('IVs:');
  print('For AES/SCrypt: $iv16 \nFor ChaCha20: $iv8');
  print('');

  //SHA-3 512 Hash
  print('SHA-3 512 Hash:');
  var hash = hasher.hash(inp: 'example'); //perform hash
  print(hash);
  print(hasher.check(plain: 'example', hashed: hash)); //perform check
  print('');

  //CMAC AES CBC Hash
  print('CMAC AES CBC Hash:');
  var hash2 = mac.process(inp: 'words'); //perform hash
  print(hash2);
  print(mac.check(plain: 'words', hashed: hash2)); //perform check
  print('');

  //Password (scrypt)
  print('Password hash (scrypt):');
  var hash3 = passHash.hash(salt: iv16, inp: 'words'); //perform hash
  print(hash3);
  print(passHash.check(
      salt: iv16, plain: 'words', hashed: hash3)); //perform check
  print('');

  //12-Round ChaCha20; Symmetric stream cipher
  print('ChaCha20 Symmetric:');
  var crypted3 = stream.encrypt(inp: 'broken', iv: iv8); //encrypt
  print(crypted3);
  print(stream.decrypt(enc: crypted3, iv: iv8)); //decrypt
  print('');

  //AES GCM encryption/decryption
  print('AES Symmetric GCM:');
  var crypted = aes.gcm.encrypt(inp: 'words', iv: iv16); //encrypt
  print(crypted);
  print(aes.gcm.decrypt(enc: crypted, iv: iv16)); //decrypt
  print('');

  //AES CTR; Symmetric stream cipher
  print('AES Symmetric CTR:');
  var crypted2 = aes.ctr.encrypt(inp: 'words', iv: iv16); //Encrypt.
  print(crypted2);
  print(aes.ctr.decrypt(enc: crypted2, iv: iv16)); //Decrypt.
  print('');
}
