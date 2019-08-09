# Steel Crypt

A comprehensive library of high-level, cryptographic API's, either manually defined or pulled from PointyCastle/encrypt.
This library currently supports hashing, two-way encryption, and key/IV generation. It also has 
a CLI, for conducting basic cryptography operations.

---
## Classes
#### AES Encryption (class AesCrypt)
* AES with PKCS7 Padding
* Operatable in 6 different modes
    - CBC ('cbc')
    - SIC ('sic)
    - CFB ('cfb-64')
    - CTR ('ctr')
    - ECB ('ecb)
    - OFB ('ofb-64')
* __Note__: AES requires 16 bytes of IV

#### Lightweight Stream Ciphers (class LightCrypt)
* ChaCha20 stream cipher ('ChaCha20') _(Default Encryption)_
    - Derivative of Salsa20 with increased security
    - __Note__: Requires 12 bytes of IV
* Salsa20 stream cipher ('Salsa20')
    - Secure, speedy AES alternative
    - __Note__: Requires 8 bytes of IV

#### 2-Way Asymmetric (class RsaCrypt)
* RSA with OAEP padding
* __Note__: RsaCrypt auto generates secure RSA private and public keys. You can access them using ```.privKey``` and ```.pubKey``` getters, or use your own. 

#### Password Hashing (class PassCrypt)
* PBKDF2 with SHA-256 and HMAC
* Compare plaintext to hashtext using ```.checkPassKey(salt, plain, hashed, length)```

#### Hashing (class HashCrypt)
* SHA-3  ('SHA-3/___') :
    - /224
    - /256
    - /384
    - /512 _(Default Hash)_
* SHA-2 ('SHA-___'):
    - -224
    - -256
    - -384
    - -512
* SHA-1 ('SHA-1') __UNSECURE__
* Tiger ('Tiger')
* Blake2b ('Blake2b')
* RipeMD ('RIPEMD-___'):
    - -128
    - -160
    - -256
    - -320
* MD5 ('MD5') __UNSECURE__
* MD4 ('MD4') __UNSECURE__
* MD2 ('MD2') __UNSECURE__

* __Note__: HMAC + key can be added to any of the above using the ```.hashHMAC(input, key)``` function.
* __Note__: Compare plaintext to hashtext using ```.checkpass(plain, hashed)``` and ```.checkpassHMAC(plain, hashed, key)```

#### Key/IV Generation (class CryptKey)
* `.genFortuna (int length = 32)`:
    - Generates cryptographic string using Fortuna algorithm
    - Slower but significantly more secure
    - Best for private keys
    - Used exclusively internally
* `.genDart (int length = 16)`:
    - Generates cryptographic string using Dart Random.secure()
    - Faster but less secure
    - Best for IV's or salt

---

## Usage

A simple usage example:

```dart
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
```

---
## CLI
This CLI allows you to perform basic functions from the main package on the terminal
#### Setup
* If you haven't already done so, add pub-cache to your PATH with ```$ export PATH="$PATH":"$HOME/.pub-cache/bin"```
* Globally activate the steel_crypt package with ```$ pub global activate steel_crypt```
#### Commands
* encrypt: ```$ encrypt -t (text here) -k (key here) -i (iv here)```
    - Uses AES with PKCS7 padding
    - All fields required
* decrypt: ```$ decrypt -t (encrypted here) -k (key here) -i (iv here)```
    - Uses AES with PKCS7 padding
    - All fields required
* hash: ```$ hashtext -p (plain here)```
    - Uses SHA-3/512
    - Field required
* make keys: ```$ genkey -l (length here)```

---
## Notes

* This is fairly well-tested and documented, but use in production AT YOUR OWN RISK.
* This is relatively complete, but will be actively maintained for new bugs.
* I've now added almost every algorithm from PointyCastle, so every algorithm requires extensive implementation work. Bear with me!
* I need your input! What algorithms and features would you like to see here? That leads me to...
* Please file feature requests and bugs at the [issue tracker][tracker].
* I'm busy, so file a PR for new features if possible...

[tracker]: https://github.com/AKushWarrior/steel_crypt/issues

---

## TODO's

- [x] Create Project + add "Starter Set" of algorithms
- [x] Add more, different hashes 
- [ ] Add more, different 2-way encryption algorithms (In progress...)
- [ ] Try to add more packaging options
- [x] Tackle adding an RSA solution
- [x] Create a more complete password solution
- [x] Add more detailed example
- [ ] Update Reading to reflect new algorithms

---

## Reading
- Look at these links for further information on ciphers, hashes, and terminology used here:
    - https://en.wikipedia.org/wiki/Salsa20
    - https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
    - https://en.wikipedia.org/wiki/RSA_(cryptosystem)
    - https://en.wikipedia.org/wiki/SHA-3
    - https://en.wikipedia.org/wiki/SHA-2
    - https://en.wikipedia.org/wiki/SHA-1
    - https://en.wikipedia.org/wiki/MD5
    - https://en.wikipedia.org/wiki/MD4
    - https://en.wikipedia.org/wiki/Tiger_(hash_function)
    - https://en.wikipedia.org/wiki/Whirlpool_(hash_function)
    - https://en.wikipedia.org/wiki/HMAC
    - https://en.wikipedia.org/wiki/OAEP
    - https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS#5_and_PKCS#7
    - https://en.wikipedia.org/wiki/Initialization_vector
    - https://en.wikipedia.org/wiki/Cryptographic_hash_function
    - https://en.wikipedia.org/wiki/Symmetric-key_algorithm
    - https://en.wikipedia.org/wiki/Public-key_cryptography
    
---

###### ©2019 Aditya Kishore
###### Licensed under the Mozilla Public License 2.0