# Steel Crypt 

[![PayPal](https://img.shields.io/static/v1?label=PayPal&message=Donate&color=blue&logo=paypal&style=for-the-badge&labelColor=black)](https://www.paypal.me/kishoredev)

A comprehensive library of high-level, cryptographic API's, either manually defined or pulled from PointyCastle.
This library currently supports hashing, symmetric two-way encryption, asymmetric two-way encryption, and key/IV generation. It also has 
a CLI, for conducting basic cryptography operations.

---
## Classes
#### AES Encryption (class AesCrypt)
* Constructor: ```AesCrypt ('32 length key', 'mode here', 'padding here')```
* AES is a standardized, widely used cipher
* It can be used as either a block or stream cipher, depending on mode
* Operatable in 6 different modes:
    - Stream modes:
        - CTR ('ctr')
        - SIC ('sic')
    - Block modes:
        - CBC ('cbc') _(Default)_
        - ECB ('ecb')
        - CFB-64 ('cfb-64')
        - OFB-64 ('ofb-64')
* 4 paddings available for block modes:
    - PKCS7 Padding ('pkcs7') _(Default)_
    - ISO7816-4 Padding ('iso7816-4')
    - X9.23 Padding ('x9.23')
    - TBC Padding ('tbc')
            
* __Note__: All block modes require padding, to ensure that input is the correct block size.
* __Note__: Paddings do not work with stream modes. You can still enter the parameter, but it won't be used.
* __Note__: AES requires 16 bytes of IV.

#### Lightweight Stream Ciphers (class LightCrypt)
* ChaCha20 stream cipher ('ChaCha20/__')
    - Derivative of Salsa20 with increased security
    - Can be used in 3 variants:
        - 20 round ( __ ==> '20' ) _(Default Encryption)_
        - 12 round ( __ ==> '12' )
        - 8 round ( __ ==> '8' )
    - __Note__: Requires 12 bytes of IV
* Salsa20 stream cipher ('Salsa20/__')
    - Secure, speedy AES alternative
    - E-Crypt Stream Cipher final portfolio
    - Can be used in 3 variants:
        - 20 round ( __ ==> '20' )
        - 12 round ( __ ==> '12' )
        - 8 round ( __ ==> '8' )
    - __Note__: Requires 8 bytes of IV
* HC-256 stream cipher ('HC-256')
    - Secure, software-efficient cipher
    - E-Crypt Stream Cipher final portfolio
    - __Note__: Requires 16 bytes of IV
* Grain-128 stream cipher ('Grain-128')
    - Secure, hardware-efficient cipher
    - E-Crypt Stream Cipher final portfolio
    - __Note__: Requires 12 bytes of IV
* ISAAC stream cipher ('ISAAC')
    - Extremely fast stream cipher
    - Secure, but with a low margin
    - Usage not recommended unless you have very high speed needs
    - __Note__: Requires no IV; you can enter an IV param, but it won't affect anything

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
* __Note__: Compare plaintext to hashtext using ```.checkpass(plain, hashed)```

#### MAC's (class MacCrypt)
* Constructor: ```MacCrypt ('32 length key', 'CMAC or HMAC', 'algorithm here')```
* HMAC and CMAC are available
    - For HMAC algorithm field, use any available __hashing__ algorithm as in HashCrypt
    - For CMAC algorithm field, use any available AES __block cipher__ algorithm as in AESCrypt

#### Key/IV Generation (class CryptKey)
* `.genFortuna (int length = 32)`:
    - Generates cryptographic string using Fortuna algorithm
    - Slower but significantly more secure
    - Best for private keys
    - Used internally
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
* Please file feature requests, clarifications, and bugs at the [issue tracker][tracker].

[tracker]: https://github.com/AKushWarrior/steel_crypt/issues

---

## TODO's

- [x] Create Project + add "Starter Set" of algorithms
- [x] Add more, different hashes 
- [ ] Add more, different 2-way stream algorithms (In progress...) ("LightCrypt" for updates)
- [x] Try to add more packaging options
- [x] Tackle adding an RSA solution
- [x] Create a more complete password solution
- [x] Add more detailed example
- [ ] ??? (Leave feature requests in the issue tracker, and they'll end up here!)

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

[![Pub](https://img.shields.io/pub/v/steel_crypt?color=blue&label=pub&logo=Steel%20Crypt&logoColor=blue&style=for-the-badge&labelColor=black)](https://pub.dev/packages/steel_crypt)
[![License](https://img.shields.io/github/license/AKushWarrior/steel_crypt?color=blue&style=for-the-badge&labelColor=black)](https://www.mozilla.org/en-US/MPL/2.0/)
[![Commits](https://img.shields.io/github/commit-activity/m/AKushWarrior/steel_crypt?color=blue&style=for-the-badge&labelColor=black)](https://github.com/AKushWarrior/steel_crypt)

###### ©2019 Aditya Kishore
###### Licensed under the Mozilla Public License 2.0