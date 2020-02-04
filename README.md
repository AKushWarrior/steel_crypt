# Steel Crypt 

A comprehensive library of high-level, cryptographic API's, either manually defined or pulled from PointyCastle.
This library currently supports hashing, symmetric two-way encryption, asymmetric two-way encryption, and key/IV generation. It also has 
a CLI, for conducting basic cryptography operations.

---

It takes time, effort, and mental power to keep this package updated, useful, and
improving. If you used or are using the package, I'd appreciate it if you could spare a few 
dollars to help me continue development.

[![PayPal](https://img.shields.io/static/v1?label=PayPal&message=Donate&color=blue&logo=paypal&style=for-the-badge&labelColor=black)](https://www.paypal.me/kishoredev)

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
        - CBC ('cbc')
        - ECB ('ecb') __INSECURE__
        - CFB-64 ('cfb-64') 
        - OFB-64 ('ofb-64') 
        - GCTR ('gctr')
        - GCM ('gcm') _(Default/Recommended Mode)_
* 5 paddings available for block modes:
    - PKCS7 Padding ('pkcs7') _(Default)_
    - ISO7816-4 Padding ('iso7816-4')
    - X9.23 Padding ('x9.23')
    - TBC Padding ('tbc')
    - ISO10126-2 Padding ('iso10126-2')
            
* __Note__: All block modes require padding, to ensure that input is the correct block size.
* __Note__: Paddings do not work with stream modes. You can still enter the parameter, but it won't be used.
* __Note__: ECB does not require an IV. You can still enter the parameter, but it won't be used.
* __Note__: All other modes require 16 bytes of IV (Initialization Vector, see CryptKey for generation).

#### Lightweight Stream Ciphers (class LightCrypt)
* Constructor: ```LightCrypt('32 length key', 'algorithm here')```
* ChaCha20 stream cipher ('ChaCha20/__')
    - Derivative of Salsa20 with increased security/speed
    - Can be used in 3 variants:
        - 20 round ( __ ==> '20' ) _(Default/Recommended Cipher)_
        - 12 round ( __ ==> '12' )
        - 8 round ( __ ==> '8' )
    - __Note__: Requires 8 bytes of IV (Initialization Vector, see CryptKey for generation)
* Salsa20 stream cipher ('Salsa20/__')
    - Secure, speedy AES alternative
    - E-Crypt Stream Cipher final portfolio
    - Can be used in 3 variants:
        - 20 round ( __ ==> '20' )
        - 12 round ( __ ==> '12' )
        - 8 round ( __ ==> '8' )
    - __Note__: Requires 8 bytes of IV (Initialization Vector, see CryptKey for generation)
* HC-256 stream cipher ('HC-256')
    - Secure, software-efficient cipher
    - E-Crypt Stream Cipher final portfolio
    - __Note__: Requires 16 bytes of IV (Initialization Vector, see CryptKey for generation)
* Grain-128 stream cipher ('Grain-128')
    - Secure, hardware-efficient cipher
    - E-Crypt Stream Cipher final portfolio
    - __Note__: Requires 12 bytes of IV (Initialization Vector, see CryptKey for generation)
* ISAAC stream cipher ('ISAAC')
    - Extremely fast stream cipher
    - Secure, but with a low margin
    - Usage not recommended unless you have very high speed needs
    - __Note__: Requires no IV; you can enter an IV param, but it won't affect anything
* RC4 stream cipher ('RC4')
    - Somewhat fast stream cipher
    - Secure(ish), but with a dangerously low margin
    - Usage **not** recommended unless you have a legacy system; otherwise use ChaCha for the whole package or Grain/HC-256 for platform optimization
    - __Note__: Requires no IV; you can enter an IV param, but it won't affect anything    

#### 2-Way Asymmetric (class RsaCrypt)
* Constructor: ```RsaCrypt()```
* RSA with OAEP padding
    - String ```encrypt(String text, RSAPublicKey pubKey)```
    - String ```decrypt(String encrypted, RSAPrivateKey privateKey)```
* __Note__: RsaCrypt auto generates secure RSA private and public keys. You can access them using ```.randPrivKey``` and ```.randPubKey``` getters, or use your own. 
* __Note__: To get key from a PEM file, use ```RsaCrypt().parseKeyFromFile(String PemFilepathHere)``` and pass the PEM file as a string.
* __Note__: To get key from a PEM string, use ```RsaCrypt().parseKeyFromString(String PemStringHere)``` and pass the PEM string.
* __Note__: To convert key to PEM string, use ```RsaCrypt().encodeKeyToString(RsaAsymmetricKey KeyHere)``` and pass the key.

#### Password Hashing (class PassCrypt)
* Constructor: ```PassCrypt([String algorithm = "scrypt"])```
* Scrypt ('scrypt') _(Default/Recommended Algorithm)_
* PBKDF2 with:
    - SHA-256 HMAC ('SHA-256/HMAC/PBKDF2')
    - SHA-384 HMAC ('SHA-384/HMAC/PBKDF2')
    - SHA-512 HMAC ('SHA-512/HMAC/PBKDF2')
    - 256 bit SHA-3 HMAC ('SHA-3/256/HMAC/PBKDF2')
    - 512 bit SHA-3 HMAC ('SHA-3/512/HMAC/PBKDF2')
    - RipeMD 128 HMAC ('RIPEMD-128/HMAC/PBKDF2')
    - RipeMD 160 HMAC ('RIPEMD-160/HMAC/PBKDF2')
    - Blake2b HMAC ('Blake2b/HMAC/PBKDF2')
    - Tiger HMAC ('Tiger/HMAC/PBKDF2')
    - Whirlpool HMAC ('Whirlpool/HMAC/PBKDF2')
* Compare plaintext to hashtext using ```.checkPassKey(salt, plain, hashed, length)```

#### Hashing (class HashCrypt)
* Constructor: ```HashCrypt([String algorithm = "SHA-3/512"])```
* SHA-3  ('SHA-3/___') :
    - /224
    - /256 _(Default/Recommended Hash)_
    - /384
    - /512 
* SHA-2 ('SHA-___'):
    - -224
    - -256
    - -384
    - -512
* SHA-1 ('SHA-1') __INSECURE__
* Tiger ('Tiger')
* Blake2b ('Blake2b')
* RipeMD ('RIPEMD-___'):
    - -128
    - -160
    - -256
    - -320
* MD5 ('MD5') __INSECURE__
* MD4 ('MD4') __INSECURE__
* MD2 ('MD2') __INSECURE__
* __Note__: Compare plaintext to hashtext using ```.checkpass(plain, hashed)```

#### MAC's (class MacCrypt)
* Constructor: ```MacCrypt ('32 length key', 'CMAC or HMAC', 'algorithm here')```
* HMAC and CMAC are available
    - For HMAC algorithm field, use any available __hashing__ algorithm in HashCrypt for `algorithm`
    - For CMAC algorithm field, use any available AES __block cipher__ algorithm in AESCrypt for `algorithm`

#### Key/IV Generation (class CryptKey)
* Constructor: `CryptKey()`
* Method: ```.genFortuna ([int length = 32])```
    - Generates cryptographic string using Fortuna algorithm
    - Slower but significantly more secure
    - Best for private keys
    - Used internally
* Method: ```.genDart ([int length = 16])```
    - Generates cryptographic string using Dart Random.secure()
    - Faster but less secure
    - Best for IV's or salt
* Note: Keys/IVs may look strange when printed, because the terminal is thrown by the full range of utf-16 characters. 
Rest assured, they are still valid.

---

## Usage

A simple usage example:

```dart
import 'package:steel_crypt/steel_crypt.dart';

main() {
  var FortunaKey = CryptKey().genFortuna(); //generate 32 byte key generated with Fortuna


  var aesEncrypter = AesCrypt(FortunaKey, 'cbc',
      'iso10126-2'); //generate AES block encrypter with key and ISO7816-4 padding

  var aesEncrypter2 = AesCrypt(FortunaKey, 'ofb-64',
      'pkcs7'); //generate AES OFB-64 block encrypter with key and PKCS7 padding

  var streamAES = AesCrypt(FortunaKey, 'ctr'); //generate AES CTR stream encrypter with key


  var encrypter2 = RsaCrypt(); //generate RSA encrypter


  var encrypter3 = LightCrypt(FortunaKey, "ChaCha20/12"); //generate ChaCha20/12 encrypter


  var hasher = HashCrypt("SHA-3/512"); //generate SHA-3/512 hasher

  var hasher3 = MacCrypt(FortunaKey, "CMAC", 'cfb-64'); //CMAC AES CFB-64 Hasher


  var passHash = PassCrypt('scrypt'); //generate scrypt password hasher


  var ivsalt = CryptKey().genDart(
      16); //generate iv for AES with Dart Random.secure()

  var iv2 = CryptKey().genDart(8); //generate iv for ChaCha20 with Dart Random.secure()

  //Print key
  print ("Key:");

  print(FortunaKey);

  print("");


  //Print IV
  print ("IV (AES/Scrypt):");

  print(ivsalt);

  print("");

  //Print IV
  print ("IV (ChaCha20):");

  print(iv2);

  print("");
  
  //SHA-3 512 Hash
  print("SHA-3 512 Hash:");

  String hash = hasher.hash('example'); //perform hash

  print(hash);

  print(hasher.checkhash('example', hash)); //perform check

  print("");

  //CMAC AES CFB-64 Hash
  print("CMAC AES CFB-64 Hash:");

  var hash3 = hasher3.process('words'); //perform hash

  print(hash3);

  print(hasher3.check('words', hash3)); //perform check

  print("");

  //Password (scrypt)
  print("Password hash (scrypt):");

  var hash4 = passHash.hashPass(ivsalt, "words"); //perform hash

  print(hash4);

  print(passHash.checkPassKey(ivsalt, "words", hash4)); //perform check

  print("");


  //12-Round ChaCha20; Symmetric stream cipher
  print("ChaCha20 Symmetric:");

  String crypted3 = encrypter3.encrypt('broken', iv2); //encrypt

  print(crypted3);

  print(encrypter3.decrypt(crypted3, iv2)); //decrypt

  print("");


  //AES CBC with ISO7816-4 padding; Symmetric block cipher
  print("AES Symmetric CBC:");

  String crypted = aesEncrypter.encrypt('words', ivsalt); //encrypt

  print(crypted);

  print(aesEncrypter.decrypt(crypted, ivsalt)); //decrypt

  print("");


  //AES OFB-64 with PKCS7 padding; Symmetric block cipher
  print("AES Symmetric OFB-64:");

  String crypted2 = aesEncrypter2.encrypt('words', ivsalt); //encrypt

  print(crypted2);

  print(aesEncrypter2.decrypt(crypted2, ivsalt)); //decrypt

  print("");


  //AES CTR; Symmetric stream cipher
  print("AES Symmetric CTR:");

  String crypted5 = streamAES.encrypt('words', ivsalt); //Encrypt.

  print(crypted5);

  print(streamAES.decrypt(crypted5, ivsalt)); //Decrypt.

  print("");


  //RSA with OAEP padding; Asymmetric
  print("RSA Asymmetric:");

  var crypted4 = encrypter2.encrypt("word", encrypter2.randPubKey); //encrypt

  print(crypted4);

  print(encrypter2.decrypt(crypted4, encrypter2.randPrivKey)); //decrypt

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

* This is fairly well-tested and documented, but use in production at your own risk.
* This is practically complete; however, I'm always open to new ideas and feature requests, and will always maintain for bugs.
* I need your input! What algorithms and features would you like to see here? That leads me to...
* Please file feature requests, clarifications, and bugs at the [issue tracker][tracker]!

[tracker]: https://github.com/AKushWarrior/steel_crypt/issues

---

## TODO's

- [x] Create Project + add "Starter Set" of algorithms
- [x] Add more, different hashes 
- [x] Add more, different 2-way stream algorithms
- [x] Try to add more packaging options
- [x] Tackle adding an RSA solution
- [x] Create a more complete password solution
- [x] Add more detailed example
- [x] Update further reading
- [ ] Add more AES modes (GCM done, de-prioritized)
- [ ] ??? (Leave feature requests in the issue tracker above, and they'll end up here!)

---

## Note: Prior Knowledge
It is my personal recommendation to always know what each algorithm that you are using in a given application is, and how it works. 
However, this package exists to help you with that transition. This package is **not** a guide on cryptography, and cannot 
substitute for prior knowledge of some level of cryptography. 
If you need help understanding concepts of cryptography, **ask** someone; user data is always the priority, and I'll help
anyone willing to listen. I'd much rather answer an issue regarding basic encryption than hear that my package was used 
improperly and thus compromised. If you ever need to reach me, post in the issue tracker above; I'll be on it as quickly as
possible.
   
---

[![Pub](https://img.shields.io/pub/v/steel_crypt?color=blue&label=pub&logo=Steel%20Crypt&logoColor=blue&style=for-the-badge&labelColor=black)](https://pub.dev/packages/steel_crypt)
[![License](https://img.shields.io/github/license/AKushWarrior/steel_crypt?color=blue&style=for-the-badge&labelColor=black)](https://www.mozilla.org/en-US/MPL/2.0/)
[![Commits](https://img.shields.io/github/commit-activity/m/AKushWarrior/steel_crypt?color=blue&style=for-the-badge&labelColor=black)](https://github.com/AKushWarrior/steel_crypt)

###### ©2019 Aditya Kishore
###### Licensed under the Mozilla Public License 2.0
###### This project is built on a custom implementation of Steven Roose's PointyCastle.