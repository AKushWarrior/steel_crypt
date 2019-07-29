# Steel Crypt

A comprehensive library of high-level, cryptographic API's from PointyCastle/encrypt. This 
library currently supports hashing, two-way encryption, and key/IV generation. It also has 
a CLI to conduct basic cryptography operations

## Classes
#### 2-Way Symmetric (class SymCrypt)
* AES with PKCS7 Padding ('AES') _(Default Encryption)_
* Salsa20 ('Salsa20')
* More planned...
* __Note__: AES requires 16 bytes of IV, whereas Salsa 20 requires 8

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
* Generates cryptographically secure keys + IV's
* Keys default to length 32, IV's to length 16


## Usage

A simple usage example:

```dart
import 'package:steel_crypt/steel_crypt.dart';

main() {

  var private = CryptKey().genKey(); //generate key


  var encrypter = SymCrypt(private, 'AES'); //generate AES encrypter with key


  var encrypter2 = RsaCrypt(); //generate RSA encrypter


  var hasher = HashCrypt(); //generate SHA-3/512 hasher

  var hasher2 = HashCrypt('SHA-3/256'); //generate SHA-3/256 hasher


  var passHash = PassCrypt();


  var iv = CryptKey().genIV(16); //generate iv for AES

  var salt = CryptKey().genIV(16); //generate salt for password hashing


  //Print key
  print ("Key:");

  print(private);

  print("");


  //SHA-3 512 Hash
  print("SHA-3 512 Hash:");

  print(hasher.hash('word')); //perform hash

  var hash = hasher.hash('word');

  print(hasher.checkhash('word', hash)); //perform check

  print("");


  //HMAC SHA-3 256 Hash
  print("HMAC SHA-3 256 Hash:");

  print(hasher2.hashHMAC('word', private)); //perform hash

  var hash2 = hasher2.hashHMAC('word', private);

  print(hasher2.checkhashHMAC('word', hash2, private)); //perform check

  print("");


  //Password
  print("Password hash (SHA-256/HMAC/PBKDF2):");

  print(passHash.hashPass(salt, "word")); //perform hash

  var hash3 = passHash.hashPass(salt, "word");

  print(passHash.checkPassKey(salt, "word", hash3)); //perform check

  print("");


  //AES Symmetric
  print("AES Symmetric:");

  print(encrypter.encrypt('word', iv)); //encrypt

  String crypted = encrypter.encrypt('word', iv);

  print(encrypter.decrypt(crypted, iv)); //decrypt

  print("");


  //RSA Asymmetric
  print("RSA Asymmetric:");

  var crypted2 = encrypter2.encrypt("word", encrypter2.pubKey); //encrypt

  print(crypted2);

  print(encrypter2.decrypt(crypted2, encrypter2.privKey)); //decrypt

  print("");
}
```
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


## Notes

* This is fairly well-tested and documented, but use in production AT YOUR OWN RISK.
* This is a work-in-progress, but will be actively maintained.
* Please file feature requests and bugs at the [issue tracker][tracker].
* I'm busy, so file a PR for new features if possible...

[tracker]: https://github.com/AKushWarrior/steel_crypt/issues

## TODO's

- [x] Create Project + add "Starter Set" of algorithms
- [x] Add more, different hashes 
- [ ] Add more, different 2-way encryption algorithms + packaging options
- [x] Tackle adding an RSA solution
- [x] Create a more complete password solution
- [x] Add more detailed example

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

###### Licensed under the Mozilla Public License 2.0
