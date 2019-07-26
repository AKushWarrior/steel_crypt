# Steel Crypt

A comprehensive library of high-level, cryptographic API's from PointyCastle/encrypt. This 
library currently supports hashing, two-way encryption, and key/IV generation:

#### 2-Way Symmetric (class SymCrypt)
* AES with PKCS7 Padding ('AES') _(Default Encryption)_
* Salsa20 ('Salsa20')
* More planned...
* __Note__: AES requires 16 bytes of IV, whereas Salsa 20 requires 8

#### 2-Way Asymmetric (class RsaCrypt)
* RSA
* __Note__: RsaCrypt is non-traditional. It auto-generates keys and stores them. However, it requires authentication text on the user end to work correctly.

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

  var private = CryptKey().genKey();



  var encrypter = SymCrypt(private, 'AES');

  var encrypter2 = RsaCrypt();


  var hasher = HashCrypt();

  var hasher2 = HashCrypt('SHA-3/256');


  var iv = CryptKey().genIV(16);



  print(private);


  print(hasher.hash('word'));

  var hash = hasher.hash('word');

  print(hasher.checkpass('word', hash));


  print(hasher2.hashHMAC('word', private));


  print(encrypter.encrypt('word', iv));

  String crypted = encrypter.encrypt('word', iv);

  print(encrypter.decrypt(crypted, iv));



  var crypted2 = encrypter2.encrypt('word', "This is authentication text...");

  print(encrypter2.getString(crypted2));

  print(encrypter2.decrypt(crypted2));

}
```

## Notes

* Use in production AT YOUR OWN RISK.
* This is a work-in-progress, but will be actively maintained.
* Please file feature requests and bugs at the [issue tracker][tracker].
* I'm busy, so file a PR for new features if possible...

[tracker]: https://github.com/AKushWarrior/steel_crypt/issues

## TODO's

- [x] Create Project + add "Starter Set" of algorithms
- [x] Add more, different hashes 
- [ ] Add CMAC
- [ ] Add more, different 2-way encryption algorithms + packaging options
- [x] Tackle adding an RSA solution OR expose _crypto_tool_'s RSA
- [x] Create a more complete password solution
- [ ] Add more detailed example

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
    - https://en.wikipedia.org/wiki/PKCS_1
    - https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS#5_and_PKCS#7
    - https://en.wikipedia.org/wiki/Initialization_vector
    - https://en.wikipedia.org/wiki/Cryptographic_hash_function
    - https://en.wikipedia.org/wiki/Symmetric-key_algorithm
    - https://en.wikipedia.org/wiki/Public-key_cryptography

###### Licensed under the Mozilla Public License 2.0
