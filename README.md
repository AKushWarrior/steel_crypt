# Steel Crypt
---
## General

A simple library of high-level API's and sugar for crypto/encrypt. This 
library currently supports hashing, two-way encryption, and key/IV generation:

#### 2-Way
* AES with PKCS7 Padding ('AES') _(Default)_
* Salsa20 ('Salsa20')
* More coming...
* Note: AES requires 16 bytes of IV, whereas Salsa 20 requires 8

#### Hashing
* SHA-256  ('sha256') _(Default)_
* SHA-1 ('sha1')
* MD5 ('md5')
* __Note__: HMAC + key can be added to any of the above using the .hashHMAC function.

#### Key/IV (Initialization Vector) Generation
* Generates cryptographically secure keys + IV's
* Keys default to length 32, IV's to length 16


## Usage

A simple usage example:

```dart
import 'package:steel_crypt/steel_crypt.dart';

main() {

  var key = CryptKey().genKey();

  var encrypter = Crypt(key, 'AES');

  var hasher = HashCrypt('sha256');

  var hasher2 = HashCrypt('sha256');

  var iv = CryptKey().genIV(16);


  print(key);

  print(hasher.hash('word'));

  print(hasher.hashHMAC('word', key));

  print(encrypter.encrypt('word', iv));

  String crypted = encrypter.encrypt('word', iv);

  print(encrypter.decrypt(crypted, iv));

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
- [ ] Add more, different 2-way encryption algorithms + packaging options
- [ ] Tackle adding an RSA solution OR expose _encrypt_'s RSA
- [ ] Create a more complete password solution
- [ ] Add more detailed example

###### Licensed under the Mozilla Public License 2.0
