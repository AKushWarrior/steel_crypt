# Steel Crypt
---
## General

A simple library of high-level API's and sugar for PointyCastle/encrypt. This 
library currently supports both hashing and two-way encryption:

#### 2-Way
* AES with PKCS7 Padding ('AES') _(Default)_
* Salsa20 ('Salsa20')
* More coming...

#### Hashing
* SHA-256 (default) ('sha256')
* SHA-1 ('sha1')
* MD5 ('md5')


## Usage

A simple usage example:

```dart
import 'package:steel_crypt/steel_crypt.dart';

main() {
  
  var key = CryptKey().genKey();

  var encrypter = Crypt(key, 'Salsa20');

  var hasher = HashCrypt('sha256');


  
  print(hasher.hash('a'));

  print(encrypter.encrypt('word'));

  print(encrypter.decrypt(encrypter.encrypt('word')));

  print(key);
  
}
```

## Notes

* Use in production AT YOUR OWN RISK.
* This is a work-in-progress, but will be actively maintained.
* Please file feature requests and bugs at the [issue tracker][tracker].

[tracker]: https://github.com/AKushWarrior/steel_crypt/issues

## TODO's

- [x] Create Project + add "Starter Set" of algorithms
- [ ] Add more, different 2-way encryption algorithms + packaging options
- [ ] Tackle adding an RSA solution OR expose _encrypt_'s RSA
- [ ] Create a more complete password solution
- [ ] Add more detailed example

###### Licensed under the Mozilla Public License 2.0
