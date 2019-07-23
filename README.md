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
* SHA-3 ('SHA-3') (_Default_)
* Blake2B ('Blake2b')
* MD5 ('MD5')
* SHA-1 ('SHA-1')
* SHA-512 ('SHA-512)
* SHA-256 ('SHA-256')
* Whirlpool ('Whirlpool)
* and more... (Find the full list of exposed hashes at [PointyCastle][PointyLink].)

[PointyLink]: https://github.com/PointyCastle/pointycastle/tree/master/lib/digests


## Usage

A simple usage example:

```dart
import 'package:SteelCrypt/steel_crypt.dart';

main() {
  
  var key = CryptKey().genKey();

  var encrypter = Crypt(key, 'Salsa20');

  var hasher = HashCrypt('SHA-3');


  
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

