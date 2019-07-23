# Steel Crypt
A simple library of high-level API's and sugar for PointyCastle. This 
library currently supports both hashing and two-way encryption:

#### 2-Way
* AES ('AES') _(Default)_
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


### Usage

A simple usage example:

```dart
import 'package:steel_crypt/steel_crypt.dart';


var key = cryptKey().genKey();

var encrypter = Crypt(key, 'Salsa20');

var hasher = hashCrypt('SHA-3');


print(hasher.hash('a'));

print(encrypter.encrypt("word"));

print(encrypter.decrypt(encrypter.encrypt(word)));

print(key);

```

## Features and bugs

Please file feature requests and bugs at the [issue tracker][tracker].

[tracker]: http://example.com/issues/replaceme
