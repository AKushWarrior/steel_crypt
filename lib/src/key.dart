//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2019 Aditya Kishore

part of 'steel_crypt_base.dart';

///Class for creating cryptographically secure strings
class CryptKey {

  ///Internal for generating Fortuna Random engine
  static SecureRandom getSecureRandom() {
    var secureRandom = FortunaRandom();
    var random = Random.secure();
    var seeds = List<int>.generate(32, (i) => random.nextInt(256));
    secureRandom.seed(KeyParameter(Uint8List.fromList(seeds)));
    return secureRandom;
  }

  ///gen cryptographically-secure, Fortuna random string; defaults to length 32
  String genFortuna ([int length = 32]) {
    var rand = getSecureRandom();
    var values = rand.nextBytes(length);
    var stringer = base64Url.encode(values);
    return stringer;
  }

  ///gen cryptographically-secure, Dart Random.secure string; defaults to length 16
  String genDart ([int length = 16]) {
    var rand = Random.secure();
    var bytes = List<int>.generate(length, (i) => rand.nextInt(256));
    return base64Url.encode(bytes);
  }
}
