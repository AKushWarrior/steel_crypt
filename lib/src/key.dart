//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2021 Aditya Kishore

part of 'steel_crypt_base.dart';

///Class for creating cryptographically secure strings.
class CryptKey {
  SecureRandom rand;
  Random dart;

  static SecureRandom _getFortunaRandom() {
    var secureRandom = FortunaRandom();
    var random = Random.secure();
    var seeds = List<int>.generate(32, (i) => random.nextInt(256));
    var seedHash = Blake2bDigest();
    seeds = seedHash.process(Uint8List.fromList(seeds)).sublist(0, 32);
    secureRandom.seed(KeyParameter(Uint8List.fromList(seeds)));
    return secureRandom;
  }

  /// Generate cryptographically-secure random string using Fortuna algorithm.
  /// The string is encoded using base64. Thus, this is for use with encoded
  /// classes.
  ///
  /// This should be used for all cases where randomness is of high importance.
  /// This includes, but is not limited to, key generation.
  ///
  /// Defaults to length 32 bytes.
  String genFortuna({int len = 32}) {
    rand ??= _getFortunaRandom();
    var values = rand.nextBytes(len);
    var stringer = base64.encode(values);
    return stringer;
  }

  /// Generate cryptographically-secure random string using Dart math.random.
  /// The string is encoded using base64. Thus, this is for use with encoded
  /// classes.
  ///
  /// This is less secure than Fortuna, but faster. It can be used for IVs and salts,
  /// but never for keys.
  ///
  /// Defaults to length 16.
  String genDart({int len = 16}) {
    dart ??= Random.secure();
    var bytes = List<int>.generate(len, (i) => dart.nextInt(256));
    return base64.encode(bytes);
  }

  /// Generate cryptographically-secure random string using the Fortuna algorithm.
  /// The string is not encoded and returned as a Uint8List. Thus, this is for use
  /// with raw classes.
  ///
  /// This should be used for all cases where randomness is of high importance.
  /// This includes, but is not limited to, key generation.
  ///
  /// Defaults to length 32 bytes.
  Uint8List genFortunaRaw({int len = 32}) {
    rand ??= _getFortunaRandom();
    return rand.nextBytes(len);
  }

  /// Generate cryptographically-secure random string using Dart math.random.
  /// The string is not encoded and returned as a Uint8List. Thus, this is for use
  /// with raw classes.
  ///
  /// This is less secure than Fortuna, but faster. It can be used for IVs and salts,
  /// but never for keys.
  ///
  /// Defaults to length 16 bytes.
  Uint8List genDartRaw({int len = 16}) {
    dart ??= Random.secure();
    return Uint8List.fromList(List.generate(len, (i) => dart.nextInt(256)));
  }
}
