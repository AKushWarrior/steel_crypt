//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2019 Aditya Kishore

part of 'steel_crypt_base.dart';

///Class for creating cryptographically secure strings.
class CryptKey {
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
  ///
  /// This should be used for all cases where randomness is of high importance.
  /// This includes, but is not limited to, key generation.
  ///
  /// Defaults to length 32 bytes.
  String genFortuna([int length = 32]) {
    var rand = _getFortunaRandom();
    var values = List.generate((length), (int i) {
      return rand.nextUint8();
    });
    var stringer = String.fromCharCodes(values);
    return stringer;
  }

  /// Generate secure random String using Dart math.random.
  ///
  /// This is less secure than Fortuna, but faster. It can be used for IVs and salts,
  /// but never for keys.
  ///
  /// Defaults to length 16.
  String genDart([int length = 16]) {
    var rand = Random.secure();
    var bytes = List<int>.generate(length, (i) => rand.nextInt(256));
    return String.fromCharCodes(bytes);
  }
}