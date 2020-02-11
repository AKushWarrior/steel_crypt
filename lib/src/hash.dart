//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2019 Aditya Kishore

part of 'steel_crypt_base.dart';

///Class to perform one-way hashing using common algorithms.
class HashCrypt {
  String _type;

  ///Get this HashCrypt's hashing algorithm.
  String get type {
    return _type;
  }

  ///Construct with type of algorithm
  HashCrypt([String inType = 'SHA-3/256']) {
    _type = inType;
  }

  ///Hash with given input.
  String hash(String input) {
    var bytes = utf8.encode(input);
    Digest digest;
    digest = Digest(_type);
    var value = digest.process(bytes as Uint8List);
    return base64.encode(value);
  }

  ///Check hashed against plain
  bool checkhash(core.String plain, core.String hashed) {
    var newhash = hash(plain);
    return newhash == hashed;
  }
}
