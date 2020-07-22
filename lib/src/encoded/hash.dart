//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2020 Aditya Kishore

part of '../steel_crypt_base.dart';

/// Class to perform one-way hashing using common algorithms.
///
/// This version of HashCrypt is encoded, meaning that it expects plaintext to be UTF-8,
/// and returns base64 encoded Strings. For more flexibility, HashCryptRaw is recommended.
class HashCrypt {
  ModeHash _type;

  ///Get this HashCrypt's hashing algorithm.
  ModeHash get type {
    return _type;
  }

  ///Construct with type of algorithm
  HashCrypt({@required algo}) {
    _type = algo;
  }

  ///Hash with given input.
  String hash({@required String inp}) {
    var bytes = utf8.encode(inp);
    Digest digest;
    digest = Digest(parseHash(type.toString()));
    var value = digest.process(bytes as Uint8List);
    return base64.encode(value);
  }

  ///Check hashed against plain
  bool check({@required String plain, @required String hashed}) {
    var newhash = hash(inp: plain);
    return newhash == hashed;
  }
}
