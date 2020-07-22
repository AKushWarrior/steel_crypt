//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2020 Aditya Kishore

part of '../steel_crypt_base.dart';

/// Class to perform one-way hashing using common algorithms.
///
/// This version of HashCrypt is raw, meaning that it expects all inputs to be
/// Uint8List, and returns Uint8Lists. For a higher-level solution, [HashCrypt]
/// is recommended.
class HashCryptRaw {
  final HashAlgo _type;

  ///Get this HashCrypt's hashing algorithm.
  HashAlgo get type {
    return _type;
  }

  ///Construct with type of algorithm
  HashCryptRaw(this._type);

  ///Hash with given input.
  Uint8List hash({@required Uint8List inp}) {
    Digest digest;
    digest = Digest(parseHash(type.toString()));
    var value = digest.process(inp);
    return value;
  }

  ///Check hashed against plain
  bool checkhash({@required Uint8List plain, @required Uint8List hashed}) {
    var newhash = hash(inp: plain);
    return newhash == hashed;
  }
}
