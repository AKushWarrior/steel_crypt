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
  final ModeHash _type;

  ///Get this HashCrypt's hashing algorithm.
  ModeHash get type {
    return _type;
  }

  ///Construct with type of algorithm
  HashCryptRaw(this._type);

  ///Hash with given input.
  Uint8List hash(Uint8List input) {
    var bytes = input;
    Digest digest;
    digest = Digest(parseHash(type.toString()));
    var value = digest.process(bytes);
    return value;
  }

  ///Check hashed against plain
  bool checkhash(Uint8List plain, Uint8List hashed) {
    var newhash = hash(plain);
    return newhash == hashed;
  }
}
