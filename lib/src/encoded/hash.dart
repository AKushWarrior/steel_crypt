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
  final ModeHash _type;

  ///Get this HashCrypt's hashing algorithm.
  ModeHash get type {
    return _type;
  }

  ///Construct with type of algorithm
  HashCrypt(this._type);

  ///Hash with given input.
  String hash(String input) {
    var bytes = utf8.encode(input);
    Digest digest;
    digest = Digest(parseHash(type.toString()));
    var value = digest.process(bytes as Uint8List);
    return base64.encode(value);
  }

  ///Check hashed against plain
  bool checkhash(core.String plain, core.String hashed) {
    var newhash = hash(plain);
    return newhash == hashed;
  }
}

enum ModeHash {
  Sha_256,
  Sha_512,
  Sha_384,
  Sha_224,
  Sha3_224,
  Sha3_256,
  Sha3_384,
  Sha3_512,
  Keccak_224,
  Keccak_256,
  Keccak_384,
  Keccak_512,
  Sha1,
  RipeMD_128,
  RipeMD_160,
  RipeMD_256,
  RipeMD_320,
  Blake2b,
  MD2,
  MD4,
  MD5,
  Tiger,
  Whirlpool
}

String parseHash(String mode) {
  var partial = mode.split('.')[1];
  if (partial.startsWith('Sha_')) {
    var split = partial.split('_');
    partial = 'SHA-' + split[1];
  } else if (partial.startsWith('Sha3')) {
    var split = partial.split('_');
    partial = 'SHA-3/' + split[1];
  } else if (partial.startsWith('K')) {
    var split = partial.split('_');
    partial = 'Keccak/' + split[1];
  } else if (partial.startsWith('R')) {
    var split = partial.split('_');
    partial = 'RIPEMD-' + split[1];
  } else if (partial.startsWith('Sha1')) {
    partial = 'SHA-1';
  }
  return partial;
}
