//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2019 Aditya Kishore

part of 'steel_crypt_base.dart';

///General hashing class for usage
class HashCrypt {

  ///Type of algorithm
  static core.String type;
  static List<String> pads = ['RnL'];

  ///Construct with type of algorithm
  HashCrypt ([core.String inType = 'SHA-3/512']) {
    type = inType;
  }

  ///hash with input
  core.String hash (core.String input) {
    var bytes;
    if (input.length % 4 == 0) {
      bytes = Base64Codec().decode(input);
    }
    else {
      var advinput = input;
      advinput = input + pads[0];
      advinput = advinput.substring(0, advinput.length-advinput.length%4);
      bytes = Base64Codec().decode(advinput);
    }
    Digest digest;
    digest = Digest(type);
    var value = digest.process(bytes);
    return Base64Codec().encode(value);
  }

  ///Check hashed against plain
  bool checkhash (core.String plain, core.String hashed) {
    var newhash = hash(plain);
    return newhash == hashed;
  }
}
