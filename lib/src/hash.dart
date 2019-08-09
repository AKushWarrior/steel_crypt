//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2019 Aditya Kishore

part of 'steel_crypt_base.dart';

///General hashing class for usage
class HashCrypt {
  ///Type of algorithm
  static core.String type;
  static List<String> pads = [];

  ///Construct with type of algorithm
  HashCrypt ([core.String inType = 'SHA-3/512']) {
    type = inType;
    var someBytes = CryptKey().genFortuna(4);
    pads.add(someBytes.substring(3));
    pads.add(someBytes.substring(2,3));
    pads.add(someBytes.substring(1,2));
    pads.add(someBytes.substring(0,1));
  }

  ///hash with input
  core.String hash (core.String input) {
    var bytes;
    if (input.length % 4 == 0) {
      bytes = Base64Codec().decode(input);
    }
    else {
      var advinput = input;
      for (var i =0; i < (input.length % 4); i++) {
        advinput = input + pads[i];
      }
      advinput = advinput.substring(0, advinput.length -2);
      bytes = Base64Codec().decode(advinput);
    }
    Digest digest;
    digest = Digest(type);
    var value = digest.process(bytes);
    return Base64Codec().encode(value);
  }

  ///HMAC hash with input and key
  core.String hashHMAC (core.String input, core.String key) {
    var listkey= Base64Codec().decode(key);
    var bytes;
    if (input.length % 4 == 0) {
      bytes = Base64Codec().decode(input);
    }
    else {
      var advinput = input;
      for (var i =0; i < input.length % 4; i++) {
        advinput = input + pads[i];
      }
      advinput = advinput.substring(0, advinput.length -2);
      bytes = Base64Codec().decode(advinput);
    }
    var params = KeyParameter(listkey);
    final _tmp = HMac(Digest(type), 128)..init(params);
    var val = _tmp.process(bytes);
    return Base64Codec().encode(val);
  }

  ///Check hashed against plain
  bool checkhash (core.String plain, core.String hashed) {
    var newhash = hash(plain);
    return newhash == hashed;
  }

  ///Check HMAC hashed against plain
  bool checkhashHMAC (core.String plain, core.String hashed, core.String key) {
    var newhash = hashHMAC(plain, key);
    return newhash == hashed;
  }
}
