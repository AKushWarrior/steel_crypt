//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2019 Aditya Kishore

//This is not functional yet, but will be soon. Stay tuned!
import 'dart:math';
import 'dart:convert';

class Speck {
  static int n = 32;
  static int m = 4;
  static int T = 34;
  static int a = 8;
  static int b = 3;

  static List<int> key = [];

  Speck(String key32);

  encrypt(String plain) {
  }

  decrypt(String crypted) {}

  static List<int> keyexp (List<int> l) {
    List<int> k = [];
    k[0] = l[0];
    l.removeAt(0);
    for (int i = T-2; i >= 0; i-=1) {
      l[i+m-1] = ((k[i] + rotateRight(a, l[i])) % pow(2, n)).round() ^ i;
      k[i+1] = rotateLeft(k[i], b) ^ l[i+m-1];
    }
    return k;
  }

  static List<int> encryptWithBlock(List<int> blocks, List<int> k) {
    List<int> cryptedblocks = blocks;
    for (var i =0; i <T; i++) {
      cryptedblocks[0] = modAdd(rotateRight(cryptedblocks[0], a), cryptedblocks[1]) ^ k[i];
      cryptedblocks[1] = rotateLeft(cryptedblocks[1], b) ^ cryptedblocks[0];
    }
    return cryptedblocks;
  }
  static List<int> decryptWithBlock(List<int> cryptedblocks, List<int> k) {
    List<int> blocks = cryptedblocks;
    for (var i =0; i <T; i++) {
      blocks[1] = rotateRight(blocks[0]^blocks[1], b);
      blocks[0] = rotateLeft(modSub(blocks[0]^k[i], blocks[1]), a);
    }
    return blocks;
  }

  static int rotateLeft (int input, int shift) {
    return (input<<shift) | (input >> (64-shift));
  }
  static int rotateRight (int input, int shift) {
    return (input>>shift) | (input << (64-shift));
  }
  static int modAdd (int one, int two) {
    return (one + two) % pow(2,n);
  }
  static int modSub (int one, int two) {
    return (one - two) % pow(2,n);
  }

  List<List<int>> processString (String input) {
    List<int> listbytes = utf8.encode(input);
    List<List<int>> finList = [];
    for (var i = 0; i< listbytes.length; i += 8) {
      var curList = listbytes.sublist(i, i+8);
      finList.add(curList);
    }
    print(finList);
    return finList;
  }
}