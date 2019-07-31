//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2019 Aditya Kishore

//This is not functional yet, but will be soon. Stay tuned!
import 'dart:core';
import 'dart:convert';
import 'dart:math';

class Threefish {
  static List<int> Key = [];
  static List<List<int>> mixT = [
    [14,16],
    [52,57],
    [23,40],
    [5,37],
    [25,33],
    [46,12],
    [58, 22],
    [32,32]
  ];

  Threefish (String key32) {
    var num = processString(key32);
    Key = num;
  }

  static List<int> encryptWithNiceString (List<int> plain32, List<List<int>> subkeys) {
    List<int> p = plain32;
    List<List<int>> k = subkeys;
    List<List<int>> v = [];
    List<List<int>> e = [];
    List<List<int>> f = [];

    List<int> crypted;

    for (var i = 0; i < 4; i++) {
      v[0][i] = p[i];
    }
    for (var d = 0; d< 72; d++) {
      for (var i = 0; i < 4; i++) {
        if (d%4 == 0) {
          e[d][i] = (v[d][i]+ k[(d/4).round()][i]) % pow(2, 64);
        }
        else {
          e[d][i] = v[d][i];
        }
      }
      for (var j = 0; j< 2; j++) {
        f[d][2*j] = (e[d][2*j] + e[d][2*j]) % pow(2, 64);
        f[d][2*j+1] = f[d][2*j] ^ rotateLeft(e[d][2*j+1], mixT[d%8][j]);
      }
      for (var i = 0; i<4; i++) {
        v[d+1][i] = f[d][iop(i)];
      }
    }
    for (var i = 0; i< 4; i++) {
      crypted[i] = (v[72][i] + k[18][i]) % pow(2,64);
    }
    return crypted;
  }

  static String decryptWithNiceString (List<int> plain32, List<List<int>> subkeys) {

  }

  static List<List<int>> keyAlgo (List<int> key, List<int>tweak) {
    List<int> t = tweak;
    List<List<int>> ks = [];
    var nw = 4;
    var constant = int.parse("0x1BD11BDAA9FC1A22");
    t[2] = t[0] ^ t[1];
    key[4] = key.reduce((value, element) => value ^ element) ^ constant;
    for (var s = 0; s<=18; s++) {
      for (var i = 0; i <= 0; i++) {
        ks[s][i] = key[s] % 5;
      }
      ks[s][1] = (key[(s+1) % 5] + t[s%3]) % pow(2, 64);
      ks[s][2] = (key[(s+2) % 5] + t[(s+1) % 3]) % pow(2, 64);
      ks[s][3] = (key[(s+3) % 5] + s) % pow(2, 64);
    }
    return ks;
  }

  static List<int> processString (String input) {
    List<int> listbytes = utf8.encode(input);
    List<int> finList = [];
    for (var i = 0; i< listbytes.length; i += 8) {
      var curList = listbytes.sublist(i, i+8);
      var tempString;
      for (var element in curList) {
        tempString += "$element";
      }
      finList.add(int.parse(tempString));
    }
    return finList;
  }

  static int rotateLeft (int input, int shift) {
    return (input<<shift) | (input >> (64-shift));
  }

  static int iop (int i) {
    if (i == 0 || i == 2) {
      return i;
    }
    if (i == 1) {
      return 3;
    }
    if (i == 3) {
      return 1;
    }
  }

}