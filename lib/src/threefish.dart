import 'dart:core';
import 'dart:math';
import 'dart:convert';

class Threefish {
  List<List<int>> Key = [];
  List<List<int>> IV = [];

  Threefish (String key32, String iv16) {
    List<int> listbytes = utf8.encode(key32);
    List<List<int>> KeyList = [];
    for (var i = 0; i< listbytes.length; i += 8) {
      KeyList.add(listbytes.sublist(i, i+8));
    }
    Key = KeyList;
    List<int> ivbytes = utf8.encode(iv16);
    List<List<int>> IvList = [];
    for (var i = 0; i< ivbytes.length; i += 8) {
      IvList.add(ivbytes.sublist(i, i+8));
    }
    IV = IvList;
  }

  encrypt (String plain) {

  }

  decrypt (String plain) {

  }

}