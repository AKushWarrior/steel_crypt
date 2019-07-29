import 'dart:core';
import 'dart:convert';

class Threefish {
  List<List<int>> Key = [];

  Threefish (String key32) {
    List<int> listbytes = utf8.encode(key32);
    List<List<int>> KeyList = [];
    for (var i = 0; i< listbytes.length; i += 8) {
      KeyList.add(listbytes.sublist(i, i+8));
    }
    Key = KeyList;
  }

  encrypt (String plain) {

  }

  decrypt (String plain) {

  }

}