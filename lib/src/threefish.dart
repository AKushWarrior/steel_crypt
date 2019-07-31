//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2019 Aditya Kishore

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