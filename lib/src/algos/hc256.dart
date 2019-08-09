//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2019 Aditya Kishore

//This is not functional yet, but will be soon. Stay tuned!

import 'dart:math';
import 'dart:typed_data';

class HC256 {
  static Uint32List Q = Uint32List(1024);
  static Uint32List P = Uint32List(1024);

  int modAdd (int x, int y) {
    return (x+y) % pow(2,32);
  }
  int modSub (int x, int y) {
    return (x-y) % 1024;
  }
  int rotRight (int x, int y) {
    return ((x >> y) ^ (x << (32-y)));
  }

  int f1 (int x) {
    return (rotRight(x,7)) ^ (rotRight(x,18)) ^ (x >> 3);
  }
  int f2 (int x) {
    return (rotRight(x,17)) ^ (rotRight(x,19)) ^ (x >> 10);
  }
  int g1 (int x, int y) {
    var inter1 = rotRight(x,10) ^ rotRight(y,23);
    var inter2 = Q[(x^y)%1024];
    return modAdd(inter1, inter2);
  }
  int g2 (int x, int y) {
    var inter1 = rotRight(x,10) ^ rotRight(y,23);
    var inter2 = P[(x^y)%1024];
    return modAdd(inter1, inter2);
  }
  int h1 (int x, int y) {
    return 0;
  }
  int h2 (int x, int y) {
    return 0;
  }

}