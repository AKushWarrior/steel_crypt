//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2019 Aditya Kishore

//imports
import 'dart:core';
import 'dart:core' as core;
import 'dart:math';
import 'dart:typed_data';
import 'dart:convert';
import 'package:encrypt/encrypt.dart';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/export.dart';
import 'algos/chacha/chacha20.dart';

//parts
part 'rsa.dart'; //for RsaCrypt
part 'light.dart'; //for LightCrypt
part 'pass.dart'; //for PassCrypt
part 'aes.dart'; //for AesCrypt
part 'key.dart'; //for CryptKey
part 'hash.dart'; //for HashCrypt