//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2021 Aditya Kishore

import 'package:args/args.dart';
import 'package:steel_crypt/steel_crypt.dart';

void main(List<String> args) {
  final argParser = ArgParser();

  argParser.addOption('text',
      abbr: 't', help: 'Input the word to be encrypted here...');

  argParser.addOption('key',
      abbr: 'k', help: 'Input the key to encrypt the word here...');

  argParser.addOption('iv',
      abbr: 'i', help: 'Input the IV to encrypt the word here...');

  argParser.addFlag('help',
      abbr: 'h', defaultsTo: false, help: 'Show this help message');

  final results = argParser.parse(args);

  final key = results['key'].toString();
  final input = results['text'].toString();
  final iv = results['iv'].toString();

  final help = results['help'] as bool;

  if (help) {
    return print(argParser.usage);
  }

  print(AesCrypt(key: key, padding: PaddingAES.pkcs7)
      .gcm
      .encrypt(inp: input, iv: iv));
}
