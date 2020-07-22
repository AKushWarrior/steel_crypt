//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2019 Aditya Kishore

import 'package:args/args.dart';
import 'package:steel_crypt/steel_crypt.dart';

void main(List<String> args) {
  final argParser = ArgParser();

  argParser.addOption('plain',
      abbr: 'p', help: 'Input the plaintext to be hashed here...');

  argParser.addFlag('help',
      abbr: 'h',
      defaultsTo: false,
      help:
          'Use Blake2b hashing to hash your string. Use -p to specify what string you want.');

  final results = argParser.parse(args);

  final plain = results['plain'].toString();

  final help = results['help'] as bool;

  if (help) {
    return print(argParser.usage);
  }

  print(HashCrypt(algo: ModeHash.Blake2b).hash(inp: plain));
}
