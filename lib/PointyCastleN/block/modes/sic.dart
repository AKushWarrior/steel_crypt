// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

// ignore_for_file: omit_local_variable_types, prefer_single_quotes, non_constant_identifier_names, directives_ordering

library pointycastle.impl.block_cipher.modes.sic;

import '../../api.dart';
import '../../adapters/stream_cipher_as_block_cipher.dart';
import '../../stream/sic.dart';
import '../../src/registry/registry.dart';

class SICBlockCipher extends StreamCipherAsBlockCipher {
  /// Intended for internal use.
  static final FactoryConfig FACTORY_CONFIG = DynamicFactoryConfig.suffix(
      BlockCipher,
      "/SIC",
      (_, final Match match) => () {
            BlockCipher underlying = BlockCipher(match.group(1));
            return SICBlockCipher(
                underlying.blockSize, SICStreamCipher(underlying));
          });

  SICBlockCipher(int blockSize, StreamCipher underlyingCipher)
      : super(blockSize, underlyingCipher);
}
