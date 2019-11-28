// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.impl.block_cipher.modes.ctr;

import '../../adapters/stream_cipher_as_block_cipher.dart';
import '../../api.dart';
import '../../src/registry/registry.dart';
import '../../stream/ctr.dart';

class CTRBlockCipher extends StreamCipherAsBlockCipher {
  /// Intended for internal use.
  static final FactoryConfig FACTORY_CONFIG = DynamicFactoryConfig.suffix(
      BlockCipher,
      "/CTR",
      (_, final Match match) => () {
        BlockCipher underlying = BlockCipher(match.group(1));
        return CTRBlockCipher(
            underlying.blockSize, CTRStreamCipher(underlying));
          });

  CTRBlockCipher(int blockSize, StreamCipher underlyingCipher)
      : super(blockSize, underlyingCipher);
}
