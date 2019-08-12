// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.impl.adapters.stream_cipher_as_block_cipher;

import "dart:typed_data";

import '../api.dart';
import '../src/impl/base_block_cipher.dart';

/// An adapter to convert an [StreamCipher] to a [BlockCipher]
class StreamCipherAsBlockCipher extends BaseBlockCipher {
  final StreamCipher streamCipher;
  final int blockSize;

  /// Create a [BlockCipher] from [streamCipher] simulating the given [blockSize]
  StreamCipherAsBlockCipher(this.blockSize, this.streamCipher);

  String get algorithmName => streamCipher.algorithmName;

  void reset() {
    streamCipher.reset();
  }

  void init(bool forEncryption, CipherParameters params) {
    streamCipher.init(forEncryption, params);
  }

  int processBlock(Uint8List inp, int inpOff, Uint8List out, int outOff) {
    streamCipher.processBytes(inp, inpOff, blockSize, out, outOff);
    return blockSize;
  }
}
