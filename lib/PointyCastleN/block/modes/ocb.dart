/*library pointycastle.impl.block_cipher.modes.ocb;

import "dart:typed_data";

import 'package:steel_crypt/PointyCastleN/src/registry/registry.dart';

import '../../api.dart';
import '../../src/impl/base_aead_block_cipher.dart';

class OCBBlockCipher extends BaseAEADBlockCipher {
  /// Intended for internal use.
  static final FactoryConfig FACTORY_CONFIG = DynamicFactoryConfig.suffix(
      BlockCipher,
      "/OCB",
          (_, final Match match) =>
          () {
        BlockCipher underlying = BlockCipher(match.group(1));
        return OCBBlockCipher(underlying);
      });
  static final int BLOCK_SIZE = 16;

  BlockCipher hashCipher;
  BlockCipher mainCipher;

  bool forEncryption;
  int macSize;
  Uint8List initialAssociatedText;

  // NOTE: elements are lazily calculated
  List L;
  Uint8List L_Asterisk, L_Dollar;

  Uint8List KtopInput;
  Uint8List Stretch = Uint8List(24);
  Uint8List OffsetMAIN_0 = Uint8List(16);

  Uint8List hashBlock, mainBlock;
  int hashBlockPos, mainBlockPos;
  int hashBlockCount, mainBlockCount;
  Uint8List OffsetHASH;
  Uint8List Sum;
  Uint8List OffsetMAIN = Uint8List(16);
  Uint8List Checksum;

  // NOTE: The MAC value is preserved after doFinal
  Uint8List macBlock;

  @override
  OCBBlockCipher (BlockCipher mainCipher) : super(null) {
    if (mainCipher.blockSize != BLOCK_SIZE)
    {
      throw ArgumentError("'mainCipher' must have a block size of $BLOCK_SIZE");
    }
    this.hashCipher = BlockCipher(mainCipher.algorithmName);
    this.mainCipher = mainCipher;
  }

  BlockCipher get underlyingCipher => mainCipher;

  String get algorithmName => mainCipher.algorithmName + '/OCB';

  void init (bool forEncryption, covariant ParametersWithIV params) {
    bool oldForEncryption = this.forEncryption;
    this.forEncryption = forEncryption;
    this.macBlock = null;
    KeyParameter keyParameter;


  }
}
*/
