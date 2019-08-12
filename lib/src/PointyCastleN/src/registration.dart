// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

//
//
//BlockCipher _cfbBlockCipherFactory(String algorithmName) {
//  var parts = algorithmName.split("/");
//
//  if (parts.length != 2) return null;
//  if (!parts[1].startsWith("CFB-")) return null;
//
//  var blockSizeInBits = int.parse(parts[1].substring(4));
//  if ((blockSizeInBits % 8) != 0) {
//    throw new ArgumentError("Bad CFB block size: $blockSizeInBits (must be a multiple of 8)");
//  }
//
//  var underlyingCipher = _createOrNull(() => new BlockCipher(parts[0]));
//
//  if (underlyingCipher != null) {
//    return new CFBBlockCipher(underlyingCipher, blockSizeInBits ~/ 8);
//  }
//
//  return null;
//}
//
//BlockCipher _ofbBlockCipherFactory(String algorithmName) {
//  var parts = algorithmName.split("/");
//
//  if (parts.length != 2) return null;
//  if (!parts[1].startsWith("OFB-")) return null;
//
//  var blockSizeInBits = int.parse(parts[1].substring(4));
//  if ((blockSizeInBits % 8) != 0) {
//    throw new ArgumentError("Bad OFB block size: $blockSizeInBits (must be a multiple of 8)");
//  }
//
//  var underlyingCipher = _createOrNull(() => new BlockCipher(parts[0]));
//
//  if (underlyingCipher != null) {
//    return new OFBBlockCipher(underlyingCipher, blockSizeInBits ~/ 8);
//  }
//
//  return null;
//}
