// AES Stuff

import 'package:pc_steelcrypt/api.dart';
import 'package:pc_steelcrypt/macs/hmac.dart';

enum ModeAES { cbc, ctr, cfb64, ofb64, gctr, ecb, gcm }

enum PaddingAES { pkcs7, iso78164, none }

String parsePadding(PaddingAES padding) {
  switch (padding) {
    case PaddingAES.pkcs7:
      return 'PKCS7';
    case PaddingAES.iso78164:
      return 'ISO7816-4';
    default:
      return 'None';
  }
}

String parseAES(ModeAES mode) {
  switch (mode) {
    case ModeAES.cfb64:
      return 'CFB-64';
    case ModeAES.ofb64:
      return 'OFB-64';
    case ModeAES.ecb:
      return 'ECB';
    case ModeAES.ctr:
      return 'CTR';
    case ModeAES.cbc:
      return 'CBC';
    case ModeAES.gcm:
      return 'GCM';
    case ModeAES.gctr:
      return 'GCTR';
  }
  throw ArgumentError('invalid mode (internal, file an issue!)');
}

// Hashing stuff

enum ModeHash {
  Sha_256,
  Sha_512,
  Sha_384,
  Sha_224,
  Sha3_224,
  Sha3_256,
  Sha3_384,
  Sha3_512,
  Keccak_224,
  Keccak_256,
  Keccak_384,
  Keccak_512,
  Sha1,
  RipeMD_128,
  RipeMD_160,
  RipeMD_256,
  RipeMD_320,
  Blake2b,
  MD2,
  MD4,
  MD5,
  Tiger,
  Whirlpool
}

String parseHash(String mode) {
  var partial = mode.split('.')[1];
  if (partial.startsWith('Sha_')) {
    var split = partial.split('_');
    partial = 'SHA-' + split[1];
  } else if (partial.startsWith('Sha3')) {
    var split = partial.split('_');
    partial = 'SHA-3/' + split[1];
  } else if (partial.startsWith('K')) {
    var split = partial.split('_');
    partial = 'Keccak/' + split[1];
  } else if (partial.startsWith('R')) {
    var split = partial.split('_');
    partial = 'RIPEMD-' + split[1];
  } else if (partial.startsWith('Sha1')) {
    partial = 'SHA-1';
  }
  return partial;
}

// MAC stuff

enum MacType { CMAC, HMAC, Poly1305 }

enum HmacHash {
  Sha_256,
  Sha_384,
  Sha_512,
  Sha3_256,
  Sha3_512,
  Keccak_256,
  Keccak_512,
  RipeMD_128,
  RipeMD_160,
  Blake2b,
  Tiger,
  Whirlpool
}

// Password Hashing stuff

HMac parsePBKDF2(HmacHash mode) {
  return HMac(Digest(parseHash(mode.toString())), 128);
}

// Stream stuff

enum Stream {
  salsa20,
  salsa20_12,
  salsa20_8,
  chacha20,
  chacha20_12,
  chacha20_8,
}

String stringifyType(Stream algo) {
  switch (algo) {
    case Stream.chacha20:
      return 'ChaCha20';
    case Stream.chacha20_8:
      return 'ChaCha20/8';
    case Stream.chacha20_12:
      return 'ChaCha20/12';
    case Stream.salsa20:
      return 'Salsa20';
    case Stream.salsa20_8:
      return 'Salsa20/8';
    case Stream.salsa20_12:
      return 'Salsa20/12';
  }
  throw ArgumentError('');
}
