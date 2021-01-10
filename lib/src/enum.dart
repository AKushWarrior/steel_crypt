// AES Stuff

import 'package:pointycastle/api.dart';
import 'package:pointycastle/macs/hmac.dart';

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

// Hashing stuff

enum HashAlgo {
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

enum StreamAlgo {
  salsa20,
  salsa20_12,
  salsa20_8,
  chacha20,
  chacha20_12,
  chacha20_8,
}

String stringifyStream(StreamAlgo algorithm) {
  var str = algorithm.toString().substring(11).replaceAll('_', '/');
  if (str.startsWith('chacha')) {
    str = str.replaceRange(0, 6, 'ChaCha');
  } else if (str.startsWith('salsa')) {
    str = str.replaceRange(0, 5, 'Salsa');
  }
  return str;
}
