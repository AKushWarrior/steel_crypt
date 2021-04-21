// AES Stuff

enum PaddingAES { pkcs7, iso78164, none }

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

// Stream stuff

enum StreamAlgo {
  salsa20,
  salsa20_12,
  salsa20_8,
  chacha20,
  chacha20_12,
  chacha20_8,
}
