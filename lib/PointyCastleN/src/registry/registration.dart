library pointycastle.src.registry.impl;

import '../../asymmetric/oaep.dart';
import '../../asymmetric/pkcs1.dart';
import '../../asymmetric/rsa.dart';
import '../../block/aes_fast.dart';
import '../../block/modes/cbc.dart';
import '../../block/modes/cfb.dart';
import '../../block/modes/ctr.dart';
import '../../block/modes/ecb.dart';
import '../../block/modes/gctr.dart';
import '../../block/modes/ofb.dart';
import '../../block/modes/sic.dart';
import '../../digests/blake2b.dart';
import '../../digests/md2.dart';
import '../../digests/md4.dart';
import '../../digests/md5.dart';
import '../../digests/ripemd128.dart';
import '../../digests/ripemd160.dart';
import '../../digests/ripemd256.dart';
import '../../digests/ripemd320.dart';
import '../../digests/sha1.dart';
import '../../digests/sha224.dart';
import '../../digests/sha256.dart';
import '../../digests/sha3.dart';
import '../../digests/sha384.dart';
import '../../digests/sha512.dart';
import '../../digests/sha512t.dart';
import '../../digests/tiger.dart';
import '../../digests/whirlpool.dart';
import '../../key_derivators/pbkdf2.dart';
import '../../key_derivators/scrypt.dart';
import '../../key_generators/rsa_key_generator.dart';
import '../../macs/hmac.dart';
import '../../macs/cmac.dart';
import '../../padded_block_cipher/padded_block_cipher_impl.dart';
import '../../paddings/pkcs7.dart';
import '../../paddings/iso7816d4.dart';
import '../../paddings/tbc.dart';
import '../../paddings/x923.dart';
import '../../random/auto_seed_block_ctr_random.dart';
import '../../random/block_ctr_random.dart';
import '../../random/fortuna_random.dart';
import '../../signers/rsa_signer.dart';
import 'registry.dart';
import '../../stream/hc256.dart';
import '../../stream/ctr.dart';
import '../../stream/salsa20.dart';
import '../../stream/salsa2012.dart';
import '../../stream/salsa208.dart';
import '../../stream/sic.dart';
import '../../stream/isaac.dart';
import '../../stream/grain128.dart';

void registerFactories(FactoryRegistry registry) {
  _registerAsymmetricCiphers(registry);
  _registerBlockCiphers(registry);
  _registerDigests(registry);
  _registerKeyDerivators(registry);
  _registerKeyGenerators(registry);
  _registerMacs(registry);
  _registerPaddedBlockCiphers(registry);
  _registerPaddings(registry);
  _registerRandoms(registry);
  _registerSigners(registry);
  _registerStreamCiphers(registry);
}

void _registerAsymmetricCiphers(FactoryRegistry registry) {
  registry.register(OAEPEncoding.FACTORY_CONFIG);
  registry.register(PKCS1Encoding.FACTORY_CONFIG);
  registry.register(RSAEngine.FACTORY_CONFIG);
}

void _registerBlockCiphers(FactoryRegistry registry) {
  registry.register(AESFastEngine.FACTORY_CONFIG);

  // modes
  registry.register(CBCBlockCipher.FACTORY_CONFIG);
  registry.register(CFBBlockCipher.FACTORY_CONFIG);
  registry.register(CTRBlockCipher.FACTORY_CONFIG);
  registry.register(ECBBlockCipher.FACTORY_CONFIG);
  registry.register(GCTRBlockCipher.FACTORY_CONFIG);
  registry.register(OFBBlockCipher.FACTORY_CONFIG);
  registry.register(SICBlockCipher.FACTORY_CONFIG);
}

void _registerDigests(FactoryRegistry registry) {
  registry.register(Blake2bDigest.FACTORY_CONFIG);
  registry.register(MD2Digest.FACTORY_CONFIG);
  registry.register(MD4Digest.FACTORY_CONFIG);
  registry.register(MD5Digest.FACTORY_CONFIG);
  registry.register(RIPEMD128Digest.FACTORY_CONFIG);
  registry.register(RIPEMD160Digest.FACTORY_CONFIG);
  registry.register(RIPEMD256Digest.FACTORY_CONFIG);
  registry.register(RIPEMD320Digest.FACTORY_CONFIG);
  registry.register(SHA1Digest.FACTORY_CONFIG);
  registry.register(SHA3Digest.FACTORY_CONFIG);
  registry.register(SHA224Digest.FACTORY_CONFIG);
  registry.register(SHA256Digest.FACTORY_CONFIG);
  registry.register(SHA384Digest.FACTORY_CONFIG);
  registry.register(SHA512Digest.FACTORY_CONFIG);
  registry.register(SHA512tDigest.FACTORY_CONFIG);
  registry.register(TigerDigest.FACTORY_CONFIG);
  registry.register(WhirlpoolDigest.FACTORY_CONFIG);
}

void _registerKeyDerivators(FactoryRegistry registry) {
  registry.register(PBKDF2KeyDerivator.FACTORY_CONFIG);
  registry.register(Scrypt.FACTORY_CONFIG);
}

void _registerKeyGenerators(FactoryRegistry registry) {
  registry.register(RSAKeyGenerator.FACTORY_CONFIG);
}

void _registerMacs(FactoryRegistry registry) {
  registry.register(HMac.FACTORY_CONFIG);
  registry.register(CMac.FACTORY_CONFIG);
}

void _registerPaddedBlockCiphers(FactoryRegistry registry) {
  registry.register(PaddedBlockCipherImpl.FACTORY_CONFIG);
}

void _registerPaddings(FactoryRegistry registry) {
  registry.register(PKCS7Padding.FACTORY_CONFIG);
  registry.register(ISO7816d4Padding.FACTORY_CONFIG);
  registry.register(TBCPadding.FACTORY_CONFIG);
  registry.register(x923Padding.FACTORY_CONFIG);
}

void _registerRandoms(FactoryRegistry registry) {
  registry.register(AutoSeedBlockCtrRandom.FACTORY_CONFIG);
  registry.register(BlockCtrRandom.FACTORY_CONFIG);
  registry.register(FortunaRandom.FACTORY_CONFIG);
}

void _registerSigners(FactoryRegistry registry) {
  registry.register(RSASigner.FACTORY_CONFIG);
}

void _registerStreamCiphers(FactoryRegistry registry) {
  registry.register(CTRStreamCipher.FACTORY_CONFIG);
  registry.register(Salsa20Engine.FACTORY_CONFIG);
  registry.register(Salsa8Engine.FACTORY_CONFIG);
  registry.register(Salsa12Engine.FACTORY_CONFIG);
  registry.register(SICStreamCipher.FACTORY_CONFIG);
  registry.register(HC256Engine.FACTORY_CONFIG);
  registry.register(Grain128Engine.FACTORY_CONFIG);
  registry.register(ISAACEngine.FACTORY_CONFIG);
}
