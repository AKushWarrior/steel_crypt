part of 'satellite.dart';

class CbcSatellite {
  String key;
  PaddingAES padding;

  CbcSatellite(this.key, this.padding);

  String encrypt({required String inp, required String iv}) {
    var key = base64Decode(this.key);
    var ivBytes = base64Decode(iv);
    dynamic params = (padding == PaddingAES.none)
        ? ParametersWithIV(KeyParameter(key), ivBytes)
        : PaddedBlockCipherParameters(
            ParametersWithIV(KeyParameter(key), ivBytes), null);
    var cipher = (padding == PaddingAES.none)
        ? CBCBlockCipher(AESFastEngine())
        : PaddedBlockCipher('AES/CBC/' + parsePadding(padding));
    cipher.init(true, params);
    var inter = cipher.process(utf8.encode(inp) as Uint8List);
    return base64.encode(inter);
  }

  String decrypt({required String enc, required String iv}) {
    var key = base64Decode(this.key);
    var encryptedBytes = base64Decode(enc);
    var ivBytes = base64Decode(iv);
    dynamic params = (padding == PaddingAES.none)
        ? ParametersWithIV(KeyParameter(key), ivBytes)
        : PaddedBlockCipherParameters(
            ParametersWithIV(KeyParameter(key), ivBytes), null);
    var cipher = (padding == PaddingAES.none)
        ? CBCBlockCipher(AESFastEngine())
        : PaddedBlockCipher('AES/CBC/' + parsePadding(padding));
    cipher.init(false, params);
    var inter = cipher.process(encryptedBytes);
    return utf8.decode(inter);
  }
}

class CbcSatelliteRaw {
  Uint8List key;
  PaddingAES padding;

  CbcSatelliteRaw(this.key, this.padding);

  Uint8List encrypt({required Uint8List inp, required Uint8List iv}) {
    dynamic params = (padding == PaddingAES.none)
        ? ParametersWithIV(KeyParameter(key), iv)
        : PaddedBlockCipherParameters(
            ParametersWithIV(KeyParameter(key), iv), null);
    var cipher = (padding == PaddingAES.none)
        ? CBCBlockCipher(AESFastEngine())
        : PaddedBlockCipher('AES/CBC/' + parsePadding(padding));
    cipher.init(true, params);
    return cipher.process(inp);
  }

  Uint8List decrypt({required Uint8List enc, required Uint8List iv}) {
    dynamic params = (padding == PaddingAES.none)
        ? ParametersWithIV(KeyParameter(key), iv)
        : PaddedBlockCipherParameters(
            ParametersWithIV(KeyParameter(key), iv), null);
    var cipher = (padding == PaddingAES.none)
        ? CBCBlockCipher(AESFastEngine())
        : PaddedBlockCipher('AES/CBC/' + parsePadding(padding));
    cipher.init(false, params);
    return cipher.process(enc);
  }
}
