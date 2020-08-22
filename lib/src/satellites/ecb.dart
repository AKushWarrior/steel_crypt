part of 'satellite.dart';

class EcbSatellite {
  String key;
  PaddingAES padding;

  EcbSatellite(this.key, this.padding);

  String encrypt({@required String inp}) {
    var key = base64Decode(this.key);

    dynamic params = (padding == PaddingAES.none)
        ? KeyParameter(key)
        : PaddedBlockCipherParameters(KeyParameter(key), null);
    var cipher = (padding == PaddingAES.none)
        ? ECBBlockCipher(AESFastEngine())
        : PaddedBlockCipher('AES/ECB/' + parsePadding(padding));
    cipher.init(true, params);

    var inter = cipher.process(utf8.encode(inp) as Uint8List);
    return base64.encode(inter);
  }

  String decrypt({@required String enc}) {
    var key = base64Decode(this.key);
    var encryptedBytes = base64Decode(enc);

    CipherParameters params =
        PaddedBlockCipherParameters(KeyParameter(key), null);
    var cipher = (padding == PaddingAES.none)
        ? ECBBlockCipher(AESFastEngine())
        : PaddedBlockCipher('AES/ECB/' + parsePadding(padding));
    cipher.init(false, params);

    var inter = cipher.process(encryptedBytes);
    return utf8.decode(inter);
  }
}

class EcbSatelliteRaw {
  Uint8List key;
  PaddingAES padding;

  EcbSatelliteRaw(this.key, this.padding);

  Uint8List encrypt({@required Uint8List inp}) {
    dynamic params = (padding == PaddingAES.none)
        ? KeyParameter(key)
        : PaddedBlockCipherParameters(KeyParameter(key), null);
    var cipher = (padding == PaddingAES.none)
        ? ECBBlockCipher(AESFastEngine())
        : PaddedBlockCipher('AES/ECB/' + parsePadding(padding));
    cipher.init(true, params);

    return cipher.process(inp);
  }

  Uint8List decrypt({@required Uint8List enc}) {
    dynamic params = (padding == PaddingAES.none)
        ? KeyParameter(key)
        : PaddedBlockCipherParameters(KeyParameter(key), null);
    var cipher = (padding == PaddingAES.none)
        ? ECBBlockCipher(AESFastEngine())
        : PaddedBlockCipher('AES/ECB/' + parsePadding(padding));
    cipher.init(false, params);

    return cipher.process(enc);
  }
}
