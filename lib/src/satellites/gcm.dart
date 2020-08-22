part of 'satellite.dart';

class GcmSatellite {
  String key;
  PaddingAES padding;

  GcmSatellite(this.key, this.padding);

  String encrypt({@required String inp, @required String iv, String aad}) {
    var key = base64Decode(this.key);
    var ivBytes = base64Decode(iv);
    var aadBytes = aad == null ? null : base64Decode(aad);

    dynamic params = (padding == PaddingAES.none)
        ? AEADParameters(KeyParameter(key), 128, ivBytes, aadBytes)
        : PaddedBlockCipherParameters(
            AEADParameters(KeyParameter(key), 128, ivBytes, aadBytes), null);
    var cipher = (padding == PaddingAES.none)
        ? GCMBlockCipher(AESFastEngine())
        : PaddedBlockCipher('AES/GCM/' + parsePadding(padding));
    cipher..init(true, params);

    var inter = cipher.process(utf8.encode(inp) as Uint8List);
    return base64.encode(inter);
  }

  String decrypt({
    @required String enc,
    @required String iv,
    String aad
  }) {
    var key = base64Decode(this.key);
    var encryptedBytes = base64Decode(enc);
    var ivBytes = base64Decode(iv);
    var aadBytes = aad == null ? null : base64Decode(aad);

    dynamic params = (padding == PaddingAES.none)
        ? AEADParameters(KeyParameter(key), 128, ivBytes, aadBytes)
        : PaddedBlockCipherParameters(
            AEADParameters(KeyParameter(key), 128, ivBytes, aadBytes), null);
    var cipher = (padding == PaddingAES.none)
        ? GCMBlockCipher(AESFastEngine())
        : PaddedBlockCipher('AES/GCM/' + parsePadding(padding));
    cipher..init(false, params);

    var inter = cipher.process(encryptedBytes);
    return utf8.decode(inter);
  }
}

class GcmSatelliteRaw {
  Uint8List key;
  PaddingAES padding;

  GcmSatelliteRaw(this.key, this.padding);

  Uint8List encrypt({
    @required Uint8List inp,
    @required Uint8List iv,
    Uint8List aad
  }) {
    dynamic params = (padding == PaddingAES.none)
        ? AEADParameters(KeyParameter(key), 128, iv, aad)
        : PaddedBlockCipherParameters(
            AEADParameters(KeyParameter(key), 128, iv, aad), null);
    var cipher = (padding == PaddingAES.none)
        ? GCMBlockCipher(AESFastEngine())
        : PaddedBlockCipher('AES/GCM/' + parsePadding(padding));
    cipher..init(true, params);

    return cipher.process(inp);
  }

  Uint8List decrypt({
    @required Uint8List enc,
    @required Uint8List iv,
    Uint8List aad
  }) {
    dynamic params = (padding == PaddingAES.none)
        ? AEADParameters(KeyParameter(key), 128, iv, aad)
        : PaddedBlockCipherParameters(
            AEADParameters(KeyParameter(key), 128, iv, aad), null);
    var cipher = (padding == PaddingAES.none)
        ? GCMBlockCipher(AESFastEngine())
        : BlockCipher('AES/GCM/' + parsePadding(padding));
    cipher..init(false, params);

    return cipher.process(enc);
  }
}
