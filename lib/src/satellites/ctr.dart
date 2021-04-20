part of 'satellite.dart';

class CtrSatellite {
  String key;

  CtrSatellite(this.key);

  String encrypt({required String inp, required String iv}) {
    var key = base64Decode(this.key);
    var ivBytes = base64Decode(iv);

    var params = ParametersWithIV(KeyParameter(key), ivBytes);
    var cipher = CTRStreamCipher(AESFastEngine());
    cipher.init(true, params);

    var inter = cipher.process(utf8.encode(inp) as Uint8List);
    return base64.encode(inter);
  }

  String decrypt({required String enc, required String iv}) {
    var key = base64Decode(this.key);
    var encryptedBytes = base64Decode(enc);
    var ivBytes = base64Decode(iv);

    var params = ParametersWithIV(KeyParameter(key), ivBytes);
    var cipher = CTRStreamCipher(AESFastEngine());
    cipher.init(false, params);

    var inter = cipher.process(encryptedBytes);
    return utf8.decode(inter);
  }
}

class CtrSatelliteRaw {
  Uint8List key;

  CtrSatelliteRaw(this.key);

  Uint8List encrypt({required Uint8List inp, required Uint8List iv}) {
    var params = ParametersWithIV(KeyParameter(key), iv);
    var cipher = CTRStreamCipher(AESFastEngine())..init(true, params);
    return cipher.process(inp);
  }

  Uint8List decrypt({required Uint8List enc, required Uint8List iv}) {
    var params = ParametersWithIV(KeyParameter(key), iv);
    var cipher = CTRStreamCipher(AESFastEngine())..init(false, params);

    return cipher.process(enc);
  }
}
