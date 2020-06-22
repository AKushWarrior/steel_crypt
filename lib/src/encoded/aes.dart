//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2020 Aditya Kishore

// ignore_for_file: unnecessary_getters_setters

part of '../steel_crypt_base.dart';

/// This is an AES symmetric encryption machine. Various modes and paddings are
/// available.
///
/// This version of AesCrypt is encoded. It expects keys and IVs to be base-64 encoded,
/// and returns base64 encoded Strings. Plaintext should be UTF-8.
/// For more flexibility, AesCryptRaw is recommended.
class AesCrypt {
  ModeAES _mode;
  String _key32;
  PaddingAES _padding;

  ///Get this AesCrypt's type of padding.
  PaddingAES get padding {
    return _padding;
  }

  set padding(PaddingAES set) {
    _padding = set;
  }

  ///Get this AesCrypt's mode of AES.
  ModeAES get mode {
    return _mode;
  }

  set mode(ModeAES set) {
    _mode = set;
  }

  ///Creates 'Crypt', serves as encrypter/decrypter of text.
  ///
  /// [key] should be base-64 encoded.
  AesCrypt(
      {@required ModeAES mode,
      @required PaddingAES padding,
      @required String key}) {
    _mode = mode;
    _key32 = key;
    _padding = padding;
  }

  ///Encrypts (with iv) and return in base 64.
  ///
  /// IV should be base-64 encoded. Input should be a valid UTF-8 string.
  ///
  /// Only pass [aad] if you are using GCM. It should be base-64 encoded if you
  /// pass it. Even if you are using GCM, [aad] is optional. GCM is still secure
  /// without it.
  core.String encrypt(String input, {@required String iv, String aad}) {
    if (_mode != ModeAES.ecb && _mode != ModeAES.gcm) {
      if (_mode == ModeAES.ctr || _mode == ModeAES.sic) {
        var key = base64Decode(_key32);
        var ivLocal = base64Decode(iv);
        var localInput = utf8.encode(input);

        var params = ParametersWithIV<KeyParameter>(KeyParameter(key), ivLocal);
        var cipher = SICStreamCipher(AESFastEngine());
        cipher..init(true, params);

        var inter = cipher.process(localInput as Uint8List);
        return base64.encode(inter);
      } else {
        var key = base64Decode(_key32);
        var ivLocal = base64Decode(iv);

        CipherParameters params = PaddedBlockCipherParameters(
            ParametersWithIV<KeyParameter>(KeyParameter(key), ivLocal), null);
        var cipher = PaddedBlockCipher(
            'AES/' + _parseAES(_mode) + '/' + _parsePadding(_padding));
        cipher..init(true, params);

        var inter = cipher.process(utf8.encode(input) as Uint8List);
        return base64.encode(inter);
      }
    } else if (mode == ModeAES.gcm) {
      var key = base64Decode(_key32);
      var ivLocal = base64Decode(iv);
      var localInput = utf8.encode(input);
      var aadLocal = aad != null ? base64Decode(aad) : null;

      var cipherparams =
          AEADParameters(KeyParameter(key), 128, ivLocal, aadLocal);
      var params = PaddedBlockCipherParameters(cipherparams, null);
      var cipher = PaddedBlockCipherImpl(
          Padding(_parsePadding(padding)), GCMBlockCipher(AESFastEngine()));
      cipher..init(true, params);

      var inter = cipher.process(localInput as Uint8List);
      return base64.encode(inter);
    } else {
      var key = base64Decode(_key32);

      CipherParameters params =
          PaddedBlockCipherParameters(KeyParameter(key), null);
      var cipher = PaddedBlockCipher(
          'AES/' + _parseAES(mode) + '/' + _parsePadding(padding));
      cipher..init(true, params);

      var inter = cipher.process(base64.decode(input));
      return base64.encode(inter);
    }
  }

  /// Decrypt base 64 (with iv) and return original.
  ///
  /// [encrypted] should be base-64 encoded. If you used [encrypt], this is taken
  /// care of for you. [iv] should also be base-64 encoded.
  ///
  /// Only pass [aad] if you are using GCM. It should be base-64 encoded if you
  /// pass it.
  String decrypt(String encrypted, {@required String iv, String aad}) {
    if (_mode != ModeAES.ecb) {
      if (_padding == PaddingAES.none) {
        var localKey = base64Decode(_key32);
        var localIV = base64Decode(iv);
        var localInput = base64.decode(encrypted);

        var params =
            ParametersWithIV<KeyParameter>(KeyParameter(localKey), localIV);
        var cipher = SICStreamCipher(AESFastEngine());
        cipher..init(false, params);

        var inter = cipher.process(localInput);
        return utf8.decode(inter);
      } else {
        var key = base64Decode(_key32);
        var ivLocal = base64Decode(iv);

        CipherParameters params = PaddedBlockCipherParameters(
            ParametersWithIV(KeyParameter(key), ivLocal), null);
        var cipher = PaddedBlockCipher(
            'AES/' + _parseAES(mode) + '/' + _parsePadding(padding));
        cipher..init(false, params);

        var inter = cipher.process(base64.decode(encrypted));
        return utf8.decode(inter);
      }
    } else if (mode == ModeAES.gcm) {
      var key = base64Decode(_key32);
      var ivLocal = base64Decode(iv);
      var localInput = base64.decode(encrypted);
      var aadLocal = aad != null ? base64Decode(aad) : null;

      var cipherparams =
          AEADParameters(KeyParameter(key), 128, ivLocal, aadLocal);
      var params = PaddedBlockCipherParameters(cipherparams, null);
      var cipher = PaddedBlockCipherImpl(
          Padding(_parsePadding(padding)), GCMBlockCipher(AESFastEngine()));
      cipher..init(false, params);

      var inter = cipher.process(localInput);
      return utf8.decode(inter);
    } else {
      var key = base64Decode(_key32);

      CipherParameters params =
          PaddedBlockCipherParameters(KeyParameter(key), null);
      var cipher = PaddedBlockCipher(
          'AES/' + _parseAES(mode) + '/' + _parsePadding(padding));
      cipher..init(false, params);

      var inter = cipher.process(base64.decode(encrypted));
      return utf8.decode(inter);
    }
  }
}

enum ModeAES { cbc, sic, cfb64, ofb64, ctr, gctr, ecb, gcm }

enum PaddingAES { pkcs7, x923, iso78164, tbc, none }

String _parsePadding(PaddingAES padding) {
  switch (padding) {
    case PaddingAES.pkcs7:
      return 'PKCS7';
    case PaddingAES.x923:
      return 'X9.23';
    case PaddingAES.iso78164:
      return 'ISO7816-4';
    case PaddingAES.tbc:
      return 'TBC';
    default:
      return 'None';
  }
}

String _parseAES(ModeAES mode) {
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
    case ModeAES.sic:
      return 'SIC';
  }
  throw ArgumentError('invalid mode (internal, file an issue!)');
}
