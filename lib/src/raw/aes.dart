//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2020 Aditya Kishore

// ignore_for_file: unnecessary_getters_setters

part of '../steel_crypt_base.dart';

/// This is an AES symmetric encryption machine. Various modes and paddings are
/// available.
///
/// This version of AesCrypt is raw. It expects keys and IVs to be Uint8List,
/// and returns Uint8Lists. For more flexibility, [AesCrypt] is recommended.
class AesCryptRaw {
  ModeAES _mode;
  Uint8List _key32;
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
  AesCryptRaw(
      {@required ModeAES mode,
      @required PaddingAES padding,
      @required Uint8List key}) {
    _mode = mode;
    _key32 = key;
    _padding = padding;
  }

  /// Encrypts (with iv).
  ///
  /// Only pass [aad] if you are using GCM. Even if you are using GCM, [aad] is
  /// optional. GCM is still secure without it.
  Uint8List encrypt(Uint8List input, {@required Uint8List iv, Uint8List aad}) {
    if (_mode != ModeAES.ecb && _mode != ModeAES.gcm) {
      if (_mode == ModeAES.ctr || _mode == ModeAES.sic) {
        var key = _key32;
        var ivLocal = iv;
        var localInput = input;

        var params = ParametersWithIV<KeyParameter>(KeyParameter(key), ivLocal);
        var cipher = SICStreamCipher(AESFastEngine());
        cipher..init(true, params);

        var inter = cipher.process(localInput);
        return inter;
      } else {
        var key = _key32;
        var ivLocal = iv;

        CipherParameters params = PaddedBlockCipherParameters(
            ParametersWithIV<KeyParameter>(KeyParameter(key), ivLocal), null);
        var cipher = PaddedBlockCipher(
            'AES/' + _parseAES(_mode) + '/' + _parsePadding(_padding));
        cipher..init(true, params);

        var inter = cipher.process(input);
        return inter;
      }
    } else if (mode == ModeAES.gcm) {
      var key = _key32;
      var ivLocal = iv;
      var aadLocal = aad;

      var cipherparams =
          AEADParameters(KeyParameter(key), 128, ivLocal, aadLocal);
      var params = PaddedBlockCipherParameters(cipherparams, null);
      var cipher = PaddedBlockCipherImpl(
          Padding(_parsePadding(padding)), GCMBlockCipher(AESFastEngine()));
      cipher..init(true, params);

      var inter = cipher.process(input);
      return inter;
    } else {
      var key = _key32;

      CipherParameters params =
          PaddedBlockCipherParameters(KeyParameter(key), null);
      var cipher = PaddedBlockCipher(
          'AES/' + _parseAES(mode) + '/' + _parsePadding(padding));
      cipher..init(true, params);

      var inter = cipher.process(input);
      return inter;
    }
  }

  /// Decrypt (with iv) and return original.
  ///
  /// Only pass [aad] if you are using GCM. [aad] is optional even if you are
  /// using gcm.
  Uint8List decrypt(Uint8List encrypted,
      {@required Uint8List iv, Uint8List aad}) {
    if (_mode != ModeAES.ecb) {
      if (_padding == PaddingAES.none) {
        var localKey = _key32;
        var localInput = encrypted;

        var params = ParametersWithIV<KeyParameter>(KeyParameter(localKey), iv);
        var cipher = SICStreamCipher(AESFastEngine());
        cipher..init(false, params);

        var inter = cipher.process(localInput);
        return inter;
      } else {
        var key = _key32;
        var ivLocal = iv;

        CipherParameters params = PaddedBlockCipherParameters(
            ParametersWithIV(KeyParameter(key), ivLocal), null);
        var cipher = PaddedBlockCipher(
            'AES/' + _parseAES(mode) + '/' + _parsePadding(padding));
        cipher..init(false, params);

        var inter = cipher.process(encrypted);
        return inter;
      }
    } else if (mode == ModeAES.gcm) {
      var key = _key32;
      var ivLocal = iv;
      var localInput = encrypted;
      var aadLocal = aad;

      var cipherparams =
          AEADParameters(KeyParameter(key), 128, ivLocal, aadLocal);
      var params = PaddedBlockCipherParameters(cipherparams, null);
      var cipher = PaddedBlockCipherImpl(
          Padding(_parsePadding(padding)), GCMBlockCipher(AESFastEngine()));
      cipher..init(false, params);

      var inter = cipher.process(localInput);
      return inter;
    } else {
      var key = _key32;

      CipherParameters params =
          PaddedBlockCipherParameters(KeyParameter(key), null);
      var cipher = PaddedBlockCipher(
          'AES/' + _parseAES(mode) + '/' + _parsePadding(padding));
      cipher..init(false, params);

      var inter = cipher.process(encrypted);
      return inter;
    }
  }
}
