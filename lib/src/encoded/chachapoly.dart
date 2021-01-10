//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2021 Aditya Kishore

// ignore_for_file: unnecessary_getters_setters

part of '../steel_crypt_base.dart';

/// This is an ChaCha20-Poly1305 symmetric encryption machine. Various modes and
/// paddings are available.
///
/// This version of ChaChaPolyCrypt is encoded. It expects keys and IVs to be
/// base-64 encoded, and returns base64 encoded Strings. Plaintext should be UTF-8.
/// For more flexibility, ChaChaPolyCryptRaw is recommended.
class ChaChaPolyCrypt {
  String _key32;

  ///Creates 'Crypt', serves as encrypter/decrypter of text.
  ///
  /// [key] should be base-64 encoded.
  ChaChaPolyCrypt({@required String key}) {
    _key32 = key;
  }

  ///Encrypts (with iv) and return in base 64.
  ///
  /// IV should be base-64 encoded. Input should be a valid UTF-8 string.
  ///
  /// [aad] is optional, ChaCha20-Poly1305 is secure without it.
  String encrypt(
      {@required String inp,
      @required String iv,
      String aad,
      int tagLength = 128}) {
    var key = base64Decode(_key32);
    var ivLocal = base64Decode(iv);
    var localInput = utf8.encode(inp);
    var aadLocal = aad != null ? base64Decode(aad) : null;

    var cipherparams =
        AEADParameters(KeyParameter(key), tagLength, ivLocal, aadLocal);
    var cipher = ChaCha20Poly1305(ChaCha7539Engine(), Poly1305());
    cipher.init(true, cipherparams);

    var inter = cipher.process(localInput as Uint8List);
    return base64.encode(inter);
  }

  /// Decrypts (with iv) and return in base 64.
  ///
  /// IV should be base-64 encoded. [encrypted] should be the result of
  /// ChaCha20-Poly1305 encryption, encoded in base-64. [encrypt] takes care of
  /// this for you.
  ///
  /// [aad] is optional, ChaCha20-Poly1305 is secure without it.
  String decrypt(
      {@required String enc,
      @required String iv,
      String aad,
      int tagLength = 128}) {
    var key = base64Decode(_key32);
    var ivLocal = base64Decode(iv);
    var localInput = base64Decode(enc);
    var aadLocal = aad != null ? base64Decode(aad) : null;

    var cipherparams =
        AEADParameters(KeyParameter(key), tagLength, ivLocal, aadLocal);
    var cipher = ChaCha20Poly1305(ChaCha7539Engine(), Poly1305());
    cipher.init(false, cipherparams);

    var inter = cipher.process(localInput);
    return utf8.decode(inter);
  }
}
