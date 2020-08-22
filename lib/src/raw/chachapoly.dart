//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

// © 2020 Aditya Kishore

// ignore_for_file: unnecessary_getters_setters

part of '../steel_crypt_base.dart';

/// This is an ChaCha20-Poly1305 symmetric encryption machine. Various modes and
/// paddings are available.
///
/// This version of ChaChaPolyCrypt is raw. It expects keys and IVs to be
/// Uint8List, and returns Uint8List. For a higher-level solution, see
/// [ChaChaPolyCrypt] (not raw).
class ChaChaPolyCryptRaw {
  Uint8List _key32;

  ///Creates 'Crypt', serves as encrypter/decrypter of text.
  ChaChaPolyCryptRaw({@required Uint8List key}) {
    _key32 = key;
  }

  /// Encrypts (with iv).
  ///
  /// [aad] is optional, ChaCha20-Poly1305 is secure without it.
  Uint8List encrypt(
      {@required Uint8List inp,
      @required Uint8List iv,
      Uint8List aad,
      int tagLength = 128}) {
    var cipherparams = AEADParameters(KeyParameter(_key32), tagLength, iv, aad);
    var cipher = ChaCha20Poly1305(ChaCha7539Engine(), Poly1305());
    cipher.init(true, cipherparams);

    var inter = cipher.process(inp);
    return inter;
  }

  /// Decrypts (with iv).
  ///
  /// [aad] is optional, ChaCha20-Poly1305 is secure without it.
  Uint8List decrypt(
      {@required Uint8List enc,
      @required Uint8List iv,
      Uint8List aad,
      int tagLength = 128}) {
    var cipherparams = AEADParameters(KeyParameter(_key32), tagLength, iv, aad);
    var cipher = ChaCha20Poly1305(ChaCha7539Engine(), Poly1305());
    cipher.init(false, cipherparams);

    var inter = cipher.process(enc);
    return inter;
  }
}
