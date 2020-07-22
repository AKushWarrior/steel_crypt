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
  String _key32;
  PaddingAES _padding;

  ///Get this AesCrypt's type of padding.
  PaddingAES get padding {
    return _padding;
  }

  set padding(PaddingAES set) {
    _padding = set;
  }

  ///Creates 'Crypt', serves as encrypter/decrypter of text.
  ///
  /// [key] should be base-64 encoded.
  AesCrypt({@required PaddingAES padding, @required String key}) {
    _key32 = key;
    _padding = padding;
  }

  GcmSatellite get gcm => GcmSatellite(_key32, padding);
  CtrSatellite get ctr => CtrSatellite(_key32);
  EcbSatellite get ecb => EcbSatellite(_key32, padding);
  CbcSatellite get cbc => CbcSatellite(_key32, padding);
  GctrSatellite get gctr64 => GctrSatellite(_key32, padding);
  CfbSatellite get cfb64 => CfbSatellite(_key32, padding);
  OfbSatellite get ofb64 => OfbSatellite(_key32, padding);
}
