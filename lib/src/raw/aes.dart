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

  ///Creates 'Crypt', serves as encrypter/decrypter of text.
  AesCryptRaw({@required PaddingAES padding, @required Uint8List key}) {
    _key32 = key;
    _padding = padding;
  }

  GcmSatelliteRaw get gcm => GcmSatelliteRaw(_key32, padding);
  CtrSatelliteRaw get ctr => CtrSatelliteRaw(_key32);
  EcbSatelliteRaw get ecb => EcbSatelliteRaw(_key32, padding);
  CbcSatelliteRaw get cbc => CbcSatelliteRaw(_key32, padding);
  GctrSatelliteRaw get gctr64 => GctrSatelliteRaw(_key32, padding);
  CfbSatelliteRaw get cfb64 => CfbSatelliteRaw(_key32, padding);
  OfbSatelliteRaw get ofb64 => OfbSatelliteRaw(_key32, padding);
}
