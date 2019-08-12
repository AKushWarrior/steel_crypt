// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.src.registry.ec_standard_curve_constructor;

import "../ecc/ecc_base.dart";
import "../ecc/ecc_fp.dart" as fp;
import "../src/utils.dart" as utils;

ECDomainParametersImpl constructFpStandardCurve(
    String name, Function constructor,
    {BigInt q, BigInt a, BigInt b, BigInt g, BigInt n, BigInt h, BigInt seed}) {
  var curve = new fp.ECCurve(q, a, b);
  var seedBytes = (seed == null) ? null : utils.encodeBigInt(seed);
  return constructor(
      name, curve, curve.decodePoint(utils.encodeBigInt(g)), n, h, seedBytes);
}
