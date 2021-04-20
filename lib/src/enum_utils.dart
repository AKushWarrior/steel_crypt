import 'package:pointycastle/api.dart';
import 'package:pointycastle/macs/hmac.dart';

import 'enum.dart';

HMac parsePBKDF2(HmacHash mode) {
  return HMac(Digest(parseHash(mode.toString())), 128);
}

String parseHash(String mode) {
  var partial = mode.split('.')[1];
  if (partial.startsWith('Sha_')) {
    var split = partial.split('_');
    partial = 'SHA-' + split[1];
  } else if (partial.startsWith('Sha3')) {
    var split = partial.split('_');
    partial = 'SHA-3/' + split[1];
  } else if (partial.startsWith('K')) {
    var split = partial.split('_');
    partial = 'Keccak/' + split[1];
  } else if (partial.startsWith('R')) {
    var split = partial.split('_');
    partial = 'RIPEMD-' + split[1];
  } else if (partial.startsWith('Sha1')) {
    partial = 'SHA-1';
  }
  return partial;
}

String parsePadding(PaddingAES padding) {
  switch (padding) {
    case PaddingAES.pkcs7:
      return 'PKCS7';
    case PaddingAES.iso78164:
      return 'ISO7816-4';
    default:
      return 'None';
  }
}

String stringifyStream(StreamAlgo algorithm) {
  var str = algorithm.toString().substring(11).replaceAll('_', '/');
  if (str.startsWith('chacha')) {
    str = str.replaceRange(0, 6, 'ChaCha');
  } else if (str.startsWith('salsa')) {
    str = str.replaceRange(0, 5, 'Salsa');
  }
  return str;
}
