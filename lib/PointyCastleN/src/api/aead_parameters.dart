part of '../../api.dart';

class AEADParameters<UnderlyingCipherParameters extends CipherParameters>
    implements CipherParameters {
  final UnderlyingCipherParameters parameters;

  final Uint8List associatedData;

  final Uint8List nonce;

  final int macSize;

  AEADParameters(
      this.parameters, this.macSize, this.nonce, this.associatedData);
}
