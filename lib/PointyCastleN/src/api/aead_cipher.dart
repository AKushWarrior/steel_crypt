part of '../../api.dart';

abstract class AEADCipher {
  void init(bool forEncryption, CipherParameters params);

  String get algorithmName;

  void processAADByte(int inp);

  void processAADBytes(Uint8List inp, int inpOff, int len);

  int processByte(int inp, Uint8List out, int outOff);

  int processBytes(
      Uint8List inp, int inOff, int len, Uint8List out, int outOff);

  int doFinal(Uint8List out, int outOff);

  Uint8List get mac;

  int getUpdateOutputSize(int len);

  int getOutputSize(int len);

  void reset();
}
