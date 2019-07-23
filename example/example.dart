import 'package:steel_crypt/steel_crypt.dart';

main() {

  var key = CryptKey().genKey();

  var encrypter = Crypt(key, 'Salsa20');

  var hasher = HashCrypt('sha256');

  var hasher2 = HashCrypt('sha256');

  var iv = CryptKey().genIV(16);


  print(key);

  print(hasher.hash('word'));

  print(hasher.hashHMAC('word', key));

  print(encrypter.encrypt('word', iv));

  String crypted = encrypter.encrypt('word', iv);

  print(encrypter.decrypt(crypted, iv));

}