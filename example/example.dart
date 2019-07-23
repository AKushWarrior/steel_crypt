import 'package:steel_crypt/steel_crypt.dart';

main() {

  var key = CryptKey().genKey();

  var encrypter = Crypt(key, 'Salsa20');

  var hasher = HashCrypt('SHA-3');



  print(hasher.hash('a'));

  print(encrypter.encrypt('word'));

  print(encrypter.decrypt(encrypter.encrypt('word')));

  print(key);

}
