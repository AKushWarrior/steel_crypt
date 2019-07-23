import 'package:steel_crypt/steel_crypt.dart';

main() {

  var key = CryptKey().genKey();

  var encrypter = Crypt(key, 'Salsa20');

  var hasher = HashCrypt('SHA-3/256');



  print(hasher.hash('word'));

  print(encrypter.encrypt('word'));

  print(encrypter.decrypt(encrypter.encrypt('word')));

  print(key);

}
