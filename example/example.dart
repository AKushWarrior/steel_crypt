import 'package:steel_crypt/steel_crypt.dart';

main() {

  var private = CryptKey().genKey();

  var public = CryptKey().genKey();


  var encrypter = SymCrypt(private, 'AES');

  var encrypter2 = RsaCrypt(private, public);


  var hasher = HashCrypt('sha256');

  var hasher2 = HashCrypt('md5');


  var iv = CryptKey().genIV(16);



  print(private);


  print(hasher.hash('word'));

  var hash = hasher.hash('word');

  print(hasher.checkpass('word', hash));


  print(hasher.hashHMAC('word', private));


  print(encrypter.encrypt('word', iv));

  String crypted = encrypter.encrypt('word', iv);

  print(encrypter.decrypt(crypted, iv));


  print(encrypter2.encrypt("word"));

  String crypted2 = encrypter2.encrypt('word');

  print(encrypter2.decrypt(crypted2));

}