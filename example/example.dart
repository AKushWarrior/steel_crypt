import 'package:steel_crypt/steel_crypt.dart';

main() {

  var private = CryptKey().genKey();



  var encrypter = SymCrypt(private, 'AES');

  var encrypter2 = RsaCrypt();


  var hasher = HashCrypt('sha256');

  var hasher2 = HashCrypt('md5');


  var iv = CryptKey().genIV(16);



  print(private);


  print(hasher.hash('word'));

  var hash = hasher.hash('word');

  print(hasher.checkpass('word', hash));


  print(hasher2.hashHMAC('word', private));


  print(encrypter.encrypt('word', iv));

  String crypted = encrypter.encrypt('word', iv);

  print(encrypter.decrypt(crypted, iv));



  var crypted2 = encrypter2.encrypt('word', "This is authentication text...");

  print(encrypter2.getString(crypted2));

  print(encrypter2.decrypt(crypted2));

}