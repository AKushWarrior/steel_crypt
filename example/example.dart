import 'package:steel_crypt/steel_crypt.dart';

main() {

  var private = CryptKey().genKey();


  var encrypter = SymCrypt(private, 'AES');

  var encrypter2 = RsaCrypt();


  var hasher = HashCrypt();

  var hasher2 = HashCrypt('SHA-3/256');


  var iv = CryptKey().genIV(16);


  //Print key
  print ("Key:");

  print(private);

  print("");


  //SHA-3 512 Hash
  print("SHA-3 512 Hash:");

  print(hasher.hash('word'));

  var hash = hasher.hash('word');

  print(hasher.checkpass('word', hash));

  print("");


  //HMAC SHA-3 256 Hash
  print("HMAC SHA-3 256 Hash:");

  print(hasher2.hashHMAC('word', private));

  print("");


  //AES Symmetric
  print("AES Symmetric:");

  print(encrypter.encrypt('word', iv));

  String crypted = encrypter.encrypt('word', iv);

  print(encrypter.decrypt(crypted, iv));

  print("");


  //RSA Asymmetric
  print("RSA Asymmetric:");

  var crypted2 = encrypter2.encrypt("word", encrypter2.pubKey);

  print(crypted2);

  print(encrypter2.decrypt(crypted2, encrypter2.privKey));

  print("");
}