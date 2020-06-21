## 2.0.1
- Fixed glitch in PBKDF2

## 2.0.0
- Breaking API changes
- Deleted unused stream ciphers
- Added Poly1305
- Added ChaCha20-Poly1305
- Added "raw" classes working with Uint8List

## 1.7.1 - 1.7.1+1
- Fixed critical Digest insecurity issue
- Affects anyone using a number of algorithms:
    - SHA-224, SHA-256, and SHA-1
    - RIPEMD (all versions)
    - MD4 and MD5
    - PBKDF2 with any of the above
- Affected people should update ASAP

## 1.6.1
- Fixed critical keyspace issue
- Fixed bug with RSA PEM parsing
- Updated dependencies
- Minor README updates

## 1.5.4 - 1.5.4+1
- Changes to random generation to adjust for base-64 bugs
- Use UTF-8 encoding more (wherever possible)
- Started work on TEA algorithm
- Updated asn1lib to placate pub

## 1.5.2 - 1.5.3
- RSA parsing improved
    - Added option to parse key from PEM string, not just files
    - Added option to encode key to PEM string
- Minor changes to MacCrypt
- Formatting changes for pub's new, super-strict linting
    - New casting reqs. might cause marginal slowdown
    - I'm trying to get that rating out of the dump
    - Also having to fix bugs that come with migrating a whole codebase
    - NNBD has been adopted by Pub before Dart?
    - Nothing should be broken; leave bugs in the issue tracker

## 1.5.1-1.5.1+2
- Made MacCrypt more consistent with standards
- Improved CMAC to function better
- Added GCM and GCTR to AES
- Improved README with note on prior knowledge

## 1.4.1+1
- No functional update
- Changed example to be more efficient

## 1.4.1 BREAKING
- Revamped ChaCha20 algorithm to:
    * Be compliant with the original definition
    * Work with the UTF-8 charset
- Bettered documentation
- Cleaned up code

## 1.3.2-1.3.2+1
- Fixed bug in ECB mode for AES
- Cleaned up code
- Updated README for AES bugfix

## 1.3.1+1
- Changed defaults for a couple classes
- Cleaned up code a little bit
- Got rid of those pesky new keywords
- Reformatted src directory
- No functional change unless you're using defaults

## 1.3.1
- Intro new algorithm: RC4
- Better documentation
- Better, more consistent README

## 1.3.0 BREAKING
- Introduced RSA key parsing from PEM
- ```.pubKey``` and ```.privKey``` getters are now ```.randPubKey``` and ```.randPrivKey```
 
## 1.2.0+2
- More major README edits
- Still no functional change

## 1.2.0+1
- Fixed major README issue
- No functional change

## 1.2.0
- Total revamp of PassCrypt()
- Scrypt password hashing now available (and default)
- PBKDF2 base algorithm now changeable
- Lowered PBKDF2 rounds to 10000 to increase speed

## 1.1.2
- New padding option: ISO10126-2
- Security fix to X9.23 padding

## 1.1.1+1 & 1.1.1+2
- README edits
- No functional change

## 1.1.1
- Various bug fixes regarding static variables
- README edits for clarity

## 1.1.0
- Added Grain-128 algorithm
- Added ISAAC algorithm
- README updates

## 1.0.1+1 to 1.0.1+3
- Minor Readme update
- No functional change

## 1.0.1
- Fixed breaking bug in CMAC
- Added HC-256 algorithm

## 1.0.0 - Breaking!
- Release version! This package is now stable and tested.
- Old .hashHMAC class now obsolete
- Added new MacCrypt() class with CMAC and HMAC
- Added two new padding options for AES

## 0.8.2+1
- Minor updates to pubspec
- No functional change

## 0.8.2
- New reduced-round variants of Salsa20
- Better documentation
- Minor bug fixes to hashing classes

## 0.8.1+1 to 0.8.1+5
- Bettered code health for pub
- No functional improvement

## 0.8.1
- Revamped AES with new padding and better explanation in README
- Made HashCrypt and PassCrypt less buggy to use
- Changed pointycastle dependency to github in order to get new padding
- Phased out encrypt package
- Added two new variants of ChaCha20

## 0.7.1+2
- Minor Readme update
- No functional change

## 0.7.1+1
- Minor Readme update
- No functional change

## 0.7.1 - Breaking!
- Revamped KeyCrypt() to have two methods
- One generating with Fortuna
- Other generating with Random.secure()
- Old key generation method no longer works

## 0.6.2
- Made it so HashCrypt() and PassCrypt() work with all strings
- Updated AES documentation in README to reflect different modes

## 0.6.1+1
- Hotfix for breaking bug regarding meta package
- Fixes ChaCha20

## 0.6.1 - Breaking!
- Reorganization of files
- Implemented ChaCha20
- Changed SymCrypt() to AesCrypt()
- Moved Salsa20 and ChaCha20 to new LightCrypt() class
- Ditched Threefish due to lack of demand

## 0.5.5+1
- Enforce IV uniqueness in SymCrypt class
- Minor updates to README
- Work begins in threefish.dart

## 0.5.5
- Changed IV + Key generation to Fortuna for increased speed + entropy
- Increases security, but no front-end changes
- Improved runtime efficiency by declaring top-end variables and helper functions static
- Decreased PassCrypt rounds from 20000 to 15000 to decrease runtime 

## 0.5.4+1
- Added Mozilla License notice + copyright to every code file
- Included copyright at bottom of README
- Updated README Notes + TODO's
- No functional improvement

## 0.5.4
- Fixing hash funct. of CLI

## 0.5.3+4
- Disregard, README isn't processing properly
- No functional improvement

## 0.5.3+3
- More README fixes
- Still no functional improvement

## 0.5.3+2
- README looks terrible on pub, patched
- No functional improvement

## 0.5.3+1
- Edited README to illustrate best usage of CLI
- No functional improvement

## 0.5.3
- Added new CLI to increase ease of use

## 0.5.2+1
- Improved documentation to adhere to dartdoc standard
- Increased key generation security to overkill

## 0.5.2
- Added better, more complete password hashing
- Updated example and README

## 0.5.1
- Traded to more traditional RSA solution
- Got rid of crypto_tools as dependency
- Changes to README and pubspec reflect this
- Cleaned up example

## 0.4.1+1
- Added to 'Reading' sect. of readme
- No functional improvement

## 0.4.1
- Exposed base PointyCastle api to get a bunch of new hashes
- Got rid of crypto dependency
- Updated pubspec and README to reflect changes

## 0.3.2+1
- Lowered Dart SDK requirement

## 0.3.2
- Fixed RSA encryption
- Updated example

## 0.3.1
- Added RSA encryption
- Added plaintext-hashtext checks
- Updated example to correspond with prior two
- Added Reading section to README

## 0.2.1+1
- Updated README

## 0.2.1
- Fixed major, breaking bugs
- Moved away from PointyCastle to reduce package size

## 0.1.2
- Github repository added to pubspec

## 0.1.1
- Project created with:
    - Two-way encryption (AES and Salsa20)
    - Hashing (Most major hashes)
    

