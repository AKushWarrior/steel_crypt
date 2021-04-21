# Steel Crypt 3.0 (BETA)

A comprehensive library of high-level, cryptographic API's, either manually defined or pulled from PointyCastle.
This library currently supports hashing, symmetric two-way encryption, and key/IV generation. It also has 
a CLI, for conducting basic cryptography operations.

This library is a high-level wrapper over https://github.com/bcgit/pc-dart. It used to contain a fork of PointyCastle
within it, but since the package came under the ownership of the BouncyCastle organization, the additions to the fork 
have been added upstream. 

---

It takes time, effort, and mental power to keep this package updated, useful, and
improving. If you used or are using the package, I'd appreciate it if you could spare a few 
dollars to help me continue development.

[![PayPal](https://img.shields.io/static/v1?label=PayPal&message=Donate&color=blue&logo=paypal&style=for-the-badge&labelColor=black)](https://www.paypal.me/kishoredev)

---

## Null Safety

This library has been fully ported to null safety. The version 3.0.0 is identical functionally to 2.3.1+6, except for 
this porting process. There may be some slight variance in the interface, due to parameters becoming required where
they were formerly "optional" named parameters. 

---

## Note: Documentation

These docs have not been fully written yet! Steel Crypt 3.X comes with major changes, and will have a static
website on GitHub Pages for documentation. For now, you can take a look at the API reference for more
information on the beta's classes. Each class has fairly extensive documentation.

---

## Note: RSA Deprecation

As I looked at the package landscape on pub.dev, it became clear to me that packages have become oversaturated, causing
difficult decisions for independent developers. I fear contributing to this issue. 

Additionally, I haven't studied asymmetric encryption; I don't feel comfortable working with it and don't think this
package is adding much to the ecosystem as far as asymmetric encryption goes.

As of today, I will be deprecating RSA functionality in steel_crypt. It is clear to me that there are better packages
for asymmetric encryption; I highly encourage affected users to check out https://pub.dev/packages/crypton. The dev there
actively works on supporting asymmetric operations, more than I ever could, and has a deeper scope of features than this
package would have ever had.

---

[![Pub](https://img.shields.io/pub/v/steel_crypt?color=blue&label=pub&logo=Steel%20Crypt&logoColor=blue&style=for-the-badge&labelColor=black)](https://pub.dev/packages/steel_crypt)
[![License](https://img.shields.io/github/license/AKushWarrior/steel_crypt?color=blue&style=for-the-badge&labelColor=black)](https://www.mozilla.org/en-US/MPL/2.0/)
[![Commits](https://img.shields.io/github/commit-activity/m/AKushWarrior/steel_crypt?color=blue&style=for-the-badge&labelColor=black)](https://github.com/AKushWarrior/steel_crypt)

###### ©2021 Aditya Kishore
###### Licensed under the Mozilla Public License 2.0
