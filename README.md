# Steel Crypt 2.0. (BETA)

A comprehensive library of high-level, cryptographic API's, either manually defined or pulled from PointyCastle.
This library currently supports hashing, symmetric two-way encryption, and key/IV generation. It also has 
a CLI, for conducting basic cryptography operations.

---

It takes time, effort, and mental power to keep this package updated, useful, and
improving. If you used or are using the package, I'd appreciate it if you could spare a few 
dollars to help me continue development.

[![PayPal](https://img.shields.io/static/v1?label=PayPal&message=Donate&color=blue&logo=paypal&style=for-the-badge&labelColor=black)](https://www.paypal.me/kishoredev)

---

## Note: Beta

Please note that this package is in a beta release for 2.0. It may not be production stable in its
current form. If you want production stability, wait two weeks for the full launch of 2.0 or use 1.7.1+1.

---

## Note: Documentation

These docs have not been fully written yet! Steel Crypt 2.0 comes with major changes, and will have a static
website on GitHub Pages for documentation. For now, you can take a look at the API reference for more
information on the beta's classes.

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

###### ©2019 Aditya Kishore
###### Licensed under the Mozilla Public License 2.0
###### This project is built on a custom implementation of Steven Roose's PointyCastle.
