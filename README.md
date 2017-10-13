tomcrypt &emsp; [![latest version](https://img.shields.io/crates/v/tomcrypt.svg)](https://crates.io/crates/tomcrypt) [![documentation](https://docs.rs/tomcrypt/badge.svg)](https://docs.rs/tomcrypt)
=====================
[LibTomCrypt](https://github.com/libtom/libtomcrypt) is a fairly comprehensive, modular and portable cryptographic
toolkit that provides developers with a vast array of well known published
block ciphers, one-way hash functions, chaining modes, pseudo-random number
generators, public key cryptography and a plethora of other routines.

At the moment, only ecc and eax are exposed by these bindings, it should be
easy to add more features.

I do not plan to add more functionality myself because I do not need it,
pull requests or people, who are willing to overtake this project and expand
the crate, are welcome though.

## Usage

Add the following to your `Cargo.toml`:

```toml
[dependencies]
tomcrypt = "0.1"
```

License
-------
Licensed under either of

 * [Apache License, Version 2.0](LICENSE-APACHE)
 * [MIT license](LICENSE-MIT)

at your option.
