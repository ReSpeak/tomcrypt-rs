//! [LibTomCrypt](https://github.com/libtom/libtomcrypt) is a fairly
//! comprehensive, modular and portable cryptographic
//! toolkit that provides developers with a vast array of well known published
//! block ciphers, one-way hash functions, chaining modes, pseudo-random number
//! generators, public key cryptography and a plethora of other routines.
//!
//! At the moment, only ecc and eax are exposed by these bindings, it should be
//! easy to add more features.
//!
//! I do not plan to add more functionality myself because I do not need it,
//! pull requests or people, who are willing to overtake this project and expand
//! the crate, are welcome though.
//!
//! # Usage
//!
//! Add the following to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! tomcrypt = "0.1"
//! ```

#[macro_use]
extern crate failure;
#[cfg(test)]
extern crate hex;
extern crate tomcrypt_sys;

use error::Result;
use std::sync::{Once, ONCE_INIT};

#[macro_use]
mod error;
mod internal;
pub mod aead;
pub mod ecc;
pub mod hash;
pub mod mac;
pub mod rand;
pub mod symmetric;
pub mod util;

pub mod ffi {
    pub use tomcrypt_sys::*;
    pub use tomcrypt_sys::_bindgen_ty_2 as Error;
}

pub use error::Error;

/// Initialize the LibTomCrypt library.
///
/// Usually you do not need to call this manually, as it is lazily called when needed.
///
/// Calling this function more than once has no effect.
pub fn init() {
    static INIT: Once = ONCE_INIT;

    INIT.call_once(|| unsafe {
        ffi::init_TFM();
        ffi::register_all_ciphers();
        ffi::register_all_hashes();
        ffi::register_all_prngs();
    });
}
