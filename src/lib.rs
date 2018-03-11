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
use std::ffi::*;
use std::mem::{self, transmute};
use std::os::raw::*;
use std::ptr;
use std::sync::{Once, ONCE_INIT};
use symmetric::Cipher;

#[macro_use]
mod error;
mod internal;
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


/// A random number generator.
#[derive(Clone, Debug)]
pub struct Rng(c_int);
/// A private or public elliptic curve key.
#[derive(Debug)]
pub struct EccKey(ffi::ecc_key);
/// Authenticated encryption mode.
#[derive(Clone)]
pub struct EaxState(ffi::eax_state);

impl EccKey {
    /// Create a new ecc key pair.
    ///
    /// Supported key sizes:
    ///
    /// | keysize | #bits |
    /// |---------|-------|
    /// | 12      | 112   |
    /// | 16      | 128   |
    /// | 20      | 160   |
    /// | 24      | 192   |
    /// | 28      | 224   |
    /// | 32      | 256   |
    /// | 48      | 384   |
    /// | 65      | 521   |
    pub fn new(prng: Rng, keysize: c_uint) -> Result<Self> {
        unsafe {
            let mut k = mem::uninitialized();
            tryt!(ffi::ecc_make_key(
                ptr::null_mut(),
                prng.0,
                keysize as c_int,
                &mut k as *mut ffi::ecc_key
            ));
            Ok(EccKey(k))
        }
    }

    /// Import a private or public ecc key from the tomcrypt format.
    pub fn import(data: &[u8]) -> Result<Self> {
        unsafe {
            let mut res = mem::uninitialized();
            tryt!(ffi::ecc_import(
                data.as_ptr(),
                data.len() as c_ulong,
                &mut res
            ));
            Ok(EccKey(res))
        }
    }

    /// Export public ecc key in the tomcrypt format.
    pub fn export_public(&self) -> Result<Vec<u8>> {
        unsafe {
            let mut buf = vec![0; ffi::ECC_BUF_SIZE as usize];
            let mut len = buf.len() as c_ulong;
            tryt!(ffi::ecc_export(
                buf.as_mut_ptr(),
                &mut len,
                transmute(ffi::PK_PUBLIC),
                transmute(&self.0),
            ));
            buf.truncate(len as usize);
            Ok(buf)
        }
    }

    /// Export private ecc key in the tomcrypt format.
    pub fn export_private(&self) -> Result<Vec<u8>> {
        unsafe {
            let mut buf = vec![0; ffi::ECC_BUF_SIZE as usize];
            let mut len = buf.len() as c_ulong;
            tryt!(ffi::ecc_export(
                buf.as_mut_ptr(),
                &mut len,
                transmute(ffi::PK_PRIVATE),
                transmute(&self.0),
            ));
            buf.truncate(len as usize);
            Ok(buf)
        }
    }

    /// If this key stores a private key.
    pub fn is_private(&self) -> bool {
        self.0.type_ == ffi::PK_PRIVATE as c_int
    }

    /// Derive a shared secret from a private and a public key.
    ///
    /// The length of the generated secret is less or equal to the specified
    /// length. If the specified length is too low, an error will be returned.
    pub fn create_shared_secret(
        private_key: &EccKey,
        public_key: &EccKey,
        len: usize,
    ) -> Result<Vec<u8>> {
        unsafe {
            let mut buf = vec![0; len];
            let mut len = len as c_ulong;
            tryt!(ffi::ecc_shared_secret(
                transmute(&private_key.0),
                transmute(&public_key.0),
                buf.as_mut_ptr(),
                &mut len
            ));
            buf.truncate(len as usize);
            Ok(buf)
        }
    }
}

impl Drop for EccKey {
    fn drop(&mut self) {
        unsafe {
            ffi::ecc_free(&mut self.0);
        }
    }
}

impl EaxState {
    /// Create a new eax mode state from a key and a nonce.
    ///
    /// The header parameter optionally contains (public) data, that will
    /// influence the generated authentication tag (also called mac).
    pub fn new(cipher: Cipher, key: &[u8], nonce: &[u8], header: Option<&[u8]>)
        -> Result<Self> {
        unsafe {
            let (h, h_len) = if let Some(header) = header {
                (header.as_ptr(), header.len() as c_ulong)
            } else {
                (ptr::null(), 0)
            };
            let mut k = mem::uninitialized();
            tryt!(ffi::eax_init(
                &mut k as *mut ffi::eax_state,
                cipher.index(),
                key.as_ptr(),
                key.len() as c_ulong,
                nonce.as_ptr(),
                nonce.len() as c_ulong,
                h,
                h_len
            ));
            Ok(EaxState(k))
        }
    }

    /// Encrypts the given data in place.
    pub fn encrypt_in_place(&mut self, data: &mut [u8]) -> Result<()> {
        unsafe {
            tryt!(ffi::eax_encrypt(
                &mut self.0,
                data.as_ptr(),
                data.as_mut_ptr(),
                data.len() as c_ulong
            ));
        }
        Ok(())
    }

    /// Encrypts the given data.
    pub fn encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        unsafe {
            let mut res = vec![0; data.len()];
            tryt!(ffi::eax_encrypt(
                &mut self.0,
                data.as_ptr(),
                res.as_mut_ptr(),
                data.len() as c_ulong
            ));
            Ok(res)
        }
    }

    /// Decrypts the given data in place.
    pub fn decrypt_in_place(&mut self, data: &mut [u8]) -> Result<()> {
        unsafe {
            tryt!(ffi::eax_decrypt(
                &mut self.0,
                data.as_ptr(),
                data.as_mut_ptr(),
                data.len() as c_ulong
            ));
        }
        Ok(())
    }

    /// Decrypts the given data.
    pub fn decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        unsafe {
            let mut res = vec![0; data.len()];
            tryt!(ffi::eax_decrypt(
                &mut self.0,
                data.as_ptr(),
                res.as_mut_ptr(),
                data.len() as c_ulong
            ));
            Ok(res)
        }
    }

    /// Generate the authentication tag (mac) with the given length.
    pub fn finish(mut self, tag_len: usize) -> Result<Vec<u8>> {
        let mut res = vec![0; tag_len];
        unsafe {
            let mut len = tag_len as c_ulong;
            tryt!(ffi::eax_done(&mut self.0, res.as_mut_ptr(), &mut len));
            res.drain((len as usize)..);
        }
        Ok(res)
    }
}

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

/// Get the sprng.
pub fn sprng() -> Rng {
    ::init();
    Rng(unsafe {
        ffi::find_prng(CString::new("sprng").unwrap().as_ptr())
    })
}


#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn test_eax_loop() {
        let key = [1; 16];
        let nonce = [2; 16];
        let header = [3; 3];
        let data = [4; 10];
        let tag_len = 7;

        // Encrypt
        let mut eax = EaxState::new(Cipher::aes(), &key, &nonce, Some(&header))
            .unwrap();
        let enc = eax.encrypt(&data).unwrap();
        let tag = eax.finish(tag_len).unwrap();

        // Decrypt
        let mut eax = EaxState::new(Cipher::aes(), &key, &nonce, Some(&header))
            .unwrap();
        let dec = eax.decrypt(&enc).unwrap();
        let tag2 = eax.finish(tag_len).unwrap();

        assert_eq!(tag, tag2);
        assert_eq!(&data, dec.as_slice());
    }

    #[test]
    fn test_shared_secret() {
        let k1 = EccKey::new(sprng(), 12).unwrap();
        let k2 = EccKey::new(sprng(), 12).unwrap();
        let len = 16;
        let secret = EccKey::create_shared_secret(&k1, &k2, len).unwrap();
        assert!(secret.len() <= len);
    }
}
