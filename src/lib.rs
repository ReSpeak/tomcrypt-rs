//! [LibTomCrypt](https://github.com/libtom/libtomcrypt) is a fairly comprehensive, modular and portable cryptographic
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

// Limit for error_chain
#![recursion_limit = "1024"]

#[macro_use]
extern crate error_chain;
extern crate tomcrypt_sys;

use std::ffi::*;
use std::mem::{self, transmute};
use std::os::raw::*;
use std::ptr;

pub mod ffi {
    pub use tomcrypt_sys::*;
    pub use tomcrypt_sys::_bindgen_ty_2 as Error;
}

#[allow(unused_doc_comment)]
pub mod errors {
    // Create the Error, ErrorKind, ResultExt, and Result types
    error_chain! {
        foreign_links {
            Io(::std::io::Error);
        }
        errors {
            Tomcrypt(e: ::ffi::_bindgen_ty_2) {
                description("tomcrypt error")
                display("tomcrypt error {}", unsafe {
                    ::CStr::from_ptr(::ffi::error_to_string(*e as ::c_int))
                        .to_str().unwrap()
                })
            }
        }
    }
}
use errors::*;

macro_rules! tryt {
    ($e:expr) => {
        match mem::transmute($e) {
            ffi::CRYPT_OK => (),
            e => bail!(ErrorKind::Tomcrypt(e)),
        }
    };
}

/// A random number generator.
#[derive(Clone, Debug)]
pub struct Rng(c_int);
/// A cipher.
#[derive(Clone, Debug)]
pub struct Cipher(c_int);
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
    pub fn export_public(&mut self) -> Result<Vec<u8>> {
        unsafe {
            let mut buf = vec![0; ffi::ECC_BUF_SIZE as usize];
            let mut len = buf.len() as c_ulong;
            tryt!(ffi::ecc_export(
                buf.as_mut_ptr(),
                &mut len,
                transmute(ffi::PK_PUBLIC),
                &mut self.0
            ));
            buf.truncate(len as usize);
            Ok(buf)
        }
    }

    /// Export private ecc key in the tomcrypt format.
    pub fn export_private(&mut self) -> Result<Vec<u8>> {
        unsafe {
            let mut buf = vec![0; ffi::ECC_BUF_SIZE as usize];
            let mut len = buf.len() as c_ulong;
            tryt!(ffi::ecc_export(
                buf.as_mut_ptr(),
                &mut len,
                transmute(ffi::PK_PRIVATE),
                &mut self.0
            ));
            buf.truncate(len as usize);
            Ok(buf)
        }
    }

    /// Derive a shared secret from a private and a public key.
    pub fn create_shared_secret(
        private_key: &mut EccKey,
        public_key: &mut EccKey,
        len: usize,
    ) -> Result<Vec<u8>> {
        unsafe {
            let mut buf = vec![0; len];
            let mut len = len as c_ulong;
            tryt!(ffi::ecc_shared_secret(
                &mut private_key.0,
                &mut public_key.0,
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
    pub fn new(cipher: Cipher, key: &[u8], nonce: &[u8], header: Option<&[u8]>) -> Result<Self> {
        unsafe {
            let (h, h_len) = if let Some(header) = header {
                (header.as_ptr(), header.len() as c_ulong)
            } else {
                (ptr::null(), 0)
            };
            let mut k = mem::uninitialized();
            tryt!(ffi::eax_init(
                &mut k as *mut ffi::eax_state,
                cipher.0,
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

/// Init the tomcrypt library.
pub fn init() {
    unsafe {
        ffi::init_TFM();
    }
}

/// Register the system pseudo random number generator.
pub fn register_sprng() -> Result<()> {
    unsafe {
        tryt!(ffi::register_prng(&ffi::sprng_desc));
    }
    Ok(())
}

/// Get the sprng, it has to be registered first using [`register_sprng`].
///
/// [`register_sprng`]: fn.register_sprng.html
pub fn sprng() -> Rng {
    Rng(unsafe {
        ffi::find_prng(CString::new("sprng").unwrap().as_ptr())
    })
}

/// Register the rijndael cipher (aes).
pub fn register_rijndael_cipher() -> Result<()> {
    unsafe {
        tryt!(ffi::register_cipher(&ffi::rijndael_desc));
    }
    Ok(())
}

/// Get the rijndael cipher (aes), it has to be registered first using
/// [`register_rijndael_cipher`].
///
/// [`register_rijndael_cipher`]: fn.register_rijndael_cipher.html
pub fn rijndael() -> Cipher {
    Cipher(unsafe {
        ffi::find_cipher(CString::new("rijndael").unwrap().as_ptr())
    })
}
