use std::mem::{self, transmute};
use std::os::raw::*;
use std::ptr;

use {ffi, rand, Result};

/// A private or public elliptic curve key.
#[derive(Debug)]
pub struct EccKey(ffi::ecc_key);

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
    pub fn new(prng: rand::Algorithm, keysize: c_uint) -> Result<Self> {
        unsafe {
            let mut k = mem::uninitialized();
            tryt!(ffi::ecc_make_key(
                ptr::null_mut(),
                prng.index(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shared_secret() {
        let k1 = EccKey::new(rand::Algorithm::sprng(), 12).unwrap();
        let k2 = EccKey::new(rand::Algorithm::sprng(), 12).unwrap();
        let len = 16;
        let secret = EccKey::create_shared_secret(&k1, &k2, len).unwrap();
        assert!(secret.len() <= len);
    }
}
