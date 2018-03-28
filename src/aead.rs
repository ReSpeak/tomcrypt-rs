use std::mem;
use std::os::raw::*;
use std::ptr;

use {ffi, Result};
use symmetric::Cipher;

/// Authenticated encryption mode.
#[derive(Clone)]
pub struct EaxState(ffi::eax_state);

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
}
