//! Provides symmetric block cipher algorithms and cipher modes.
//!
//! LibTomCrypt provides several block ciphers with an ECB block mode interface. It is important to first note that you
//! should never use the ECB modes directly to encrypt data. Instead you should use the ECB functions to make a chaining
//! mode, or use one of the provided chaining modes.
use error::{Error, Result};
use ffi;
use internal;
use std::ffi::{CStr, CString};
use std::mem;
use std::os::raw::*;
use std::slice;


/// A symmetric encryption cipher.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Cipher(c_int);

impl Cipher {
    /// Find a cipher algorithm by name.
    pub fn find(name: &str) -> Option<Self> {
        ::init();

        unsafe {
            let name = CString::new(name).unwrap();

            match ffi::find_cipher(name.as_ptr()) {
                -1 => None,
                index => Some(Cipher(index)),
            }
        }
    }

    /// Get a cipher algorithm by name. Panics if the algorithm is not available.
    fn find_required(name: &str) -> Self {
        match Self::find(name) {
            Some(hash) => hash,
            None => panic!("{} algorithm not available", name),
        }
    }

    /// Get the AES cipher algorithm.
    ///
    /// This cipher is also known as Rijndael.
    pub fn aes() -> Self {
        Cipher::find_required("aes")
    }

    /// Get the name of this cipher.
    pub fn name(&self) -> &str {
        unsafe {
            CStr::from_ptr(self.descriptor().name).to_str().unwrap()
        }
    }

    /// Get the default number of rounds for this cipher.
    pub fn default_rounds(&self) -> u32 {
        self.descriptor().default_rounds as u32
    }

    /// Get the minimum allowed key size for this cipher.
    pub fn min_key_length(&self) -> usize {
        self.descriptor().min_key_length as usize
    }

    /// Get the maximum allowed key size for this cipher.
    pub fn max_key_length(&self) -> usize {
        self.descriptor().max_key_length as usize
    }

    /// Get the block size (in octets) for this cipher.
    pub fn block_size(&self) -> usize {
        self.descriptor().block_length as usize
    }

    #[inline]
    pub(crate) fn index(&self) -> c_int {
        self.0
    }

    #[inline]
    fn descriptor(&self) -> &'static ffi::ltc_cipher_descriptor {
        unsafe {
            &*(&ffi::cipher_descriptor as *const ffi::ltc_cipher_descriptor).offset(self.0 as isize)
        }
    }
}


/// A block cipher mode of operation.
pub trait CipherMode {
    /// Encrypt the given plaintext and return the ciphertext.
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        unsafe {
            let mut ciphertext = internal::alloc(plaintext.len());
            self.encrypt_unchecked(plaintext, &mut ciphertext)?;

            Ok(ciphertext)
        }
    }

    /// Decrypt the given ciphertext and return the plaintext.
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        unsafe {
            let mut plaintext = internal::alloc(ciphertext.len());
            self.decrypt_unchecked(ciphertext, &mut plaintext)?;

            Ok(plaintext)
        }
    }

    /// Encrypt the given plaintext in place.
    fn encrypt_in_place(&mut self, buffer: &mut [u8]) -> Result<()> {
        unsafe {
            let ciphertext = slice::from_raw_parts_mut(buffer.as_mut_ptr(), buffer.len());
            self.encrypt_unchecked(buffer, ciphertext)
        }
    }

    /// Decrypt the given ciphertext in place.
    fn decrypt_in_place(&mut self, buffer: &mut [u8]) -> Result<()> {
        unsafe {
            let plaintext = slice::from_raw_parts_mut(buffer.as_mut_ptr(), buffer.len());
            self.decrypt_unchecked(buffer, plaintext)
        }
    }

    /// Encrypt the given plaintext and write the ciphertext to the given array.
    ///
    /// This method is unsafe because it is up to the caller to guarantee that the given arrays are of the same length.
    /// It is possible that the input and output buffer are the same buffer.
    unsafe fn encrypt_unchecked(&mut self, plaintext: &[u8], ciphertext: &mut [u8]) -> Result<()>;

    /// Decrypt the given ciphertext and write the plaintext to the given array.
    ///
    /// This method is unsafe because it is up to the caller to guarantee that the given arrays are of the same length.
    /// It is possible that the input and output buffer are the same buffer.
    unsafe fn decrypt_unchecked(&mut self, ciphertext: &[u8], plaintext: &mut [u8]) -> Result<()>;
}


/// ECB or Electronic Codebook Mode is the simplest method to use.
///
/// This mode is very weak since it allows people to swap blocks and perform replay attacks if the same key is used more
/// than once.
pub struct Ecb(ffi::symmetric_ECB);

impl Ecb {
    pub fn new(cipher: Cipher, key: &[u8], rounds: Option<u32>) -> Result<Self> {
        unsafe {
            let mut raw = mem::uninitialized();
            tryt!(ffi::ecb_start(cipher.index(), key.as_ptr(), key.len() as c_int, rounds.unwrap_or(0) as c_int, &mut raw));

            Ok(Ecb(raw))
        }
    }
}

impl CipherMode for Ecb {
    unsafe fn encrypt_unchecked(&mut self, plaintext: &[u8], ciphertext: &mut [u8]) -> Result<()> {
        tryt!(ffi::ecb_encrypt(plaintext.as_ptr(), ciphertext.as_mut_ptr(), plaintext.len() as u64, &mut self.0));

        Ok(())
    }

    unsafe fn decrypt_unchecked(&mut self, ciphertext: &[u8], plaintext: &mut [u8]) -> Result<()> {
        tryt!(ffi::ecb_decrypt(ciphertext.as_ptr(), plaintext.as_mut_ptr(), ciphertext.len() as u64, &mut self.0));

        Ok(())
    }
}

impl Drop for Ecb {
    fn drop(&mut self) {
        unsafe {
            ffi::ecb_done(&mut self.0);
        }
    }
}


/// CBC or Cipher Block Chaining mode is a simple mode designed to prevent trivial forms of replay and swap attacks on
/// ciphers.
///
/// It is important that the initialization vector be unique and preferably random for each message encrypted under the
/// same key.
pub struct Cbc(ffi::symmetric_CBC);

impl Cbc {
    pub fn new(cipher: Cipher, iv: &[u8], key: &[u8], rounds: Option<u32>) -> Result<Self> {
        // Validate the IV size since LibTomCrypt doesn't.
        if iv.len() != cipher.block_size() {
            return Err(Error::from_code(ffi::CRYPT_INVALID_ARG));
        }

        unsafe {
            let mut raw = mem::uninitialized();
            tryt!(ffi::cbc_start(cipher.index(), iv.as_ptr(), key.as_ptr(), key.len() as c_int, rounds.unwrap_or(0) as c_int, &mut raw));

            Ok(Cbc(raw))
        }
    }
}

impl CipherMode for Cbc {
    unsafe fn encrypt_unchecked(&mut self, plaintext: &[u8], ciphertext: &mut [u8]) -> Result<()> {
        tryt!(ffi::cbc_encrypt(plaintext.as_ptr(), ciphertext.as_mut_ptr(), plaintext.len() as u64, &mut self.0));

        Ok(())
    }

    unsafe fn decrypt_unchecked(&mut self, ciphertext: &[u8], plaintext: &mut [u8]) -> Result<()> {
        tryt!(ffi::cbc_decrypt(ciphertext.as_ptr(), plaintext.as_mut_ptr(), ciphertext.len() as u64, &mut self.0));

        Ok(())
    }
}

impl Drop for Cbc {
    fn drop(&mut self) {
        unsafe {
            ffi::cbc_done(&mut self.0);
        }
    }
}


/// CTR or Counter Mode is a mode which only uses the encryption function of the cipher.
///
/// As long as the initialization vector is random for each message encrypted under the same key replay and swap attacks
/// are infeasible. CTR mode may look simple but it is as secure as the block cipher is under a chosen plaintext attack
/// (provided the initialization vector is unique).
pub struct Ctr(ffi::symmetric_CTR);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CtrEndianness {
    BigEndian,
    LittleEndian,
}

impl Ctr {
    pub fn new(cipher: Cipher, iv: &[u8], key: &[u8], rounds: Option<u32>, mode: CtrEndianness) -> Result<Self> {
        let ctr_flags = iv.len() as c_int | match mode {
            CtrEndianness::BigEndian => ffi::CTR_COUNTER_BIG_ENDIAN,
            CtrEndianness::LittleEndian => ffi::CTR_COUNTER_LITTLE_ENDIAN,
        } as c_int;

        unsafe {
            let mut raw = mem::uninitialized();

            tryt!(ffi::ctr_start(
                cipher.index(),
                iv.as_ptr(),
                key.as_ptr(),
                key.len() as c_int,
                rounds.unwrap_or(0) as c_int,
                ctr_flags,
                &mut raw,
            ));

            Ok(Ctr(raw))
        }
    }
}

impl CipherMode for Ctr {
    unsafe fn encrypt_unchecked(&mut self, plaintext: &[u8], ciphertext: &mut [u8]) -> Result<()> {
        tryt!(ffi::ctr_encrypt(plaintext.as_ptr(), ciphertext.as_mut_ptr(), plaintext.len() as u64, &mut self.0));

        Ok(())
    }

    unsafe fn decrypt_unchecked(&mut self, ciphertext: &[u8], plaintext: &mut [u8]) -> Result<()> {
        tryt!(ffi::ctr_decrypt(ciphertext.as_ptr(), plaintext.as_mut_ptr(), ciphertext.len() as u64, &mut self.0));

        Ok(())
    }
}

impl Drop for Ctr {
    fn drop(&mut self) {
        unsafe {
            ffi::ctr_done(&mut self.0);
        }
    }
}


/// CFB or Ciphertext Feedback Mode is a mode akin to CBC.
pub struct Cfb(ffi::symmetric_CFB);

impl Cfb {
    pub fn new(cipher: Cipher, iv: &[u8], key: &[u8], rounds: Option<u32>) -> Result<Self> {
        unsafe {
            let mut raw = mem::uninitialized();
            tryt!(ffi::cfb_start(
                cipher.index(),
                iv.as_ptr(),
                key.as_ptr(),
                key.len() as c_int,
                rounds.unwrap_or(0) as c_int,
                &mut raw,
            ));

            Ok(Cfb(raw))
        }
    }
}

impl CipherMode for Cfb {
    unsafe fn encrypt_unchecked(&mut self, plaintext: &[u8], ciphertext: &mut [u8]) -> Result<()> {
        tryt!(ffi::cfb_encrypt(plaintext.as_ptr(), ciphertext.as_mut_ptr(), plaintext.len() as u64, &mut self.0));

        Ok(())
    }

    unsafe fn decrypt_unchecked(&mut self, ciphertext: &[u8], plaintext: &mut [u8]) -> Result<()> {
        tryt!(ffi::cfb_decrypt(ciphertext.as_ptr(), plaintext.as_mut_ptr(), ciphertext.len() as u64, &mut self.0));

        Ok(())
    }
}

impl Drop for Cfb {
    fn drop(&mut self) {
        unsafe {
            ffi::cfb_done(&mut self.0);
        }
    }
}


/// OFB or Output Feedback Mode is a mode akin to CBC as well.
pub struct Ofb(ffi::symmetric_OFB);

impl Ofb {
    pub fn new(cipher: Cipher, iv: &[u8], key: &[u8], rounds: Option<u32>) -> Result<Self> {
        unsafe {
            let mut raw = mem::uninitialized();

            tryt!(ffi::ofb_start(
                cipher.index(),
                iv.as_ptr(),
                key.as_ptr(), key.len() as c_int,
                rounds.unwrap_or(0) as c_int,
                &mut raw,
            ));

            Ok(Ofb(raw))
        }
    }
}

impl CipherMode for Ofb {
    unsafe fn encrypt_unchecked(&mut self, plaintext: &[u8], ciphertext: &mut [u8]) -> Result<()> {
        tryt!(ffi::ofb_encrypt(plaintext.as_ptr(), ciphertext.as_mut_ptr(), plaintext.len() as u64, &mut self.0));

        Ok(())
    }

    unsafe fn decrypt_unchecked(&mut self, ciphertext: &[u8], plaintext: &mut [u8]) -> Result<()> {
        tryt!(ffi::ofb_decrypt(ciphertext.as_ptr(), plaintext.as_mut_ptr(), ciphertext.len() as u64, &mut self.0));

        Ok(())
    }
}

impl Drop for Ofb {
    fn drop(&mut self) {
        unsafe {
            ffi::ofb_done(&mut self.0);
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn test_find_cipher() {
        assert_eq!(Cipher::find("aes").unwrap(), Cipher::aes());

        for name in &["aes", "des", "blowfish"] {
            let cipher = Cipher::find(name).unwrap();
            assert_eq!(cipher.name(), *name);
        }
    }

    #[test]
    fn aes_ecb_simple() {
        let key = [1; 16];
        let data = vec![2; Cipher::aes().block_size()];
        let mut buffer = data.clone();

        let mut ecb = Ecb::new(Cipher::aes(), key.as_ref(), None).unwrap();

        ecb.encrypt_in_place(&mut buffer).unwrap();
        ecb.decrypt_in_place(&mut buffer).unwrap();

        assert_eq!(buffer, data);
    }
}
