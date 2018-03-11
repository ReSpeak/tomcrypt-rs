//! Provides algorithm implementations of message authentication codes.
use ffi;
use hash::Hash;
use std::mem;
use std::os::raw::*;
use symmetric::Cipher;
use util;
use Result;


/// A message authentication code algorithm.
pub trait Mac: Sized {
    /// Add data to the message being processed.
    fn process<I: AsRef<[u8]>>(&mut self, input: I) -> Result<()>;

    /// Finishes the MAC routine and returns the MAC code.
    fn done(self) -> Result<Vec<u8>>;

    /// Compute the MAC of `input`.
    fn sign<I: AsRef<[u8]>>(mut self, input: I) -> Result<Vec<u8>> {
        self.process(input)?;
        self.done()
    }

    /// Computes the MAC of `input` and verifies the result matches `signature`.
    fn verify<I: AsRef<[u8]>, S: AsRef<[u8]>>(self, input: I, signature: S) -> Result<bool> {
        let mac = self.sign(input)?;
        Ok(util::compare_slices(&mac, signature.as_ref()))
    }
}


/// Computes a Hash-based Message Authentication Code (HMAC).
pub struct Hmac {
    hash: Hash,
    raw: ffi::hmac_state,
}

impl Hmac {
    /// Initialize a new HMAC with a hash algorithm and key.
    pub fn new(hash: Hash, key: &[u8]) -> Result<Hmac> {
        unsafe {
            let mut raw = mem::uninitialized();

            tryt! {
                ffi::hmac_init(&mut raw, hash.index(), key.as_ptr(), key.len() as c_ulong)
            };

            Ok(Hmac {
                hash: hash,
                raw: raw,
            })
        }
    }

    /// Get the hash algorithm used by this HMAC.
    pub fn hash(&self) -> &Hash {
        &self.hash
    }
}

impl Mac for Hmac {
    fn process<I: AsRef<[u8]>>(&mut self, input: I) -> Result<()> {
        let input = input.as_ref();

        unsafe {
            tryt! {
                ffi::hmac_process(&mut self.raw, input.as_ptr(), input.len() as c_ulong)
            };
        }

        Ok(())
    }

    fn done(mut self) -> Result<Vec<u8>> {
        let mut output = vec![0; self.hash.size() as usize];
        let mut output_len = output.len() as c_ulong;

        unsafe {
            tryt! {
                ffi::hmac_done(&mut self.raw, output.as_mut_ptr(), &mut output_len)
            };
        }

        Ok(output)
    }
}


/// OMAC, which stands for _One-Key CBC MAC_ is an algorithm which produces a Message Authentication Code (MAC) using
/// only a block cipher such as AES.
pub struct Omac {
    cipher: Cipher,
    raw: ffi::omac_state,
}

impl Omac {
    /// Initialize a new OMAC with an encryption cipher and key.
    pub fn new(cipher: Cipher, key: &[u8]) -> Result<Self> {
        unsafe {
            let mut raw = mem::uninitialized();

            tryt! {
                ffi::omac_init(&mut raw, cipher.index(), key.as_ptr(), key.len() as c_ulong)
            };

            Ok(Self {
                cipher: cipher,
                raw: raw,
            })
        }
    }

    /// Get the cipher algorithm used by this OMAC.
    pub fn cipher(&self) -> &Cipher {
        &self.cipher
    }
}

impl Mac for Omac {
    fn process<I: AsRef<[u8]>>(&mut self, input: I) -> Result<()> {
        let input = input.as_ref();

        unsafe {
            tryt! {
                ffi::omac_process(&mut self.raw, input.as_ptr(), input.len() as c_ulong)
            };
        }

        Ok(())
    }

    fn done(mut self) -> Result<Vec<u8>> {
        let mut output = vec![0; self.cipher.block_size()];
        let mut output_len = output.len() as c_ulong;

        unsafe {
            tryt! {
                ffi::omac_done(&mut self.raw, output.as_mut_ptr(), &mut output_len)
            };
        }

        Ok(output)
    }
}


/// The PMAC protocol is another MAC algorithm that relies solely on a symmetric-key block cipher.
pub struct Pmac {
    cipher: Cipher,
    raw: ffi::pmac_state,
}

impl Pmac {
    /// Initialize a new PMAC with an encryption cipher and key.
    pub fn new(cipher: Cipher, key: &[u8]) -> Result<Self> {
        unsafe {
            let mut raw = mem::uninitialized();

            tryt! {
                ffi::pmac_init(&mut raw, cipher.index(), key.as_ptr(), key.len() as c_ulong)
            };

            Ok(Self {
                cipher: cipher,
                raw: raw,
            })
        }
    }

    /// Get the cipher algorithm used by this PMAC.
    pub fn cipher(&self) -> &Cipher {
        &self.cipher
    }
}

impl Mac for Pmac {
    fn process<I: AsRef<[u8]>>(&mut self, input: I) -> Result<()> {
        let input = input.as_ref();

        unsafe {
            tryt! {
                ffi::pmac_process(&mut self.raw, input.as_ptr(), input.len() as c_ulong)
            };
        }

        Ok(())
    }

    fn done(mut self) -> Result<Vec<u8>> {
        let mut output = vec![0; self.cipher.block_size()];
        let mut output_len = output.len() as c_ulong;

        unsafe {
            tryt! {
                ffi::pmac_done(&mut self.raw, output.as_mut_ptr(), &mut output_len)
            };
        }

        Ok(output)
    }
}


#[cfg(test)]
mod tests {
    use std::iter::repeat;
    use super::*;


    /// Run test vectors from http://tools.ietf.org/html/rfc2104.
    #[test]
    fn test_hmac_md5() {
        let parameters = [
            (
                repeat(0x0bu8).take(16).collect::<Vec<u8>>(),
                b"Hi There".to_vec(),
                [0x92, 0x94, 0x72, 0x7a, 0x36, 0x38, 0xbb, 0x1c,
                0x13, 0xf4, 0x8e, 0xf8, 0x15, 0x8b, 0xfc, 0x9d],
            ),
            (
                b"Jefe".to_vec(),
                b"what do ya want for nothing?".to_vec(),
                [
                    0x75, 0x0c, 0x78, 0x3e, 0x6a, 0xb0, 0xb5, 0x03,
                    0xea, 0xa8, 0x6e, 0x31, 0x0a, 0x5d, 0xb7, 0x38
                ],
            ),
            (
                repeat(0xaau8).take(16).collect::<Vec<u8>>(),
                repeat(0xddu8).take(50).collect::<Vec<u8>>(),
                [
                    0x56, 0xbe, 0x34, 0x52, 0x1d, 0x14, 0x4c, 0x88,
                    0xdb, 0xb8, 0xc7, 0x33, 0xf0, 0xe8, 0xb3, 0xf6
                ],
            ),
        ];

        for &(ref key, ref input, ref expected) in &parameters {
            let mut hmac = Hmac::new(Hash::md5(), key).unwrap();
            assert!(hmac.verify(input, expected).unwrap());
        }
    }
}
