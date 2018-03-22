//! Random number generation and pseudo-random number algorithms.
use ffi;
use std::ffi::{CStr, CString};
use std::io;
use std::mem;
use std::os::raw::*;
use Result;


/// A pseudo-random number generator algorithm.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrngAlgorithm(c_int);

impl Default for PrngAlgorithm {
    fn default() -> PrngAlgorithm {
        PrngAlgorithm::chacha20()
    }
}

impl PrngAlgorithm {
    pub fn find(name: &str) -> Option<Self> {
        ::init();

        unsafe {
            let name = CString::new(name).unwrap();

            match ffi::find_prng(name.as_ptr()) {
                -1 => None,
                index => Some(PrngAlgorithm(index)),
            }
        }
    }

    /// Get a PRNG algorithm by name. Panics if the algorithm is not available.
    fn find_required(name: &str) -> Self {
        match Self::find(name) {
            Some(prng) => prng,
            None => panic!("{} algorithm not available", name),
        }
    }

    /// Secure PRNG using the system RNG.
    ///
    /// This algorithm implements the PRNG interface by using the system RNG underneath the hood. Adding entropy to an
    /// SPRNG does nothing.
    pub fn sprng() -> Self {
        Self::find_required("sprng")
    }

    /// ChaCha20 stream cipher algorithm as a PRNG (recommended, fast).
    pub fn chacha20() -> Self {
        Self::find_required("chacha20")
    }

    /// Fast long-term PRNG (recommended, secure).
    pub fn fortuna() -> Self {
        Self::find_required("fortuna")
    }

    /// Get the name of the PRNG.
    pub fn name(&self) -> &str {
        unsafe {
            CStr::from_ptr(self.descriptor().name).to_str().unwrap()
        }
    }

    #[inline]
    pub(crate) fn index(&self) -> c_int {
        self.0
    }

    fn descriptor(&self) -> &'static ffi::ltc_prng_descriptor {
        unsafe {
            &*(&ffi::prng_descriptor as *const ffi::ltc_prng_descriptor).offset(self.0 as isize)
        }
    }
}

/// A pseudo-random number generator.
pub struct Prng {
    algorithm: PrngAlgorithm,
    raw: ffi::prng_state,
}

impl Prng {
    /// Create a new pseudo-random number generator using the given algorithm.
    pub fn new(algorithm: PrngAlgorithm) -> Self {
        unsafe {
            let mut raw = mem::uninitialized();

            (algorithm.descriptor().start.unwrap())(&mut raw);

            Self {
                algorithm: algorithm,
                raw: raw,
            }
        }
    }

    /// Get the PRNG algorithm used by this PRNG.
    #[inline]
    pub fn algorithm(&self) -> &PrngAlgorithm {
        &self.algorithm
    }

    /// Add entropy to the PRNG state.
    pub fn add_entropy(&mut self, input: &[u8]) -> Result<()> {
        unsafe {
            tryt! {
                (self.algorithm.descriptor().add_entropy.unwrap())(input.as_ptr(), input.len() as u64, &mut self.raw)
            }
        }

        Ok(())
    }

    /// Make the PRNG ready to read from.
    pub fn ready(&mut self) -> Result<()> {
        unsafe {
            tryt! {
                (self.algorithm.descriptor().ready.unwrap())(&mut self.raw)
            }
        }

        Ok(())
    }
}

impl io::Read for Prng {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        unsafe {
            Ok((self.algorithm.descriptor().read.unwrap())(buf.as_mut_ptr(), buf.len() as u64, &mut self.raw) as usize)
        }
    }
}

impl Drop for Prng {
    fn drop(&mut self) {
        unsafe {
            (self.algorithm.descriptor().done.unwrap())(&mut self.raw);
        }
    }
}
