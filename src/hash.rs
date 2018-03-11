use error::Result;
use ffi;
use std::ffi::{CStr, CString};
use std::mem;
use std::os::raw::*;


/// A cryptographic hash algorithm.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Hash(c_int);

impl Hash {
    /// Find a hash algorithm by name.
    pub fn find(name: &str) -> Option<Self> {
        ::init();

        unsafe {
            let name = CString::new(name).unwrap();

            match ffi::find_hash(name.as_ptr()) {
                -1 => None,
                index => Some(Hash(index)),
            }
        }
    }

    /// Get a hash algorithm by name. Panics if the algorithm is not available.
    fn find_required(name: &str) -> Self {
        match Self::find(name) {
            Some(hash) => hash,
            None => panic!("{} algorithm not available", name),
        }
    }

    /// Get a hash algorithm by its ASN.1 object identifier.
    pub fn oid(oid: &[u64]) -> Option<Self> {
        ::init();

        unsafe {
            match ffi::find_hash_oid(oid.as_ptr(), oid.len() as c_ulong) {
                -1 => None,
                index => Some(Hash(index)),
            }
        }
    }

    /// The MD5 hash algorithm.
    pub fn md5() -> Self {
        Self::find_required("md5")
    }

    /// The SHA-1 hash algorithm.
    pub fn sha1() -> Self {
        Self::find_required("sha1")
    }

    /// The SHA-256 hash algorithm.
    pub fn sha256() -> Self {
        Self::find_required("sha256")
    }

    /// The SHA-512 hash algorithm.
    pub fn sha512() -> Self {
        Self::find_required("sha512")
    }

    /// Get the name of the hash function.
    pub fn name(&self) -> &str {
        unsafe {
            CStr::from_ptr(self.descriptor().name).to_str().unwrap()
        }
    }

    /// Get the digest output size in bytes.
    pub fn size(&self) -> u64 {
        self.descriptor().hashsize
    }

    /// Get the block size the hash uses.
    pub fn block_size(&self) -> u64 {
        self.descriptor().blocksize
    }

    /// Computes the message digest of the given data.
    pub fn hash<I: AsRef<[u8]>>(&self, input: I) -> Result<Vec<u8>> {
        let mut state = HashState::new(self.clone());
        state.process(input)?;
        state.done()
    }

    #[inline]
    pub(crate) fn index(&self) -> c_int {
        self.0
    }

    #[inline]
    fn descriptor(&self) -> &'static ffi::ltc_hash_descriptor {
        unsafe {
            &*(&ffi::hash_descriptor as *const ffi::ltc_hash_descriptor).offset(self.0 as isize)
        }
    }
}


/// The state of a message digest being computed using a hash function.
pub struct HashState {
    hash: Hash,
    raw: ffi::hash_state,
}

impl HashState {
    /// Initialize a new message digest using the given hash algorithm.
    pub fn new(hash: Hash) -> Self {
        unsafe {
            let mut raw = mem::uninitialized();

            (hash.descriptor().init.unwrap())(&mut raw);

            HashState {
                hash: hash,
                raw: raw,
            }
        }
    }

    /// Add data to the message being hashed.
    ///
    /// This method can be called repeatedly for use with streaming messages.
    pub fn process<I: AsRef<[u8]>>(&mut self, input: I) -> Result<()> {
        let input = input.as_ref();

        unsafe {
            tryt! {
                (self.hash.descriptor().process.unwrap())(&mut self.raw, input.as_ptr(), input.len() as c_ulong)
            };
        }

        Ok(())
    }

    /// Finalize the hash and get the message digest.
    pub fn done(mut self) -> Result<Vec<u8>> {
        let mut output = vec![0; self.hash.size() as usize];

        unsafe {
            tryt! {
                (self.hash.descriptor().done.unwrap())(&mut self.raw, output.as_mut_ptr())
            };
        }

        Ok(output)
    }
}


#[cfg(test)]
mod tests {
    use hex;
    use super::*;


    #[test]
    fn test_find_hash() {
        assert_eq!(Hash::find("md5").unwrap(), Hash::md5());

        for name in &["md5", "sha1", "sha256"] {
            let hash = Hash::find(name).unwrap();
            assert_eq!(hash.name(), *name);
        }
    }

    #[test]
    fn test_md5_hash() {
        assert_eq!(hex::encode(Hash::md5().hash("hello world").unwrap()), "5eb63bbbe01eeed093cb22bb8f5acdc3");
    }
}
