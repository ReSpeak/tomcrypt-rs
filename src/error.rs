use ffi;
use std::ffi::CStr;
use std::fmt;
use std::io;
use std::os::raw::*;


macro_rules! tryt {
    ($e:expr) => {
        match ::std::mem::transmute($e) {
            ::ffi::CRYPT_OK => (),
            e => return Err(::error::Error::from_code(e)),
        }
    };
}


pub type Result<T> = ::std::result::Result<T, Error>;


#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "{}", _0)]
    Io(io::Error),

    #[fail(display = "{}", _0)]
    Tomcrypt(TomcryptError),
}

impl Error {
    pub(crate) fn from_code(code: ffi::Error) -> Error {
        Error::Tomcrypt(TomcryptError(code))
    }
}


#[derive(Clone, Copy, Eq, PartialEq)]
pub struct TomcryptError(ffi::Error);

impl fmt::Display for TomcryptError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = unsafe {
            CStr::from_ptr(ffi::error_to_string(self.0 as c_int)).to_str()
                .unwrap()
        };
        write!(f, "{}", s)?;
        Ok(())
    }
}

impl fmt::Debug for TomcryptError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "TomcryptError({})", self)?;
        Ok(())
    }
}
