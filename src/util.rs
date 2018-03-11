use ffi;
use std::mem;
use std::os::raw::*;


/// Overwrites the memory for the given value with all zeros.
pub unsafe fn zeromem<T: ?Sized>(value: &mut T) {
    ffi::zeromem(value as *mut _ as *mut c_void, mem::size_of_val(value));
}

/// Sets the given bytes to all zeros.
pub fn zeromem_slice(x: &mut [u8]) {
    unsafe {
        zeromem(x);
    }
}

/// This will compare the buffer `lhs` against the buffer `rhs` and return `true` if they are equal. The comparison is
/// done in constant time regardless of their contents.
///
/// Some symmetric-key cryptographic operation-modes are vulnerable to timing attacks in case non-contant-time memory
/// comparison functions are used to compare results. Therefore LibTomCrypt implements a constant-time memory compare
/// function.
pub fn compare_slices(lhs: &[u8], rhs: &[u8]) -> bool {
    if rhs.len() != lhs.len() {
        return false;
    }

    unsafe {
        ffi::mem_neq(lhs.as_ptr() as *mut c_void, rhs.as_ptr() as *mut c_void, lhs.len()) == 0
    }
}
