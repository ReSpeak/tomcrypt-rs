//! Internal helper functions used by other modules.

/// Allocate an uninitialized byte vector of a given size.
pub unsafe fn alloc(size: usize) -> Vec<u8> {
    let mut vec = Vec::with_capacity(size);
    vec.set_len(size);
    vec
}
