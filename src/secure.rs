use std::ops::{Deref, DerefMut};
use std::ptr;

use zeroize::Zeroize;

#[derive(Debug)]
pub struct SecureBuffer {
    bytes: Vec<u8>,
    locked: bool,
}

impl SecureBuffer {
    pub fn new(size: usize) -> Self {
        let mut bytes = vec![0; size];
        let locked = try_mlock(&mut bytes);
        Self { bytes, locked }
    }

    pub fn from_slice(data: &[u8]) -> Self {
        let mut buffer = Self::new(data.len());
        buffer.bytes.copy_from_slice(data);
        buffer
    }

    pub fn locked(&self) -> bool {
        self.locked
    }
}

impl Deref for SecureBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl DerefMut for SecureBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.bytes
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        self.bytes.zeroize();
        if self.locked && !self.bytes.is_empty() {
            unsafe {
                libc::munlock(self.bytes.as_ptr().cast::<libc::c_void>(), self.bytes.len());
            }
        }
    }
}

fn try_mlock(bytes: &mut [u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }

    unsafe { libc::mlock(bytes.as_ptr().cast::<libc::c_void>(), bytes.len()) == 0 }
}

pub unsafe fn zeroize_c_string(ptr: *mut libc::c_char) {
    if ptr.is_null() {
        return;
    }

    let mut len = 0usize;
    while *ptr.add(len) != 0 {
        len += 1;
    }

    secure_zero(ptr.cast::<u8>(), len);
}

pub unsafe fn secure_zero(ptr: *mut u8, len: usize) {
    for idx in 0..len {
        ptr::write_volatile(ptr.add(idx), 0);
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}
