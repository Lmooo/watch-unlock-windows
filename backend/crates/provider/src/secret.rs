//! Best-effort erasure of owned temporary password buffers.

use std::ops::{Deref, DerefMut};

pub struct Wide(pub Vec<u16>);

impl Deref for Wide {
    type Target = Vec<u16>;
    fn deref(&self) -> &Self::Target { &self.0 }
}

impl DerefMut for Wide {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0 }
}

impl Drop for Wide {
    fn drop(&mut self) {
        for unit in &mut self.0 {
            unsafe { std::ptr::write_volatile(unit, 0); }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

pub struct Text(pub String);

impl Deref for Text {
    type Target = str;
    fn deref(&self) -> &str { &self.0 }
}

impl Drop for Text {
    fn drop(&mut self) { crate::clear_secret(&mut self.0); }
}
