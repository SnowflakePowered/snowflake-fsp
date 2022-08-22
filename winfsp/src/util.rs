use std::ops::Deref;
use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};

/// An owned handle that will always be dropped
/// when it goes out of scope.
///
/// ## Safety
/// This handle will become invalid when it goes out of scope.
/// `SafeDropHandle` implements `Deref<Target=Handle>` to make it
/// usable for APIs that take `HANDLE`. Dereference the `SafeDropHandle`
/// to obtain a `HANDLE` that is `Copy` without dropping the `SafeDropHandle`
/// and invalidating the underlying handle.
#[repr(transparent)]
pub struct SafeDropHandle(HANDLE);

impl SafeDropHandle {
    /// Invalidate the handle without dropping it.
    pub fn invalidate(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                CloseHandle(self.0);
            }
        }
        self.0 = INVALID_HANDLE_VALUE
    }
}

impl Drop for SafeDropHandle {
    fn drop(&mut self) {
        unsafe {
            if !self.0.is_invalid() {
                CloseHandle(self.0);
            }
        }
    }
}

impl Deref for SafeDropHandle {
    type Target = HANDLE;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<HANDLE> for SafeDropHandle {
    fn from(h: HANDLE) -> Self {
        Self(h)
    }
}
