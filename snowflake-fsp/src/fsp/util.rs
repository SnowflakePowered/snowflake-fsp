use std::ops::Deref;
use windows::Win32::Foundation::{CloseHandle, HANDLE};

#[derive(Clone)]
pub struct DropCloseHandle(HANDLE);

impl Drop for DropCloseHandle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

impl Deref for DropCloseHandle {
    type Target = HANDLE;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<HANDLE> for DropCloseHandle {
    fn from(h: HANDLE) -> Self {
        Self(h)
    }
}

impl From<DropCloseHandle> for HANDLE {
    fn from(h: DropCloseHandle) -> Self {
        h.0
    }
}
