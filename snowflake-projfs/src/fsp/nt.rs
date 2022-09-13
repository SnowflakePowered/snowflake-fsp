use std::ffi::c_void;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::WindowsProgramming::{IO_STATUS_BLOCK, PIO_APC_ROUTINE};

#[link(name = "windows")]
#[allow(non_snake_case)]
extern "system" {
    pub fn NtReadFile(
        FileHandle: HANDLE,
        Event: HANDLE,
        ApcRoutine: PIO_APC_ROUTINE,
        ApcContext: *mut c_void,
        IoStatusBlock: *mut IO_STATUS_BLOCK,
        Buffer: *mut c_void,
        Length: u32,
        ByteOffset: *mut u64,
        Key: *mut u32,
    ) -> windows_sys::Win32::Foundation::NTSTATUS;

}
