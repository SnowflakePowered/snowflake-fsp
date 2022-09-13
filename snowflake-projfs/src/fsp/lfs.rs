use std::ffi::c_void;
use std::mem::MaybeUninit;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    HANDLE, INVALID_HANDLE_VALUE, NTSTATUS, STATUS_INSUFFICIENT_RESOURCES, STATUS_PENDING,
    STATUS_SUCCESS,
};
use windows::Win32::Security::PSECURITY_DESCRIPTOR;
use windows::Win32::Storage::FileSystem::{
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
};
use windows::Win32::System::Threading::{CreateEventW, WaitForSingleObject};
use windows::Win32::System::WindowsProgramming::INFINITE;

use windows_sys::Win32::Foundation::UNICODE_STRING;
use windows_sys::Win32::Storage::FileSystem::NtCreateFile;

use crate::fsp::nt;
use windows_sys::Win32::System::WindowsProgramming::{
    NtOpenFile, RtlInitUnicodeString, IO_STATUS_BLOCK, OBJECT_ATTRIBUTES,
};
use winfsp::util::SafeDropHandle;

fn initialize_object_attributes(
    obj_name: &mut UNICODE_STRING,
    attributes: u32,
    root_dir: Option<HANDLE>,
    security_descriptor: Option<PSECURITY_DESCRIPTOR>,
) -> OBJECT_ATTRIBUTES {
    OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: root_dir.unwrap_or_default().0,
        ObjectName: obj_name,
        Attributes: attributes,
        SecurityDescriptor: security_descriptor.map_or_else(std::ptr::null_mut, |s| s.0),
        SecurityQualityOfService: std::ptr::null_mut(),
    }
}

fn thread_event() -> windows::core::Result<HANDLE> {
    unsafe { CreateEventW(std::ptr::null(), true, false, PCWSTR::null()) }
}

pub fn lfs_create_file<P: Into<PCWSTR>>(
    file_path: P,
    desired_access: u32,
    security_descriptor: PSECURITY_DESCRIPTOR,
    allocation_size: Option<&mut i64>,
    file_attributes: u32,
    create_disposition: u32,
    create_options: u32,
    ea_buffer: &mut Option<&mut [u8]>,
    parent: Option<HANDLE>,
) -> winfsp::Result<HANDLE> {
    let mut unicode_filename = unsafe {
        let mut unicode_filename: MaybeUninit<UNICODE_STRING> = MaybeUninit::uninit();
        RtlInitUnicodeString(unicode_filename.as_mut_ptr(), file_path.into().0);
        unicode_filename.assume_init()
    };

    let mut object_attrs =
        initialize_object_attributes(&mut unicode_filename, 0, parent, Some(security_descriptor));

    let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::uninit();
    let mut handle = INVALID_HANDLE_VALUE;

    let result = if let Some(buffer) = ea_buffer.as_deref_mut() {
        // the lifetime of buffer has to last until after NtCreateFile.
        NTSTATUS(unsafe {
            NtCreateFile(
                &mut handle.0,
                FILE_READ_ATTRIBUTES.0 | desired_access,
                &mut object_attrs,
                iosb.as_mut_ptr(),
                allocation_size
                    .map(|r| r as *mut i64)
                    .unwrap_or(std::ptr::null_mut()),
                file_attributes,
                (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE).0,
                create_disposition,
                create_options,
                buffer.as_mut_ptr().cast(),
                buffer.len() as u32,
            )
        })
    } else {
        NTSTATUS(unsafe {
            NtCreateFile(
                &mut handle.0,
                FILE_READ_ATTRIBUTES.0 | desired_access,
                &mut object_attrs,
                iosb.as_mut_ptr(),
                allocation_size
                    .map(|r| r as *mut i64)
                    .unwrap_or(std::ptr::null_mut()),
                file_attributes,
                (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE).0,
                create_disposition,
                create_options,
                std::ptr::null_mut(),
                0,
            )
        })
    };

    if result != STATUS_SUCCESS {
        Err(result.into())
    } else {
        Ok(handle)
    }
}
pub fn lfs_open_file<P: Into<PCWSTR>>(
    file_path: P,
    desired_access: u32,
    open_options: u32,
) -> winfsp::Result<HANDLE> {
    let mut unicode_filename = unsafe {
        let mut unicode_filename: MaybeUninit<UNICODE_STRING> = MaybeUninit::uninit();
        RtlInitUnicodeString(unicode_filename.as_mut_ptr(), file_path.into().0);
        unicode_filename.assume_init()
    };

    let mut object_attrs = initialize_object_attributes(&mut unicode_filename, 0, None, None);

    let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::uninit();
    let mut handle = INVALID_HANDLE_VALUE;

    let result = NTSTATUS(unsafe {
        NtOpenFile(
            &mut handle.0,
            FILE_READ_ATTRIBUTES.0 | desired_access,
            &mut object_attrs,
            iosb.as_mut_ptr(),
            (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE).0,
            open_options,
        )
    });

    if result != STATUS_SUCCESS {
        Err(result.into())
    } else {
        Ok(handle)
    }
}

pub fn lfs_read_file(handle: HANDLE, buffer: &mut [u8], offset: u64, out: &mut usize) -> NTSTATUS {
    let event = thread_event();
    if event.is_err() {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    let event = event.unwrap();
    let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::uninit();
    let mut offset = offset;

    let mut result = unsafe {
        NTSTATUS(nt::NtReadFile(
            handle.0,
            event.0,
            None,
            std::ptr::null_mut(),
            iosb.as_mut_ptr(),
            buffer.as_mut_ptr() as *mut _,
            buffer.len() as u32,
            &mut offset,
            std::ptr::null_mut(),
        ))
    };

    let iosb = unsafe { iosb.assume_init() };

    if result == STATUS_PENDING {
        unsafe {
            WaitForSingleObject(event, INFINITE);
        }
        result = NTSTATUS(unsafe { iosb.Anonymous.Status })
    }

    *out = iosb.Information;

    result
}
