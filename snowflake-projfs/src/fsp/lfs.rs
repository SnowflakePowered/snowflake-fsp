use std::ffi::c_void;
use std::mem::MaybeUninit;
use std::ops::DerefMut;
use std::ptr::addr_of_mut;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    HANDLE, INVALID_HANDLE_VALUE, NTSTATUS, STATUS_ACCESS_DENIED, STATUS_CANNOT_DELETE,
    STATUS_DIRECTORY_NOT_EMPTY, STATUS_FILE_DELETED, STATUS_OBJECT_NAME_COLLISION, STATUS_PENDING,
    STATUS_SUCCESS,
};
use windows::Win32::Security::PSECURITY_DESCRIPTOR;
use windows::Win32::Storage::FileSystem::{
    FileRenameInfoEx, FILE_INFO_BY_HANDLE_CLASS, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE,
};
use windows::Win32::System::Threading::{CreateEventW, WaitForSingleObject};
use windows::Win32::System::WindowsProgramming::INFINITE;
use windows_sys::core::HSTRING;

use windows_sys::Win32::Foundation::{BOOLEAN, UNICODE_STRING};
use windows_sys::Win32::Storage::FileSystem::{
    NtCreateFile, SetFileInformationByHandle, FILE_DISPOSITION_INFO, FILE_RENAME_INFO,
};

use crate::fsp::nt;
use windows_sys::Win32::System::WindowsProgramming::{
    NtOpenFile, RtlInitUnicodeString, FILE_DISPOSITION_INFO_EX, IO_STATUS_BLOCK, OBJECT_ATTRIBUTES,
};
use winfsp::util::{NtSafeHandle, SafeDropHandle, VariableSizedBox};

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

thread_local! {
    static LFS_EVENT: HANDLE = new_thread_event().unwrap();
}

fn new_thread_event() -> windows::core::Result<HANDLE> {
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
) -> winfsp::Result<NtSafeHandle> {
    let mut unicode_filename = unsafe {
        let mut unicode_filename: MaybeUninit<UNICODE_STRING> = MaybeUninit::uninit();
        RtlInitUnicodeString(unicode_filename.as_mut_ptr(), file_path.into().0);
        unicode_filename.assume_init()
    };

    let mut object_attrs =
        initialize_object_attributes(&mut unicode_filename, 0, parent, Some(security_descriptor));

    let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::uninit();
    let mut handle = NtSafeHandle::from(INVALID_HANDLE_VALUE);

    let result = if let Some(buffer) = ea_buffer.as_deref_mut() {
        // the lifetime of buffer has to last until after NtCreateFile.
        NTSTATUS(unsafe {
            NtCreateFile(
                &mut handle.deref_mut().0,
                0x00010000 | FILE_READ_ATTRIBUTES.0 | desired_access,
                &mut object_attrs,
                iosb.as_mut_ptr(),
                allocation_size
                    .map(|r| r as *mut i64)
                    .unwrap_or(std::ptr::null_mut()),
                file_attributes,
                FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0,
                create_disposition,
                create_options,
                buffer.as_mut_ptr().cast(),
                buffer.len() as u32,
            )
        })
    } else {
        NTSTATUS(unsafe {
            NtCreateFile(
                &mut handle.deref_mut().0,
                0x00010000 | FILE_READ_ATTRIBUTES.0 | desired_access,
                &mut object_attrs,
                iosb.as_mut_ptr(),
                allocation_size
                    .map(|r| r as *mut i64)
                    .unwrap_or(std::ptr::null_mut()),
                file_attributes,
                FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0,
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
) -> winfsp::Result<NtSafeHandle> {
    let mut unicode_filename = unsafe {
        let mut unicode_filename: MaybeUninit<UNICODE_STRING> = MaybeUninit::uninit();
        RtlInitUnicodeString(unicode_filename.as_mut_ptr(), file_path.into().0);
        unicode_filename.assume_init()
    };

    let mut object_attrs = initialize_object_attributes(&mut unicode_filename, 0, None, None);

    let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::uninit();
    let mut handle = NtSafeHandle::from(INVALID_HANDLE_VALUE);

    let result = NTSTATUS(unsafe {
        NtOpenFile(
            &mut handle.deref_mut().0,
            0x00010000 | FILE_READ_ATTRIBUTES.0 | desired_access,
            &mut object_attrs,
            iosb.as_mut_ptr(),
            FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0,
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
    LFS_EVENT.with(|event| {
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

        if result == STATUS_PENDING {
            unsafe {
                WaitForSingleObject(*event, INFINITE);
            }
            let iosb = unsafe { iosb.assume_init() };
            result = NTSTATUS(unsafe { iosb.Anonymous.Status })
        }

        let iosb = unsafe { iosb.assume_init() };
        *out = iosb.Information;

        result
    })
}

pub fn lfs_write_file(handle: HANDLE, buffer: &[u8], offset: u64, out: &mut usize) -> NTSTATUS {
    LFS_EVENT.with(|event| {
        let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::uninit();
        let mut offset = offset;

        let mut result = unsafe {
            NTSTATUS(nt::NtWriteFile(
                handle.0,
                event.0,
                None,
                std::ptr::null_mut(),
                iosb.as_mut_ptr(),
                buffer.as_ptr().cast_mut().cast(),
                buffer.len() as u32,
                &mut offset,
                std::ptr::null_mut(),
            ))
        };

        if result == STATUS_PENDING {
            unsafe {
                WaitForSingleObject(*event, INFINITE);
            }
            let iosb = unsafe { iosb.assume_init() };
            result = NTSTATUS(unsafe { iosb.Anonymous.Status })
        }

        let iosb = unsafe { iosb.assume_init() };
        *out = iosb.Information;

        result
    })
}

pub fn lfs_unlink(handle: HANDLE, delete: bool) -> NTSTATUS {
    let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::uninit();
    let mut disp_info = FILE_DISPOSITION_INFO {
        DeleteFileA: if delete { 1u8 } else { 0u8 },
    };

    let mut disp_info_ex = FILE_DISPOSITION_INFO_EX {
        Flags: if delete {
            0x17 /*DELETE | POSIX_SEMANTICS | IGNORE_READONLY_ATTRIBUTE | FORCE_IMAGE_SECTION_CHECK*/
        } else {
            0
        },
    };

    let result = unsafe {
        NTSTATUS(nt::NtSetInformationFileGeneric(
            handle.0,
            iosb.as_mut_ptr(),
            &mut disp_info_ex,
            64, /*FileDispositionInformationEx*/
        ))
    };

    match result {
        STATUS_ACCESS_DENIED
        | STATUS_DIRECTORY_NOT_EMPTY
        | STATUS_CANNOT_DELETE
        | STATUS_FILE_DELETED => result,
        _ => {
            unsafe {
                NTSTATUS(nt::NtSetInformationFileGeneric(
                    handle.0,
                    iosb.as_mut_ptr(),
                    &mut disp_info,
                    13, /*FileDispositionInformation*/
                ))
            }
        }
    }
}

#[derive(Eq, PartialEq)]
pub enum LfsRenameSemantics {
    DoNotReplace,
    NtReplaceSemantics,
    PosixReplaceSemantics,
}

pub fn lfs_rename(
    handle: HANDLE,
    nt_full_path: windows::core::HSTRING,
    replace_if_exists: LfsRenameSemantics,
) -> NTSTATUS {
    let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::uninit();
    let file_path_len = nt_full_path.len() * std::mem::size_of::<u16>();
    let mut rename_info: VariableSizedBox<FILE_RENAME_INFO> =
        VariableSizedBox::new(file_path_len + std::mem::size_of::<FILE_RENAME_INFO>() + 1);
    unsafe {
        addr_of_mut!((*rename_info.as_mut_ptr()).FileNameLength).write(file_path_len as u32);
        addr_of_mut!((*rename_info.as_mut_ptr()).FileName)
            .copy_from(nt_full_path.as_ptr().cast(), nt_full_path.len());
        addr_of_mut!((*rename_info.as_mut_ptr()).Anonymous.Flags).write(
            if replace_if_exists == LfsRenameSemantics::PosixReplaceSemantics {
                1
            } else {
                0
            } | 0x42, /*POSIX_SEMANTICS | IGNORE_READONLY_ATTRIBUTE*/
        )
    }

    let result = unsafe {
        NTSTATUS(nt::NtSetInformationFile(
            handle.0,
            iosb.as_mut_ptr(),
            rename_info.as_mut_ptr().cast(),
            rename_info.len() as u32,
            65, /*FileRenameInformationEx*/
        ))
    };

    match result {
        STATUS_OBJECT_NAME_COLLISION
            if replace_if_exists != LfsRenameSemantics::PosixReplaceSemantics =>
        {
            STATUS_ACCESS_DENIED
        }
        STATUS_ACCESS_DENIED => {
            eprintln!("access denied");
            STATUS_ACCESS_DENIED
        }
        _ => {
            unsafe {
                addr_of_mut!((*rename_info.as_mut_ptr()).Anonymous.Flags).write(0);
                addr_of_mut!((*rename_info.as_mut_ptr()).Anonymous.ReplaceIfExists).write(
                    if replace_if_exists != LfsRenameSemantics::DoNotReplace {
                        1
                    } else {
                        0
                    },
                );
                NTSTATUS(nt::NtSetInformationFile(
                    handle.0,
                    iosb.as_mut_ptr(),
                    rename_info.as_mut_ptr().cast(),
                    rename_info.len() as u32,
                    10, /*FileRenameInformation*/
                ))
            }
        }
    }
}
