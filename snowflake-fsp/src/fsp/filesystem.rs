use std::borrow::Borrow;
use std::ffi::{c_void, OsStr};
use std::panic;
use std::path::Path;
use widestring::U16CStr;
use windows::core::{HRESULT, HSTRING, PWSTR};
use windows::w;
use windows::Win32::Foundation::{
    EXCEPTION_NONCONTINUABLE_EXCEPTION, NTSTATUS, STATUS_INVALID_DEVICE_REQUEST, STATUS_SUCCESS,
};
use windows::Win32::Security::PSECURITY_DESCRIPTOR;
use windows::Win32::Storage::FileSystem::{FILE_ACCESS_FLAGS, FILE_FLAGS_AND_ATTRIBUTES};
use winfsp_sys::{
    FspFileSystemCreate, FspFileSystemSetMountPoint, FspFileSystemStartDispatcher,
    FspFileSystemStopDispatcher, FSP_FILE_SYSTEM, FSP_FILE_SYSTEM_INTERFACE, FSP_FSCTL_FILE_INFO,
    FSP_FSCTL_VOLUME_INFO, FSP_FSCTL_VOLUME_PARAMS,
};
use winfsp_sys::{NTSTATUS as FSP_STATUS, PVOID};

use windows::core::Result as NtResult;

pub struct FspFileSystem(pub *mut FSP_FILE_SYSTEM);
impl FspFileSystem {
    pub unsafe fn new<T>(mut volume_params: FSP_FSCTL_VOLUME_PARAMS, context: T) -> NtResult<Self> {
        let mut fsp_struct = std::ptr::null_mut();

        let result = FspFileSystemCreate(
            if volume_params.Prefix[0] != 0 {
                w!("WinFsp.Net").as_ptr().cast_mut()
            } else {
                w!("WinFsp.Disk").as_ptr().cast_mut()
            },
            &volume_params,
            // todo: interface
            std::ptr::null(),
            &mut fsp_struct,
        );

        let result = NTSTATUS(result);
        result.ok()?;

        (*fsp_struct).UserContext = Box::into_raw(Box::new(context)) as *mut _;
        Ok(FspFileSystem(fsp_struct))
    }

    pub fn start(&mut self) -> NtResult<()> {
        let result = unsafe { FspFileSystemStartDispatcher(self.0, 0) };
        let result = NTSTATUS(result);
        result.ok()
    }

    pub fn stop(&mut self) {
        unsafe { FspFileSystemStopDispatcher(self.0) }
    }

    pub fn mount<S: Into<HSTRING>>(&mut self, mount: S) -> NtResult<()> {
        let result =
            unsafe { FspFileSystemSetMountPoint(self.0, mount.into().as_ptr().cast_mut()) };

        let result = NTSTATUS(result);
        result.ok()
    }
}

struct Interface {
    get_volume_info: Option<
        unsafe extern "stdcall" fn(
            fs: *mut FSP_FILE_SYSTEM,
            volume_info: *mut FSP_FSCTL_VOLUME_INFO,
        ) -> FSP_STATUS,
    >,
}

pub trait FileSystemContext: Sized {
    type FileContext: Sized;
    unsafe fn get_security_by_name<P: AsRef<Path>>(
        &self,
        file_name: P,
    ) -> NtResult<(u32, PSECURITY_DESCRIPTOR, u32)>;

    unsafe fn open<P: AsRef<Path>>(
        &self,
        file_name: P,
        create_options: FILE_FLAGS_AND_ATTRIBUTES,
        granted_access: FILE_ACCESS_FLAGS,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> NtResult<Self::FileContext>;

    unsafe fn close(&self, context: &mut Self::FileContext);

    unsafe fn can_delete<P: AsRef<Path>>(
        &self,
        _context: &Self::FileContext,
        _file_name: P,
    ) -> NtResult<()> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    unsafe fn cleanup<P: AsRef<Path>>(
        &self,
        _context: &Self::FileContext,
        _file_name: P,
        _flags: u32,
    ) {
    }

    unsafe fn get_volume_info(&self) -> NtResult<FSP_FSCTL_VOLUME_INFO> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }
}

impl<T: FileSystemContext> From<T> for Interface {
    fn from(_: T) -> Self {
        Interface {
            get_volume_info: Some(get_volume_info::<T>),
        }
    }
}

/// Catch panic and return STATUS_INVALID_DISPOSITION
macro_rules! catch_panic {
    ($bl:block) => {
        ::std::panic::catch_unwind(|| $bl)
            .unwrap_or_else(|_| ::windows::Win32::Foundation::EXCEPTION_NONCONTINUABLE_EXCEPTION.0)
    };
}

unsafe extern "stdcall" fn get_volume_info<T: FileSystemContext>(
    fs: *mut FSP_FILE_SYSTEM,
    volume_info: *mut FSP_FSCTL_VOLUME_INFO,
) -> FSP_STATUS {
    catch_panic!({
        let context: &T = (*fs).UserContext.cast::<T>().as_ref().unwrap_unchecked();
        match T::get_volume_info(context) {
            Ok(info) => {
                volume_info.write(info);
                STATUS_SUCCESS.into()
            }
            Err(e) => e.code(),
        }
        .0
    })
}

unsafe extern "stdcall" fn open<T: FileSystemContext>(
    fs: *mut FSP_FILE_SYSTEM,
    file_name: winfsp_sys::PWSTR,
    create_options: u32,
    granted_access: u32,
    file_context: *mut PVOID,
    file_info: *mut FSP_FSCTL_FILE_INFO,
) -> FSP_STATUS {
    catch_panic!({
        let context: &T = (*fs).UserContext.cast::<T>().as_ref().unwrap_unchecked();
        let file_name = unsafe { U16CStr::from_ptr_str_mut(file_name).to_os_string() };

        match T::open(
            context,
            &file_name,
            FILE_FLAGS_AND_ATTRIBUTES(create_options),
            FILE_ACCESS_FLAGS(granted_access),
            file_info.as_mut().unwrap_unchecked()
        ) {
            Ok(context) => {
                *file_context = Box::into_raw(Box::new(context)) as *mut _;
                STATUS_SUCCESS.into()
            }
            Err(e) => e.code(),
        }
        .0
    })
}

unsafe extern "stdcall" fn close<T: FileSystemContext>(
    fs: *mut FSP_FILE_SYSTEM,
    fptr: PVOID,
) {
    catch_panic!({
        let context: &T = (*fs).UserContext.cast::<T>().as_ref().unwrap_unchecked();
        if let Some(file_context) = fptr.cast::<T::FileContext>().as_mut() {
            T::close(context, file_context);
        }
        if !fptr.is_null() {
            drop(Box::from_raw(fptr));
        }
        0
    });
}
