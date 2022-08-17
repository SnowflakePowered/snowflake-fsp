use std::borrow::Borrow;
use std::ffi::{c_void, OsStr};
use std::mem::MaybeUninit;
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

use crate::fsp::interface::Interface;
use windows::core::Result as NtResult;

pub struct FspFileSystem(pub *mut FSP_FILE_SYSTEM);
impl FspFileSystem {
    pub unsafe fn new<T: FileSystemContext>(
        volume_params: FSP_FSCTL_VOLUME_PARAMS,
        context: T,
    ) -> NtResult<Self> {
        let mut fsp_struct = std::ptr::null_mut();

        let interface = Interface::create::<T>();
        let interface: FSP_FILE_SYSTEM_INTERFACE = interface.into();
        let interface = Box::into_raw(Box::new(interface));
        let result = unsafe {
            FspFileSystemCreate(
                if volume_params.Prefix[0] != 0 {
                    w!("WinFsp.Net").as_ptr().cast_mut()
                } else {
                    w!("WinFsp.Disk").as_ptr().cast_mut()
                },
                &volume_params,
                interface,
                &mut fsp_struct,
            )
        };

        let result = NTSTATUS(result);
        result.ok()?;

        dbg!("init ok");

        #[cfg(debug_assertions)]
        unsafe {
            use windows::Win32::System::Console::{GetStdHandle, STD_ERROR_HANDLE};
            // pointer crimes
            winfsp_sys::FspDebugLogSetHandle(std::mem::transmute(
                GetStdHandle(STD_ERROR_HANDLE).unwrap().0,
            ));
            winfsp_sys::FspFileSystemSetDebugLogF(fsp_struct, u32::MAX);
        }

        unsafe {
            (*fsp_struct).UserContext = Box::into_raw(Box::new(context)) as *mut _;
        }
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

pub trait FileSystemContext: Sized {
    type FileContext: Sized;
    fn get_security_by_name<P: AsRef<Path>>(
        &self,
        file_name: P,
        security_descriptor: PSECURITY_DESCRIPTOR,
        descriptor_len: Option<u32>,
    ) -> NtResult<(u32, u64)>;

    fn open<P: AsRef<Path>>(
        &self,
        file_name: P,
        create_options: u32,
        granted_access: FILE_ACCESS_FLAGS,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> NtResult<Self::FileContext>;

    fn close(&self, context: Self::FileContext);

    fn can_delete<P: AsRef<Path>>(
        &self,
        _context: &Self::FileContext,
        _file_name: P,
    ) -> NtResult<()> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    fn cleanup<P: AsRef<Path>>(&self, _context: &Self::FileContext, _file_name: P, _flags: u32) {}

    fn get_volume_info(&self, out_volume_info: &mut FSP_FSCTL_VOLUME_INFO) -> NtResult<()> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }
}
