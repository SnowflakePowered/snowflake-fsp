use std::ffi::c_void;
use windows::core::{HSTRING, PWSTR};
use windows::w;
use windows::Win32::Foundation::{NTSTATUS, STATUS_SUCCESS};
use winfsp_sys::{FspFileSystemCreate, FspFileSystemStopDispatcher, FSP_FILE_SYSTEM, FSP_FILE_SYSTEM_INTERFACE, FSP_FSCTL_VOLUME_INFO, FSP_FSCTL_VOLUME_PARAMS, FspFileSystemSetMountPoint, FspFileSystemStartDispatcher};
use winfsp_sys::{NTSTATUS as FSP_STATUS, PVOID};

pub struct FspFileSystem(pub *mut FSP_FILE_SYSTEM);
impl FspFileSystem {
    pub unsafe fn new<T>(
        mut volume_params: FSP_FSCTL_VOLUME_PARAMS,
        context: T,
    ) -> windows::core::Result<Self> {
        let mut fsp_struct = std::ptr::null_mut();

        let result = FspFileSystemCreate(
            if volume_params.Prefix[0] != 0 { w!("WinFsp.Net").as_ptr().cast_mut() } else { w!("WinFsp.Disk").as_ptr().cast_mut()  },
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

    pub fn start(&mut self) -> windows::core::Result<()>{
        let result = unsafe { FspFileSystemStartDispatcher(self.0, 0) };
        let result = NTSTATUS(result);
        result.ok()
    }

    pub fn stop(&mut self) {
        unsafe { FspFileSystemStopDispatcher(self.0) }
    }

    pub fn mount(&mut self, mount: PWSTR) -> windows::core::Result<()>{

        let result = unsafe {
                FspFileSystemSetMountPoint(self.0, mount.as_ptr())
        };

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
    fn get_volume_info(&self) -> windows::core::Result<FSP_FSCTL_VOLUME_INFO>;
    unsafe fn close(&self, file: &mut Self::FileContext);
}

impl<T: FileSystemContext> From<T> for Interface {
    fn from(_: T) -> Self {
        Interface {
            get_volume_info: Some(get_volume_info::<T>),
        }
    }
}

unsafe extern "stdcall" fn get_volume_info<T: FileSystemContext>(
    fs: *mut FSP_FILE_SYSTEM,
    volume_info: *mut FSP_FSCTL_VOLUME_INFO,
) -> FSP_STATUS {
    let context: &T = (*fs).UserContext.cast::<T>().as_ref().unwrap_unchecked();
    match T::get_volume_info(context) {
        Ok(info) => {
            volume_info.write(info);
            STATUS_SUCCESS.into()
        }
        Err(e) => e.code(),
    }
    .0
}

unsafe extern "stdcall" fn close<T: FileSystemContext>(
    fs: *mut FSP_FILE_SYSTEM,
    file_context: *mut c_void,
) {
    let context: &T = (*fs).UserContext.cast::<T>().as_ref().unwrap_unchecked();
    if let Some(file_context) = file_context.cast::<T::FileContext>().as_mut() {
        T::close(context, file_context)
    }
}
