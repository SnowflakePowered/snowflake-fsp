use widestring::U16CStr;
use windows::Win32::Foundation::{
    STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_PARAMETER, STATUS_SUCCESS,
};
use winfsp_sys::{
    FspFileSystemAcquireDirectoryBufferEx, FspFileSystemDeleteDirectoryBuffer,
    FspFileSystemFillDirectoryBuffer, FspFileSystemReadDirectoryBuffer,
    FspFileSystemReleaseDirectoryBuffer, FSP_FSCTL_FILE_INFO, PVOID,
};

use crate::error::Result;

pub struct DirBuffer(PVOID);
pub struct DirBufferLock<'a>(&'a mut DirBuffer);

impl Default for DirBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl DirBuffer {
    pub fn new() -> Self {
        Self(std::ptr::null_mut())
    }

    pub fn acquire(&mut self, reset: bool, capacity_hint: Option<u32>) -> Result<DirBufferLock> {
        let mut result = STATUS_SUCCESS;
        unsafe {
            if FspFileSystemAcquireDirectoryBufferEx(
                &mut self.0,
                reset.into(),
                capacity_hint.unwrap_or(0),
                &mut result.0,
            ) != 0
            {
                Ok(DirBufferLock(self))
            } else {
                Err(result.into())
            }
        }
    }

    pub fn read(&mut self, marker: Option<&[u16]>, buffer: &mut [u8]) -> u32 {
        let mut out = 0u32;
        unsafe {
            FspFileSystemReadDirectoryBuffer(
                &mut self.0,
                marker.map_or(std::ptr::null_mut(), |v| v.as_ptr().cast_mut()),
                buffer.as_mut_ptr() as *mut _,
                buffer.len() as u32,
                &mut out,
            );
        }
        out
    }
}

impl DirBufferLock<'_> {
    pub fn fill<const D: usize>(&mut self, dir_info: &mut DirInfo<D>) -> Result<()> {
        let mut status = STATUS_SUCCESS;
        unsafe {
            let buffer = &mut self.0;
            // this is cursed.
            if FspFileSystemFillDirectoryBuffer(
                &mut buffer.0,
                (dir_info as *mut DirInfo<D>).cast(),
                &mut status.0,
            ) == 0
            {
                return Err(status.into());
            }
        }
        Ok(())
    }
}

impl Drop for DirBuffer {
    fn drop(&mut self) {
        unsafe {
            FspFileSystemDeleteDirectoryBuffer(&mut self.0);
        }
    }
}

impl Drop for DirBufferLock<'_> {
    fn drop(&mut self) {
        let buffer = &mut self.0;

        unsafe { FspFileSystemReleaseDirectoryBuffer(&mut buffer.0) }
    }
}

#[repr(C)]
union DirInfoPadding {
    next_offset: u64,
    padding: [u8; 24],
}

#[repr(C)]
pub struct DirInfo<const BUFFER_SIZE: usize> {
    size: u16,
    file_info: FSP_FSCTL_FILE_INFO,
    padding: DirInfoPadding,
    file_name: [u16; BUFFER_SIZE],
}

impl<const BUFFER_SIZE: usize> DirInfo<BUFFER_SIZE> {
    pub fn new() -> Self {
        assert_eq!(104, std::mem::size_of::<DirInfo<0>>());
        Self {
            // begin with initially no file_name
            size: std::mem::size_of::<DirInfo<0>>() as u16,
            file_info: FSP_FSCTL_FILE_INFO::default(),
            padding: DirInfoPadding { padding: [0; 24] },
            file_name: [0; BUFFER_SIZE],
        }
    }

    /// Set the file name of the directory info.
    ///
    /// The input buffer must not have a null byte at the end.
    pub fn set_file_name<'a, P: Into<&'a [u16]>>(&mut self, file_name: P) -> Result<()> {
        let file_name = file_name.into();
        let file_name =
            U16CStr::from_slice_truncate(file_name).map_err(|_| STATUS_INVALID_PARAMETER)?;
        let file_name = file_name.as_slice();
        if file_name.len() >= BUFFER_SIZE {
            return Err(STATUS_INSUFFICIENT_RESOURCES.into());
        }
        self.file_name[0..std::cmp::min(file_name.len(), BUFFER_SIZE)]
            .copy_from_slice(&file_name[0..std::cmp::min(file_name.len(), BUFFER_SIZE)]);
        self.size = (std::mem::size_of::<DirInfo<0>>()
            + std::mem::size_of::<u16>() * file_name.len()) as u16;
        Ok(())
    }

    pub fn file_info_mut(&mut self) -> &mut FSP_FSCTL_FILE_INFO {
        &mut self.file_info
    }

    pub fn reset(&mut self) {
        self.size = 0;
        self.file_info = FSP_FSCTL_FILE_INFO::default();
        self.padding.next_offset = 0;
        self.padding.padding = [0; 24];
        self.file_name = [0; BUFFER_SIZE]
    }
}

impl<const BUFFER_SIZE: usize> Default for DirInfo<BUFFER_SIZE> {
    fn default() -> Self {
        Self::new()
    }
}
