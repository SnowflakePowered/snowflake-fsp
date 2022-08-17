use crate::fsp::{FileSystemContext, FspFileSystem};
use anyhow::anyhow;
use std::cell::RefCell;
use std::fs;
use std::io::ErrorKind;
use std::mem::{ManuallyDrop, MaybeUninit};
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use windows::core::{Result, HSTRING, PWSTR};
use windows::w;
use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
use windows::Win32::Security::PSECURITY_DESCRIPTOR;
use windows::Win32::Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, FILE_ACCESS_FLAGS, FILE_FLAGS_AND_ATTRIBUTES, GetFileInformationByHandle};
use winfsp_sys::{
    FspFileSystemCreate, FspFileSystemDeleteDirectoryBuffer, FSP_FILE_SYSTEM, FSP_FSCTL_FILE_INFO,
    FSP_FSCTL_VOLUME_INFO, FSP_FSCTL_VOLUME_PARAMS, PVOID,
};

const ALLOCATION_UNIT: u16 = 4096;
pub struct Ptfs {
    pub fs: FspFileSystem,
}

#[repr(C)]
pub struct PtfsContext {
    path: PathBuf,
}

#[repr(C)]
pub struct PtfsFileContext {
    handle: HANDLE,
    dir_buffer: PVOID,
}

#[inline(always)]
const fn quadpart(hi: u32, lo: u32) -> u64 {
    (hi as u64) << 32 | lo as u64
}

impl PtfsContext {
    fn get_file_info_internal(&self, file_handle: HANDLE, file_info: &mut FSP_FSCTL_FILE_INFO) -> Result<()> {
        let mut os_file_info: BY_HANDLE_FILE_INFORMATION = Default::default();
        unsafe {
            if !GetFileInformationByHandle(file_handle, &mut os_file_info).as_bool() {
                return Err(GetLastError().into())
            }
        }

        file_info.FileAttributes = os_file_info.dwFileAttributes;

        // todo: reparse
        file_info.ReparseTag = 0;
        file_info.IndexNumber = 0;
        file_info.HardLinks = 0;

        file_info.FileSize = quadpart(os_file_info.nFileSizeHigh, os_file_info.nFileSizeLow);
        file_info.AllocationSize = (file_info.FileSize + ALLOCATION_UNIT as u64 - 1) / ALLOCATION_UNIT as u64 * ALLOCATION_UNIT as u64;
        file_info.CreationTime = quadpart(os_file_info.ftCreationTime.dwHighDateTime, os_file_info.ftCreationTime.dwLowDateTime);
        file_info.LastAccessTime = quadpart(os_file_info.ftLastAccessTime.dwHighDateTime, os_file_info.ftLastAccessTime.dwLowDateTime);
        file_info.LastWriteTime = quadpart(os_file_info.ftLastWriteTime.dwHighDateTime, os_file_info.ftLastWriteTime.dwLowDateTime);
        file_info.ChangeTime = file_info.LastWriteTime;
        Ok(())
    }
}

impl FileSystemContext for PtfsContext {
    type FileContext = PtfsFileContext;

    unsafe fn get_volume_info(&self) -> Result<FSP_FSCTL_VOLUME_INFO> {
        todo!()
    }

    unsafe fn get_security_by_name<P: AsRef<Path>>(
        &self,
        file_name: P,
    ) -> Result<(u32, PSECURITY_DESCRIPTOR, u32)> {
        todo!()
    }

    unsafe fn open<P: AsRef<Path>>(
        &self,
        file_name: P,
        create_options: FILE_FLAGS_AND_ATTRIBUTES,
        granted_access: FILE_ACCESS_FLAGS,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> Result<Self::FileContext> {
        todo!()
    }

    unsafe fn close(&self, file: &mut Self::FileContext) {
        CloseHandle(file.handle);
        FspFileSystemDeleteDirectoryBuffer(&mut file.dir_buffer)
    }
}

impl Ptfs {
    pub fn create<P: AsRef<Path>>(path: P, volume_prefix: &str) -> anyhow::Result<Box<Ptfs>> {
        let metadata = fs::metadata(&path)?;
        if !metadata.is_dir() {
            return Err(std::io::Error::new(ErrorKind::NotADirectory, "not a directory").into());
        }

        let canonical_path = fs::canonicalize(&path)?;
        let mut volume_params = FSP_FSCTL_VOLUME_PARAMS {
            SectorSize: ALLOCATION_UNIT,
            SectorsPerAllocationUnit: 1,
            VolumeCreationTime: metadata.creation_time(),
            VolumeSerialNumber: 0,
            FileInfoTimeout: 1000,
            ..Default::default()
        };
        volume_params.set_CaseSensitiveSearch(0);
        volume_params.set_CasePreservedNames(1);
        volume_params.set_UnicodeOnDisk(1);
        volume_params.set_PersistentAcls(1);
        volume_params.set_PostCleanupWhenModifiedOnly(1);
        volume_params.set_PassQueryDirectoryPattern(1);
        volume_params.set_FlushAndPurgeOnCleanup(1);
        volume_params.set_UmFileContextIsUserContext2(1);

        let prefix = HSTRING::from(volume_prefix);
        let fs_name = w!("snowflake-fsp");

        volume_params.Prefix[..std::cmp::min(prefix.len(), 192)]
            .copy_from_slice(&prefix.as_wide()[..std::cmp::min(prefix.len(), 192)]);

        volume_params.FileSystemName[..std::cmp::min(fs_name.len(), 192)]
            .copy_from_slice(&fs_name.as_wide()[..std::cmp::min(fs_name.len(), 192)]);

        let mut context = PtfsContext {
            path: canonical_path,
        };

        unsafe {
            Ok(Box::new(Ptfs {
                fs: FspFileSystem::new(volume_params, context)?,
            }))
        }
    }
}
