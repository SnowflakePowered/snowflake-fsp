use crate::fsp::{FileSystemContext, FspFileSystem};
use anyhow::anyhow;
use std::cell::RefCell;
use std::fs;
use std::io::ErrorKind;
use std::mem::{ManuallyDrop, MaybeUninit};
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use windows::core::HSTRING;
use windows::w;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use winfsp_sys::{
    FspFileSystemCreate, FspFileSystemDeleteDirectoryBuffer, FSP_FILE_SYSTEM,
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
impl FileSystemContext for PtfsContext {
    type FileContext = PtfsFileContext;

    fn get_volume_info(&self) -> windows::core::Result<FSP_FSCTL_VOLUME_INFO> {
        todo!()
    }

    unsafe fn close(&self, file: &mut Self::FileContext) {
        CloseHandle(file.handle);
        FspFileSystemDeleteDirectoryBuffer(&mut file.dir_buffer)
    }
}

impl Ptfs {
    pub fn create<P: AsRef<Path>>(
        path: P,
        volume_prefix: &str,
    ) -> anyhow::Result<Box<Ptfs>> {
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
