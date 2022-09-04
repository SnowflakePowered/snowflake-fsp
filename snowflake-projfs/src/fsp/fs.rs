use snowflake_projfs_common::path::OwnedProjectedPath;
use snowflake_projfs_common::projections::{Projection, ProjectionEntry};
use std::ffi::{OsStr, OsString};
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use widestring::U16CString;
use windows::core::{HSTRING, PCWSTR};
use windows::w;
use windows::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, MAX_PATH, STATUS_FILE_NOT_AVAILABLE, STATUS_INVALID_DEVICE_REQUEST,
};
use windows::Win32::Security::PSECURITY_DESCRIPTOR;
use windows::Win32::Storage::FileSystem::{FILE_ACCESS_FLAGS, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL};
use winfsp::filesystem::{DirBuffer, DirInfo, DirMarker, FileSecurity, FileSystemContext, FileSystemHost, FSP_FSCTL_FILE_INFO, FSP_FSCTL_VOLUME_INFO, FSP_FSCTL_VOLUME_PARAMS};
use winfsp::util::SafeDropHandle;

const ALLOCATION_UNIT: u16 = 4096;
const VOLUME_LABEL: &HSTRING = w!("Snowflake");
const FULLPATH_SIZE: usize = MAX_PATH as usize
    + (winfsp::filesystem::constants::FSP_FSCTL_TRANSACT_PATH_SIZEMAX as usize
        / std::mem::size_of::<u16>());

pub struct SnowflakeProjFs {
    pub fs: FileSystemHost,
}

#[repr(C)]
struct ProjFsContext {
    projections: Projection,
}

enum ProjectedHandle {
    Real(SafeDropHandle),
    Directory(OwnedProjectedPath),
}

#[repr(C)]
pub struct ProjFsFileContext {
    handle: ProjectedHandle,
    dir_buffer: DirBuffer,
}

#[inline(always)]
const fn quadpart(hi: u32, lo: u32) -> u64 {
    (hi as u64) << 32 | lo as u64
}

macro_rules! win32_try {
    (unsafe $e:expr) => {
        if unsafe { !($e).as_bool() } {
            return Err(::winfsp::error::FspError::from(unsafe { GetLastError() }));
        }
    };
}

impl ProjFsContext {
    fn get_root_file_info(file_info: &mut FSP_FSCTL_FILE_INFO) {
        file_info.FileAttributes = FILE_ATTRIBUTE_DIRECTORY.0;

        file_info.ReparseTag = 0;
        file_info.IndexNumber = 0;
        file_info.HardLinks = 0;

        file_info.FileSize = 0;
        file_info.AllocationSize = (file_info.FileSize + ALLOCATION_UNIT as u64 - 1)
            / ALLOCATION_UNIT as u64
            * ALLOCATION_UNIT as u64;
    }
}

impl FileSystemContext for ProjFsContext {
    type FileContext = ProjFsFileContext;

    fn get_security_by_name<P: AsRef<OsStr>>(
        &self,
        file_name: P,
        security_descriptor: PSECURITY_DESCRIPTOR,
        descriptor_len: Option<u64>,
    ) -> winfsp::Result<FileSecurity> {
        eprintln!("gsbn: {:?}", file_name.as_ref());

        if file_name.as_ref() == "\\" {
            return Ok(FileSecurity {
                attributes: FILE_ATTRIBUTE_DIRECTORY.0,
                reparse: false,
                sz_security_descriptor: 0,
            });
        }

        Ok(FileSecurity {
            attributes: 0,
            reparse: false,
            sz_security_descriptor: 0,
        })
    }

    fn open<P: AsRef<OsStr>>(
        &self,
        file_name: P,
        create_options: u32,
        granted_access: FILE_ACCESS_FLAGS,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> winfsp::Result<Self::FileContext> {
        eprintln!("open: {:?}", file_name.as_ref());
        if file_name.as_ref() == "\\" {
            Self::get_root_file_info(file_info);
            return Ok(Self::FileContext {
                handle: ProjectedHandle::Directory(OwnedProjectedPath::root()),
                dir_buffer: Default::default(),
            });
        }

        Err(ERROR_FILE_NOT_FOUND.into())
    }

    fn close(&self, context: Self::FileContext) {}

    fn read_directory<P: Into<PCWSTR>>(&self, context: &mut Self::FileContext,
                                       pattern: Option<P>,
                                       marker: DirMarker,
                                       buffer: &mut [u8]) -> winfsp::Result<u32> {
        if let Ok(mut buffer) =
            context.dir_buffer.acquire(marker.is_none(), None) {
            let mut dirinfo = DirInfo::<{ MAX_PATH as usize }>::new();

            match &context.handle {
                ProjectedHandle::Real(_) => {},
                ProjectedHandle::Directory(path) if path == OwnedProjectedPath::ROOT => {
                    dirinfo.reset();
                    let finfo = dirinfo.file_info_mut();
                    finfo.FileAttributes = FILE_ATTRIBUTE_NORMAL.0;

                    dirinfo.set_file_name("test")?;

                    if let Err(e) = buffer.write(&mut dirinfo) {
                        eprintln!("{:?}", e);
                        drop(buffer);
                        return Err(e);
                    }
                }
                ProjectedHandle::Directory(path) => {
                }
            }

        }

        Ok(context.dir_buffer.read(marker, buffer))
    }

    fn get_volume_info(&self, out_volume_info: &mut FSP_FSCTL_VOLUME_INFO) -> winfsp::Result<()> {
        let mut total_size = 0u64;
        let mut free_size = 0u64;

        out_volume_info.TotalSize = total_size;
        out_volume_info.FreeSize = free_size;
        out_volume_info.VolumeLabel[0..VOLUME_LABEL.len()].copy_from_slice(VOLUME_LABEL.as_wide());
        out_volume_info.VolumeLabelLength =
            (VOLUME_LABEL.len() * std::mem::size_of::<u16>()) as u16;
        Ok(())
    }
}

impl SnowflakeProjFs {
    pub fn create(
        projections: Vec<ProjectionEntry>,
        volume_prefix: &str,
    ) -> anyhow::Result<SnowflakeProjFs> {
        let mut volume_params = FSP_FSCTL_VOLUME_PARAMS {
            SectorSize: ALLOCATION_UNIT,
            SectorsPerAllocationUnit: 1,
            VolumeCreationTime: 0,
            VolumeSerialNumber: 0,
            FileInfoTimeout: 1000,
            ..Default::default()
        };
        volume_params.set_CaseSensitiveSearch(0);
        volume_params.set_CasePreservedNames(1);
        volume_params.set_UnicodeOnDisk(1);
        volume_params.set_PersistentAcls(1);
        volume_params.set_PostCleanupWhenModifiedOnly(1);
        // volume_params.set_PassQueryDirectoryPattern(1);
        volume_params.set_FlushAndPurgeOnCleanup(1);
        volume_params.set_UmFileContextIsUserContext2(1);

        let prefix = HSTRING::from(volume_prefix);
        let fs_name = w!("snowflake-projfs");

        volume_params.Prefix[..std::cmp::min(prefix.len(), 192)]
            .copy_from_slice(&prefix.as_wide()[..std::cmp::min(prefix.len(), 192)]);

        volume_params.FileSystemName[..std::cmp::min(fs_name.len(), 192)]
            .copy_from_slice(&fs_name.as_wide()[..std::cmp::min(fs_name.len(), 192)]);

        let context = ProjFsContext {
            projections: Projection::from(projections.as_slice()),
        };

        unsafe {
            Ok(SnowflakeProjFs {
                fs: FileSystemHost::new(volume_params, context)?,
            })
        }
    }
}
