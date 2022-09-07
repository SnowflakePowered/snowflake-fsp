use snowflake_projfs_common::path::OwnedProjectedPath;
use snowflake_projfs_common::projections::{FileAccess, Projection, ProjectionEntry};

use std::ffi::{OsStr, OsString};
use std::fs;
use std::fs::{File, OpenOptions};
use std::os::windows::ffi::OsStringExt;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::IntoRawHandle;
use time::OffsetDateTime;

use windows::core::{HSTRING, PCWSTR};
use windows::w;
use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, HANDLE, MAX_PATH, STATUS_INVALID_DEVICE_REQUEST};
use windows::Win32::Security::PSECURITY_DESCRIPTOR;
use windows::Win32::Storage::FileSystem::{FILE_ACCESS_FLAGS, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_OFFLINE, FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_VIRTUAL, FILE_FLAG_BACKUP_SEMANTICS};
use winfsp::filesystem::{
    DirBuffer, DirInfo, DirMarker, FileSecurity, FileSystemContext, FileSystemHost,
    FSP_FSCTL_FILE_INFO, FSP_FSCTL_VOLUME_INFO, FSP_FSCTL_VOLUME_PARAMS,
};
use winfsp::util::SafeDropHandle;

use crate::fsp::util::{systemtime_to_filetime, win32_try};

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
    start_time: OffsetDateTime,
    projections: Projection,
}

enum ProjectedHandle {
    /// A real file opened under a portal.
    Real {
        handle: SafeDropHandle,
        parent: OwnedProjectedPath,
    },
    /// A projected file or directory that points to a real filesystem entry.
    Projected(SafeDropHandle),
    /// A directory with a canonical path in the projection tree.
    Directory(OwnedProjectedPath),
}

#[repr(C)]
pub struct ProjFsFileContext {
    handle: ProjectedHandle,
    dir_buffer: DirBuffer,
}

impl ProjFsContext {
    fn get_virtdir_file_info(&self, file_info: &mut FSP_FSCTL_FILE_INFO) {
        file_info.FileAttributes = (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_READONLY).0;

        file_info.LastAccessTime = systemtime_to_filetime(self.start_time);

        file_info.LastWriteTime = file_info.LastAccessTime;
        file_info.CreationTime = file_info.LastAccessTime;
        file_info.ChangeTime = file_info.LastAccessTime;

        file_info.ReparseTag = 0;
        file_info.IndexNumber = 0;
        file_info.HardLinks = 0;

        file_info.FileSize = 0;
        file_info.AllocationSize = (file_info.FileSize + ALLOCATION_UNIT as u64 - 1)
            / ALLOCATION_UNIT as u64
            * ALLOCATION_UNIT as u64;
    }

    fn get_real_file_info() {

    }
    fn get_file_info_internal(&self, file: &ProjFsFileContext, file_info: &mut FSP_FSCTL_FILE_INFO) -> winfsp::Result<()>{
        match file.handle {
            ProjectedHandle::Real { .. } => {}
            ProjectedHandle::Projected(_) => {}
            ProjectedHandle::Directory(_) => {
                self.get_virtdir_file_info(file_info)
            }
        }

        Ok(())
    }
}

impl FileSystemContext for ProjFsContext {
    type FileContext = ProjFsFileContext;

    fn get_security_by_name<P: AsRef<OsStr>>(
        &self,
        file_name: P,
        _security_descriptor: PSECURITY_DESCRIPTOR,
        _descriptor_len: Option<u64>,
    ) -> winfsp::Result<FileSecurity> {
        if file_name.as_ref() == "\\" {
            return Ok(FileSecurity {
                attributes: FILE_ATTRIBUTE_DIRECTORY.0 | FILE_ATTRIBUTE_READONLY.0,
                reparse: false,
                sz_security_descriptor: 0,
            });
        }

        if let Some((entry, _remainder)) = self.projections.search_entry(file_name.as_ref()) {
            match entry {
                // todo: need to get real shit.
                ProjectionEntry::File { .. } => {}
                ProjectionEntry::Portal { .. } => {}
                ProjectionEntry::Directory { .. } => {
                    return Ok(FileSecurity {
                        attributes: FILE_ATTRIBUTE_DIRECTORY.0 | FILE_ATTRIBUTE_READONLY.0,
                        reparse: false,
                        sz_security_descriptor: 0,
                    });
                }
            }
        }

        Ok(FileSecurity {
            attributes: 0,
            reparse: false,
            sz_security_descriptor: 0,
        })
    }

    fn get_file_info(&self, context: &Self::FileContext, file_info: &mut FSP_FSCTL_FILE_INFO) -> winfsp::Result<()> {
        self.get_file_info_internal(context, file_info)
    }

    fn open<P: AsRef<OsStr>>(
        &self,
        file_name: P,
        _create_options: u32,
        _granted_access: FILE_ACCESS_FLAGS,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> winfsp::Result<Self::FileContext> {
        eprintln!("open: {:?}", file_name.as_ref());
        if file_name.as_ref() == "\\" {
            let context = Self::FileContext {
                handle: ProjectedHandle::Directory(OwnedProjectedPath::root()),
                dir_buffer: Default::default(),
            };
            self.get_file_info_internal(&context, file_info)?;
            return Ok(context);
        }

        if let Some((entry, _remainder)) = self.projections.search_entry(file_name.as_ref()) {
            match entry {
                ProjectionEntry::File { .. } => {}
                ProjectionEntry::Directory { name, .. } => {
                    eprintln!("vd: {:?}", name);
                    let context = Self::FileContext {
                        handle: ProjectedHandle::Directory(name.clone()),
                        dir_buffer: Default::default(),
                    };
                    self.get_file_info_internal(&context, file_info)?;
                    return Ok(context);
                }
                ProjectionEntry::Portal { .. } => {}
            }
        }

        Err(ERROR_FILE_NOT_FOUND.into())
    }

    fn close(&self, _context: Self::FileContext) {}

    fn read_directory<P: Into<PCWSTR>>(
        &self,
        context: &mut Self::FileContext,
        _pattern: Option<P>,
        mut marker: DirMarker,
        buffer: &mut [u8],
    ) -> winfsp::Result<u32> {
        if let Ok(mut buffer) = context.dir_buffer.acquire(marker.is_none(), None) {
            let mut dirinfo = DirInfo::<{ MAX_PATH as usize }>::new();

            match &context.handle {
                ProjectedHandle::Real { .. } => {}
                ProjectedHandle::Projected(_) => {}
                ProjectedHandle::Directory(path) => {
                    if !path.is_root() {
                        if marker.is_none() {
                            // add '.'
                            dirinfo.reset();
                            let finfo = dirinfo.file_info_mut();

                            self.get_virtdir_file_info(finfo);
                            dirinfo.set_file_name(".")?;
                            buffer.write(&mut dirinfo)?;
                        }

                        if marker.is_none() || marker.is_current() {
                            // add '..'
                            dirinfo.reset();
                            let finfo = dirinfo.file_info_mut();
                            self.get_virtdir_file_info(finfo);
                            dirinfo.set_file_name("..")?;
                            buffer.write(&mut dirinfo)?;
                            marker.reset();
                        }
                    }

                    if let Some(directory) = self.projections.get_children(path) {
                        for entry in directory {
                            dirinfo.reset();
                            let filename = entry
                                .file_name()
                                .expect("projection entry must have filename, can not be root.");

                            let finfo = dirinfo.file_info_mut();

                            match entry {
                                ProjectionEntry::Portal { name, source, access, .. }
                                    | ProjectionEntry::File { name, source, access } => {
                                    if let Ok(metadata) = fs::metadata(source) {
                                        finfo.FileSize = metadata.file_size();
                                        finfo.FileAttributes = metadata.file_attributes();
                                        finfo.CreationTime = metadata.creation_time();
                                        finfo.LastAccessTime = metadata.last_access_time();
                                        finfo.LastWriteTime = metadata.last_write_time();
                                        finfo.ChangeTime = finfo.LastWriteTime;

                                        // respect access flag
                                        if access == &FileAccess::Read {
                                            finfo.FileAttributes |= FILE_ATTRIBUTE_READONLY.0;
                                        }
                                    } else {
                                        finfo.FileSize = 0;
                                        finfo.FileAttributes = if entry.is_portal() {
                                            FILE_ATTRIBUTE_DIRECTORY.0 | FILE_ATTRIBUTE_OFFLINE.0
                                        } else {
                                            // non-existent file
                                            FILE_ATTRIBUTE_NORMAL.0 | FILE_ATTRIBUTE_OFFLINE.0 | FILE_ATTRIBUTE_READONLY.0
                                        };
                                        finfo.LastAccessTime = systemtime_to_filetime(self.start_time);
                                        finfo.LastWriteTime = finfo.LastAccessTime;
                                        finfo.CreationTime = finfo.LastAccessTime;
                                        finfo.ChangeTime = finfo.LastAccessTime;
                                    }

                                    finfo.AllocationSize = (finfo.FileSize + ALLOCATION_UNIT as u64 - 1)
                                        / ALLOCATION_UNIT as u64
                                        * ALLOCATION_UNIT as u64;

                                    finfo.HardLinks = 0;
                                    finfo.ReparseTag = 0;
                                    finfo.IndexNumber = 0;
                                }

                                ProjectionEntry::Directory { .. } => {
                                    self.get_virtdir_file_info(finfo);
                                }
                            }
                            dirinfo.set_file_name(filename)?;

                            if let Err(e) = buffer.write(&mut dirinfo) {
                                eprintln!("{:?}", e);
                                drop(buffer);
                                return Err(e);
                            }
                        }
                    }
                }
            }
        }

        Ok(context.dir_buffer.read(marker, buffer))
    }

    fn get_volume_info(&self, out_volume_info: &mut FSP_FSCTL_VOLUME_INFO) -> winfsp::Result<()> {
        let total_size = 0u64;
        let free_size = 0u64;

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
            start_time: OffsetDateTime::now_utc(),
            projections: Projection::from(projections.as_slice()),
        };

        unsafe {
            Ok(SnowflakeProjFs {
                fs: FileSystemHost::new(volume_params, context)?,
            })
        }
    }
}
