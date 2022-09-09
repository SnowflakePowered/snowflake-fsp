use snowflake_projfs_common::path::OwnedProjectedPath;
use snowflake_projfs_common::projections::{FileAccess, Projection, ProjectionEntry};

use std::ffi::OsStr;
use std::fs;
use std::fs::{DirEntry, OpenOptions};
use std::io::ErrorKind;
use std::mem::MaybeUninit;
use std::ops::Deref;

use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::IntoRawHandle;
use std::path::Path;
use time::OffsetDateTime;
use widestring::{u16cstr, U16String};

use windows::core::{HSTRING, PCWSTR, PSTR};
use windows::w;
use windows::Win32::Foundation::{
    GetLastError, ERROR_ACCESS_DENIED, ERROR_DIRECTORY, ERROR_FILE_NOT_FOUND, ERROR_FILE_OFFLINE,
    HANDLE, MAX_PATH,
};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorA, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    GetKernelObjectSecurity, DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FindClose, FindFirstFileW, FindNextFileW, GetFileInformationByHandle,
    GetFinalPathNameByHandleW, ReadFile, BY_HANDLE_FILE_INFORMATION, FILE_ACCESS_FLAGS,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_OFFLINE, FILE_ATTRIBUTE_READONLY,
    FILE_FLAGS_AND_ATTRIBUTES, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_DELETE_ON_CLOSE,
    FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_NAME, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, READ_CONTROL, WIN32_FIND_DATAW,
};
use windows::Win32::System::WindowsProgramming::FILE_DELETE_ON_CLOSE;
use windows::Win32::System::IO::{OVERLAPPED, OVERLAPPED_0, OVERLAPPED_0_0};
use winfsp::error::FspError;
use winfsp::filesystem::{
    DirBuffer, DirInfo, DirMarker, FileSecurity, FileSystemContext, FileSystemHost, IoResult,
    FSP_FSCTL_FILE_INFO, FSP_FSCTL_VOLUME_INFO, FSP_FSCTL_VOLUME_PARAMS,
};
use winfsp::util::SafeDropHandle;

use crate::fsp::util::{quadpart_to_u64, systemtime_to_filetime, win32_try};

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

    fn get_real_file_info(
        handle: HANDLE,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> winfsp::Result<()> {
        let mut os_file_info: BY_HANDLE_FILE_INFORMATION = Default::default();
        win32_try!(unsafe GetFileInformationByHandle(handle, &mut os_file_info));

        file_info.FileAttributes = os_file_info.dwFileAttributes;

        // todo: reparse
        file_info.ReparseTag = 0;
        file_info.IndexNumber = 0;
        file_info.HardLinks = 0;

        file_info.FileSize = quadpart_to_u64(os_file_info.nFileSizeHigh, os_file_info.nFileSizeLow);
        file_info.AllocationSize = (file_info.FileSize + ALLOCATION_UNIT as u64 - 1)
            / ALLOCATION_UNIT as u64
            * ALLOCATION_UNIT as u64;
        file_info.CreationTime = quadpart_to_u64(
            os_file_info.ftCreationTime.dwHighDateTime,
            os_file_info.ftCreationTime.dwLowDateTime,
        );
        file_info.LastAccessTime = quadpart_to_u64(
            os_file_info.ftLastAccessTime.dwHighDateTime,
            os_file_info.ftLastAccessTime.dwLowDateTime,
        );
        file_info.LastWriteTime = quadpart_to_u64(
            os_file_info.ftLastWriteTime.dwHighDateTime,
            os_file_info.ftLastWriteTime.dwLowDateTime,
        );
        file_info.ChangeTime = file_info.LastWriteTime;
        Ok(())
    }

    fn get_file_info_internal(
        &self,
        file: &ProjFsFileContext,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> winfsp::Result<()> {
        match &file.handle {
            ProjectedHandle::Real { handle, .. } => {
                // todo: check against protectlist for r/o
                Self::get_real_file_info(*handle.deref(), file_info)?
            }
            ProjectedHandle::Projected(handle) => {
                Self::get_real_file_info(*handle.deref(), file_info)?
            }
            ProjectedHandle::Directory(_) => self.get_virtdir_file_info(file_info),
        }

        Ok(())
    }

    fn get_real_file_security_by_name<P: AsRef<Path>>(
        path: P,
        security_descriptor: PSECURITY_DESCRIPTOR,
        descriptor_len: Option<u64>,
    ) -> winfsp::Result<FileSecurity> {
        let mut opt = OpenOptions::new();
        opt.access_mode(FILE_READ_ATTRIBUTES.0 | READ_CONTROL.0);
        opt.custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0);

        let f = opt.open(path)?;
        let metadata = f.metadata()?;
        let handle = HANDLE(f.into_raw_handle() as isize);

        let mut len_needed = 0;
        if let Some(descriptor_len) = descriptor_len {
            win32_try!(unsafe GetKernelObjectSecurity(
                handle,
                (OWNER_SECURITY_INFORMATION
                    | GROUP_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION)
                    .0,
                security_descriptor,
                descriptor_len as u32,
                &mut len_needed,
            ));
        }

        Ok(FileSecurity {
            attributes: metadata.file_attributes(),
            reparse: false,
            sz_security_descriptor: len_needed as u64,
        })
    }

    fn open_handle_internal<P: Into<HSTRING>>(
        file_path: P,
        create_options: u32,
        mut granted_access: FILE_ACCESS_FLAGS,
        request_access: FileAccess,
    ) -> winfsp::Result<HANDLE> {
        let mut create_flags = FILE_FLAG_BACKUP_SEMANTICS;
        if (create_options & FILE_DELETE_ON_CLOSE) != 0 {
            create_flags |= FILE_FLAG_DELETE_ON_CLOSE
        }

        if request_access == FileAccess::Read {
            // remove write access to the file.
            granted_access = FILE_GENERIC_EXECUTE | FILE_GENERIC_READ;
        }

        let file_path = file_path.into();

        let handle = unsafe {
            let handle = CreateFileW(
                PCWSTR(file_path.as_ptr()),
                granted_access,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                create_flags,
                None,
            )?;
            if handle.is_invalid() {
                return Err(FspError::from(GetLastError()));
            }
            handle
        };

        Ok(handle)
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
        if file_name.as_ref() == "\\" {
            return Ok(FileSecurity {
                attributes: FILE_ATTRIBUTE_DIRECTORY.0 | FILE_ATTRIBUTE_READONLY.0,
                reparse: false,
                sz_security_descriptor: 0,
            });
        }

        if let Some((entry, remainder)) = self.projections.search_entry(file_name.as_ref()) {
            return match (entry, remainder) {
                (ProjectionEntry::File { source, .. }, _)
                | (ProjectionEntry::Portal { source, .. }, None) => {
                    Self::get_real_file_security_by_name(
                        source,
                        security_descriptor,
                        descriptor_len,
                    )
                    // FspError coerces to Win32 whenever possible.
                    .map_err(|e| {
                        if matches!(e, FspError::WIN32(ERROR_FILE_NOT_FOUND)) {
                            FspError::WIN32(ERROR_FILE_OFFLINE)
                        } else {
                            e
                        }
                    })
                }
                (ProjectionEntry::Directory { .. }, _) => {
                    let sz_security_descriptor = if let Some(d) = descriptor_len {
                        winfsp::util::get_process_security(security_descriptor, Some(d as u32))?
                    } else {
                        0
                    };

                    Ok(FileSecurity {
                        attributes: FILE_ATTRIBUTE_DIRECTORY.0 | FILE_ATTRIBUTE_READONLY.0,
                        reparse: false,
                        sz_security_descriptor: sz_security_descriptor as u64,
                    })
                }
                (ProjectionEntry::Portal { source, .. }, Some(remainder)) => {
                    // todo: adjust attributes for ro protectlist
                    eprintln!("fullpath {:?}", source.join(&remainder));
                    Self::get_real_file_security_by_name(
                        source.join(&remainder),
                        security_descriptor,
                        descriptor_len,
                    )
                }
            };
        }

        Err(ERROR_FILE_NOT_FOUND.into())
    }

    fn open<P: AsRef<OsStr>>(
        &self,
        file_name: P,
        create_options: u32,
        mut granted_access: FILE_ACCESS_FLAGS,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> winfsp::Result<Self::FileContext> {
        if file_name.as_ref() == "\\" {
            let context = Self::FileContext {
                handle: ProjectedHandle::Directory(OwnedProjectedPath::root()),
                dir_buffer: Default::default(),
            };
            self.get_file_info_internal(&context, file_info)?;
            return Ok(context);
        }

        if let Some((entry, remainder)) = self.projections.search_entry(file_name.as_ref()) {
            match (entry, remainder) {
                (
                    ProjectionEntry::File {
                        name,
                        source,
                        access,
                        ..
                    },
                    _,
                )
                | (
                    ProjectionEntry::Portal {
                        name,
                        source,
                        access,
                        ..
                    },
                    None,
                ) => {
                    let file_path = HSTRING::from(source.as_os_str());
                    let handle = Self::open_handle_internal(
                        file_path,
                        create_options,
                        granted_access,
                        *access,
                    )?;
                    let context = Self::FileContext {
                        handle: ProjectedHandle::Projected(SafeDropHandle::from(handle)),
                        dir_buffer: Default::default(),
                    };

                    self.get_file_info_internal(&context, file_info)?;
                    return Ok(context);
                }
                (ProjectionEntry::Directory { name, .. }, _) => {
                    eprintln!("vd: {:?}", name);
                    let context = Self::FileContext {
                        handle: ProjectedHandle::Directory(name.clone()),
                        dir_buffer: Default::default(),
                    };
                    self.get_file_info_internal(&context, file_info)?;
                    return Ok(context);
                }
                (
                    ProjectionEntry::Portal {
                        source,
                        name,
                        access,
                        ..
                    },
                    Some(remainder),
                ) => {
                    let file_path = source.join(remainder);
                    let file_path = HSTRING::from(file_path.as_os_str());

                    // todo: check with protectlist.
                    let handle = Self::open_handle_internal(
                        file_path,
                        create_options,
                        granted_access,
                        *access,
                    )?;
                    let context = Self::FileContext {
                        handle: ProjectedHandle::Real {
                            handle: SafeDropHandle::from(handle),
                            parent: name.clone(),
                        },
                        dir_buffer: Default::default(),
                    };

                    self.get_file_info_internal(&context, file_info)?;
                    return Ok(context);
                }
            }
        }

        Err(ERROR_FILE_OFFLINE.into())
    }

    fn close(&self, _context: Self::FileContext) {}

    fn create<P: AsRef<OsStr>>(
        &self,
        file_name: P,
        _create_options: u32,
        _granted_access: FILE_ACCESS_FLAGS,
        _file_attributes: FILE_FLAGS_AND_ATTRIBUTES,
        _security_descriptor: PSECURITY_DESCRIPTOR,
        _allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        _extra_buffer_is_reparse_point: bool,
        _file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> winfsp::Result<Self::FileContext> {
        if let Some((entry, remainder)) = self.projections.search_entry(file_name.as_ref()) {
            match (entry, remainder) {
                (ProjectionEntry::Portal { .. }, Some(remainder)) => {
                    // todo: create
                    eprintln!("{:?}", remainder)
                }
                _ => {
                    return Err(ERROR_ACCESS_DENIED.into());
                }
            }
        }
        Err(ERROR_ACCESS_DENIED.into())
    }

    fn get_file_info(
        &self,
        context: &Self::FileContext,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> winfsp::Result<()> {
        self.get_file_info_internal(context, file_info)
    }

    fn get_security(
        &self,
        context: &Self::FileContext,
        security_descriptor: PSECURITY_DESCRIPTOR,
        descriptor_len: Option<u64>,
    ) -> winfsp::Result<u64> {
        let mut descriptor_size_needed = 0;
        match &context.handle {
            ProjectedHandle::Real { handle, .. } | ProjectedHandle::Projected(handle) => {
                win32_try!(unsafe GetKernelObjectSecurity(
                    *handle.deref(),
                    (OWNER_SECURITY_INFORMATION
                        | GROUP_SECURITY_INFORMATION
                        | DACL_SECURITY_INFORMATION)
                        .0,
                    security_descriptor,
                    descriptor_len.unwrap_or(0) as u32,
                    &mut descriptor_size_needed,
                ));
            }
            ProjectedHandle::Directory(_) => {
                descriptor_size_needed = winfsp::util::get_process_security(
                    security_descriptor,
                    descriptor_len.map(|d| d as u32),
                )?
            }
        }

        Ok(descriptor_size_needed as u64)
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

    fn read(
        &self,
        context: &Self::FileContext,
        buffer: &mut [u8],
        offset: u64,
    ) -> winfsp::Result<IoResult> {
        let mut overlapped = OVERLAPPED {
            Anonymous: OVERLAPPED_0 {
                Anonymous: OVERLAPPED_0_0 {
                    Offset: offset as u32,
                    OffsetHigh: (offset >> 32) as u32,
                },
            },
            ..Default::default()
        };

        let mut bytes_read = 0;

        match &context.handle {
            ProjectedHandle::Real { handle, .. } | ProjectedHandle::Projected(handle) => {
                win32_try!(unsafe ReadFile(
                    *handle.deref(),
                    buffer.as_mut_ptr() as *mut _,
                    buffer.len() as u32,
                    &mut bytes_read,
                    &mut overlapped,
                ));
            }
            ProjectedHandle::Directory(_) => return Err(ERROR_DIRECTORY.into()),
        }

        Ok(IoResult {
            bytes_transferred: bytes_read,
            io_pending: false,
        })
    }

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
                ProjectedHandle::Real { handle, .. } | ProjectedHandle::Projected(handle) => {
                    let mut full_path = [0; FULLPATH_SIZE];
                    let length = unsafe {
                        let length = GetFinalPathNameByHandleW(
                            *handle.deref(),
                            &mut full_path[0..FULLPATH_SIZE - 1],
                            FILE_NAME::default(),
                        );
                        if length == 0 {
                            return Err(GetLastError().into());
                        }
                        length
                    };

                    let full_path =
                        unsafe { U16String::from_ptr(&full_path as *const u16, length as usize) };

                    let readdir = fs::read_dir(full_path.to_os_string())?;
                    for entry in readdir {
                        dirinfo.reset();
                        let entry = entry?;
                        let find_data = entry.metadata()?;
                        let finfo = dirinfo.file_info_mut();
                        finfo.FileAttributes = find_data.file_attributes();
                        finfo.ReparseTag = 0;
                        finfo.FileSize = find_data.file_size();
                        finfo.AllocationSize = ((finfo.FileSize + ALLOCATION_UNIT as u64 - 1)
                            / ALLOCATION_UNIT as u64)
                            * ALLOCATION_UNIT as u64;
                        finfo.CreationTime = find_data.creation_time();
                        finfo.LastAccessTime = find_data.last_access_time();
                        finfo.LastWriteTime = find_data.last_write_time();
                        finfo.ChangeTime = finfo.LastWriteTime;
                        finfo.HardLinks = 0;
                        finfo.IndexNumber = 0;
                        dirinfo.set_file_name(entry.file_name())?;
                        buffer.write(&mut dirinfo)?;
                    }
                }
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
                                ProjectionEntry::Portal {
                                    name: _,
                                    source,
                                    access,
                                    ..
                                }
                                | ProjectionEntry::File {
                                    name: _,
                                    source,
                                    access,
                                } => {
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
                                            FILE_ATTRIBUTE_OFFLINE.0 | FILE_ATTRIBUTE_READONLY.0
                                        };
                                        finfo.LastAccessTime =
                                            systemtime_to_filetime(self.start_time);
                                        finfo.LastWriteTime = finfo.LastAccessTime;
                                        finfo.CreationTime = finfo.LastAccessTime;
                                        finfo.ChangeTime = finfo.LastAccessTime;
                                    }

                                    finfo.AllocationSize =
                                        (finfo.FileSize + ALLOCATION_UNIT as u64 - 1)
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
