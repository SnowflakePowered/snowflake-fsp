use std::ffi::{OsStr, OsString};
use std::fs;
use std::fs::OpenOptions;

use std::ops::{BitXor, Deref};
use std::os::windows::ffi::OsStringExt;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::IntoRawHandle;
use std::path::{Path, PathBuf};

use time::OffsetDateTime;
use widestring::{U16Str, U16String};
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Foundation::{
    GetLastError, ERROR_ACCESS_DENIED, ERROR_DIRECTORY, ERROR_FILE_NOT_FOUND, ERROR_FILE_OFFLINE,
    ERROR_INVALID_NAME, HANDLE, MAX_PATH, STATUS_OBJECT_NAME_INVALID,
};

use windows::Win32::Security::{
    GetKernelObjectSecurity, DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FileAllocationInfo, FileBasicInfo, FileDispositionInfoEx, FileEndOfFileInfo,
    FlushFileBuffers, GetFileInformationByHandle, GetFileInformationByHandleEx, GetFileSizeEx,
    GetFinalPathNameByHandleW, MoveFileExW, ReadFile, SetFileInformationByHandle, WriteFile,
    BY_HANDLE_FILE_INFORMATION, CREATE_NEW, FILE_ACCESS_FLAGS, FILE_ALLOCATION_INFO,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_OFFLINE,
    FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_TAG_INFO, FILE_BASIC_INFO, FILE_END_OF_FILE_INFO,
    FILE_FLAGS_AND_ATTRIBUTES, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_DELETE_ON_CLOSE,
    FILE_FLAG_POSIX_SEMANTICS, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_NAME,
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    INVALID_FILE_ATTRIBUTES, MOVEFILE_REPLACE_EXISTING, MOVE_FILE_FLAGS, OPEN_EXISTING,
    READ_CONTROL,
};
use windows::Win32::System::WindowsProgramming::{
    FILE_DELETE_ON_CLOSE, FILE_DIRECTORY_FILE, FILE_DISPOSITION_FLAG_DELETE,
    FILE_DISPOSITION_FLAG_DO_NOT_DELETE, FILE_DISPOSITION_INFO_EX,
};
use windows::Win32::System::IO::{OVERLAPPED, OVERLAPPED_0, OVERLAPPED_0_0};

use snowflake_projfs_common::path::OwnedProjectedPath;
use snowflake_projfs_common::projections::{FileAccess, Projection, ProjectionEntry};
use winfsp::error::FspError;
use winfsp::filesystem::constants::FspCleanupFlags;
use winfsp::filesystem::{
    DirBuffer, DirInfo, DirMarker, FileSecurity, FileSystemContext, IoResult, FSP_FSCTL_FILE_INFO,
    FSP_FSCTL_VOLUME_INFO,
};
use winfsp::util::Win32SafeHandle;
use winfsp::WCStr;

use crate::fsp::host::{ALLOCATION_UNIT, FULLPATH_SIZE, VOLUME_LABEL};
use crate::fsp::util::{quadpart_to_u64, systemtime_to_filetime, win32_try};

/// Do an operation that requires a real file handle with optional else block for virtual directories.
/// If no optional block is provided, returns ERROR_DIRECTORY.
macro_rules! require_handle {
    ($context:expr, $handle:ident => $body:block) => {
        match $context {
            ProjectedHandle::Real {
                handle: $handle, ..
            }
            | ProjectedHandle::Projected($handle) => $body,
            ProjectedHandle::Directory(_) => return Err(ERROR_DIRECTORY.into()),
        }
    };
    ($context:expr, $handle:ident => $body:block else $el:block) => {
        match $context {
            ProjectedHandle::Real {
                handle: $handle, ..
            }
            | ProjectedHandle::Projected($handle) => $body,
            ProjectedHandle::Directory(_) => $el,
        }
    };
    ($context:expr, $handle:ident => $body:block else $path:ident => $el:block) => {
        match $context {
            ProjectedHandle::Real {
                handle: $handle, ..
            }
            | ProjectedHandle::Projected($handle) => $body,
            ProjectedHandle::Directory($path) => $el,
        }
    };
}

#[repr(C)]
pub struct ProjFsContext {
    start_time: OffsetDateTime,
    projections: Projection,
}

enum ProjectedHandle {
    /// A real file opened under a portal.
    Real {
        handle: Win32SafeHandle,
        portal: OwnedProjectedPath,
    },
    /// A projected file or directory that points to a real filesystem entry.
    Projected(Win32SafeHandle),
    /// A directory with a canonical path in the projection tree.
    Directory(OwnedProjectedPath),
}

fn join_remainder_windows_semantics(left: impl AsRef<OsStr>, right: impl AsRef<OsStr>) -> OsString {
    [left.as_ref(), right.as_ref()].join(OsStr::new("\\"))
}

#[repr(C)]
pub struct ProjFsFileContext {
    handle: ProjectedHandle,
    dir_buffer: DirBuffer,
}

impl ProjectedHandle {
    /// Get the real path of the handle if available.
    pub fn get_real_path(&self) -> Option<PathBuf> {
        require_handle!(self, handle => {
            let mut full_path = [0; FULLPATH_SIZE];
            let length = unsafe {
                GetFinalPathNameByHandleW(
                    *handle.deref(),
                    &mut full_path[0..FULLPATH_SIZE - 1],
                    FILE_NAME::default(),
                )
            };
            if length == 0 {
                return None;
            }
            let full_path = U16Str::from_slice(&full_path[..length as usize]);
            Some(PathBuf::from(full_path.to_os_string()))
        } else {
            None
        })
    }
}

impl ProjFsContext {
    pub(crate) fn new(projections: Projection) -> Self {
        ProjFsContext {
            start_time: OffsetDateTime::now_utc(),
            projections,
        }
    }

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
                Self::get_real_file_info(*handle.deref(), file_info).map_err(|e| {
                    eprintln!("error: {:?}", e);
                    e
                })?
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
        let handle = Win32SafeHandle::from(HANDLE(f.into_raw_handle() as isize));

        let mut len_needed = 0;
        if let Some(descriptor_len) = descriptor_len {
            win32_try!(unsafe GetKernelObjectSecurity(
                *handle,
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

    fn get_security_by_name<P: AsRef<WCStr>>(
        &self,
        file_name: P,
        security_descriptor: PSECURITY_DESCRIPTOR,
        descriptor_len: Option<u64>,
    ) -> winfsp::Result<FileSecurity> {
        let file_name = OsString::from_wide(file_name.as_ref().as_slice());
        if file_name.as_os_str() == "\\" {
            return Ok(FileSecurity {
                attributes: FILE_ATTRIBUTE_DIRECTORY.0 | FILE_ATTRIBUTE_READONLY.0,
                reparse: false,
                sz_security_descriptor: 0,
            });
        }

        if let Some((entry, remainder)) = self
            .projections
            .search_entry_case_insensitive(file_name.as_os_str())
        {
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
                    Self::get_real_file_security_by_name(
                        join_remainder_windows_semantics(source, remainder),
                        security_descriptor,
                        descriptor_len,
                    )
                }
            };
        }

        Err(ERROR_FILE_NOT_FOUND.into())
    }

    fn open<P: AsRef<WCStr>>(
        &self,
        file_name: P,
        create_options: u32,
        granted_access: FILE_ACCESS_FLAGS,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> winfsp::Result<Self::FileContext> {
        let file_name = OsString::from_wide(file_name.as_ref().as_slice());
        if file_name.as_os_str() == "\\" {
            let context = Self::FileContext {
                handle: ProjectedHandle::Directory(OwnedProjectedPath::root()),
                dir_buffer: Default::default(),
            };
            self.get_file_info_internal(&context, file_info)?;
            return Ok(context);
        }

        if let Some((entry, remainder)) = self
            .projections
            .search_entry_case_insensitive(file_name.as_os_str())
        {
            return match (entry, remainder) {
                (ProjectionEntry::File { source, access, .. }, _)
                | (ProjectionEntry::Portal { source, access, .. }, None) => {
                    // Forbid projected entries from being deleted.
                    if (create_options & FILE_DELETE_ON_CLOSE) != 0 {
                        eprintln!("fp delete failed");
                        return Err(ERROR_ACCESS_DENIED.into());
                    }
                    let file_path = HSTRING::from(source.as_os_str());
                    let handle = Self::open_handle_internal(
                        file_path,
                        create_options,
                        granted_access,
                        *access,
                    )?;
                    let context = Self::FileContext {
                        handle: ProjectedHandle::Projected(Win32SafeHandle::from(handle)),
                        dir_buffer: Default::default(),
                    };

                    self.get_file_info_internal(&context, file_info)?;
                    Ok(context)
                }
                (ProjectionEntry::Directory { name, .. }, _) => {
                    // Forbid projected entries from being deleted.
                    if (create_options & FILE_DELETE_ON_CLOSE) != 0 {
                        eprintln!("d delete failed");
                        return Err(ERROR_ACCESS_DENIED.into());
                    }

                    let context = Self::FileContext {
                        handle: ProjectedHandle::Directory(name.clone()),
                        dir_buffer: Default::default(),
                    };
                    self.get_file_info_internal(&context, file_info)?;
                    Ok(context)
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
                    let file_path = join_remainder_windows_semantics(source, remainder);
                    let file_path = HSTRING::from(file_path.as_os_str());
                    eprintln!("{}", file_path);

                    // todo: check with protectlist.
                    let handle = Self::open_handle_internal(
                        file_path,
                        create_options,
                        granted_access,
                        *access,
                    )?;
                    let context = Self::FileContext {
                        handle: ProjectedHandle::Real {
                            handle: Win32SafeHandle::from(handle),
                            portal: name.clone(),
                        },
                        dir_buffer: Default::default(),
                    };

                    self.get_file_info_internal(&context, file_info)?;
                    Ok(context)
                }
            };
        }

        Err(ERROR_FILE_OFFLINE.into())
    }

    fn close(&self, _context: Self::FileContext) {}

    fn create<P: AsRef<WCStr>>(
        &self,
        file_name: P,
        create_options: u32,
        granted_access: FILE_ACCESS_FLAGS,
        mut file_attributes: FILE_FLAGS_AND_ATTRIBUTES,
        security_descriptor: PSECURITY_DESCRIPTOR,
        _allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        _extra_buffer_is_reparse_point: bool,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> winfsp::Result<Self::FileContext> {
        let file_name = OsString::from_wide(file_name.as_ref().as_slice());
        let new_path = Path::new(file_name.as_os_str());

        let parent = new_path.parent().ok_or(STATUS_OBJECT_NAME_INVALID)?;
        let new_filename = new_path.file_name().ok_or(STATUS_OBJECT_NAME_INVALID)?;

        eprintln!("cr: {:?} under {:?}", new_path, parent);
        if let Some((entry, remainder)) = self.projections.search_entry_case_insensitive(parent) {
            return match entry {
                ProjectionEntry::Portal { source, name, .. } => {
                    // true parent
                    let parent = remainder.map_or_else(
                        || source.clone().into_os_string(),
                        |remainder| join_remainder_windows_semantics(source, remainder),
                    );
                    let target_path = join_remainder_windows_semantics(parent, new_filename);
                    if target_path.as_os_str().len() > FULLPATH_SIZE {
                        return Err(STATUS_OBJECT_NAME_INVALID.into());
                    }

                    let security_attributes = SECURITY_ATTRIBUTES {
                        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                        lpSecurityDescriptor: security_descriptor.0,
                        bInheritHandle: false.into(),
                    };

                    let mut create_flags = FILE_FLAG_BACKUP_SEMANTICS;
                    if (create_options & FILE_DELETE_ON_CLOSE) != 0 {
                        create_flags |= FILE_FLAG_DELETE_ON_CLOSE;
                    }

                    if (create_options & FILE_DIRECTORY_FILE) != 0 {
                        create_flags |= FILE_FLAG_POSIX_SEMANTICS;
                        file_attributes |= FILE_ATTRIBUTE_DIRECTORY
                    } else {
                        file_attributes &= !FILE_ATTRIBUTE_DIRECTORY
                    }

                    if file_attributes == FILE_FLAGS_AND_ATTRIBUTES(0) {
                        file_attributes = FILE_ATTRIBUTE_NORMAL
                    }

                    let target_path = HSTRING::from(target_path.as_os_str());

                    let handle = unsafe {
                        let handle = CreateFileW(
                            PCWSTR(target_path.as_ptr()),
                            granted_access,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            &security_attributes,
                            CREATE_NEW,
                            create_flags | file_attributes,
                            None,
                        )?;
                        if handle.is_invalid() {
                            return Err(FspError::from(GetLastError()));
                        }
                        handle
                    };

                    let context = Self::FileContext {
                        handle: ProjectedHandle::Real {
                            handle: Win32SafeHandle::from(handle),
                            portal: name.clone(),
                        },
                        dir_buffer: Default::default(),
                    };

                    self.get_file_info_internal(&context, file_info)?;
                    Ok(context)
                }
                _ => Err(ERROR_ACCESS_DENIED.into()),
            };
        } else {
            eprintln!("could not find parent {:?}", parent);
        }
        Err(ERROR_ACCESS_DENIED.into())
    }

    fn rename<P: AsRef<WCStr>>(
        &self,
        context: &Self::FileContext,
        _file_name: P,
        new_file_name: P,
        replace_if_exists: bool,
    ) -> winfsp::Result<()> {
        let new_file_name = OsString::from_wide(new_file_name.as_ref().as_slice());

        if let ProjectedHandle::Real { portal, .. } = &context.handle {
            // WinFSP treats filenames as case-insensitive and gives us an uppercase name.
            // We need to resolve it against the case-sensitive projections.
            let target_portal = self
                .projections
                .search_entry_case_insensitive(Path::new(new_file_name.as_os_str()));
            let source_portal = self.projections.get_entry(portal);
            eprintln!("rn: tp {:?}", target_portal);
            eprintln!("rn: sp {:?}", source_portal);

            if let (
                Some((target_portal @ ProjectionEntry::Portal { source, .. }, target_remainder)),
                Some(source_portal),
            ) = (target_portal, source_portal)
            {
                if target_portal != source_portal {
                    eprintln!("target portal is not real portal");
                    return Err(ERROR_ACCESS_DENIED.into());
                }

                if target_remainder.is_none() {
                    return Err(ERROR_INVALID_NAME.into());
                }

                if let Some(source_path) = &context.handle.get_real_path() {
                    let target_path =
                        join_remainder_windows_semantics(source, target_remainder.unwrap());

                    eprintln!("mv: source {:?}", source_path);
                    eprintln!("mv: target {:?}", target_path);

                    let source_path = HSTRING::from(source_path.as_os_str());
                    let target_path = HSTRING::from(target_path.as_os_str());

                    win32_try!(unsafe MoveFileExW(
                        PCWSTR::from_raw(source_path.as_ptr()),
                        PCWSTR::from_raw(target_path.as_ptr()),
                        if replace_if_exists {
                            MOVEFILE_REPLACE_EXISTING
                        } else {
                            MOVE_FILE_FLAGS::default()
                        }
                    ));

                    return Ok(());
                }
            }
        }
        Err(ERROR_ACCESS_DENIED.into())
    }

    fn flush(
        &self,
        context: Option<&Self::FileContext>,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> winfsp::Result<()> {
        if let Some(context) = context {
            require_handle!(&context.handle, handle => {
                 if *handle.deref() == HANDLE(0) {
                    // we do not flush the whole volume, so just return ok
                    return Ok(());
                }
                win32_try!(unsafe FlushFileBuffers(*handle.deref()));
            });

            // it's fine if we also refresh data for virtdirs
            self.get_file_info_internal(context, file_info)
        } else {
            Ok(())
        }
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
        require_handle!(&context.handle, handle => {
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
        } else {
            descriptor_size_needed = winfsp::util::get_process_security(
                security_descriptor,
                descriptor_len.map(|d| d as u32),
            )?
        });

        Ok(descriptor_size_needed as u64)
    }

    fn get_volume_info(&self, out_volume_info: &mut FSP_FSCTL_VOLUME_INFO) -> winfsp::Result<()> {
        let total_size = 1073741824u64;
        let free_size = 1073741824u64;

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
        let mut bytes_read = 0;
        require_handle!(&context.handle, handle => {
            let mut overlapped = OVERLAPPED {
                Anonymous: OVERLAPPED_0 {
                    Anonymous: OVERLAPPED_0_0 {
                        Offset: offset as u32,
                        OffsetHigh: (offset >> 32) as u32,
                    },
                },
                ..Default::default()
            };

            win32_try!(unsafe ReadFile(
                *handle.deref(),
                buffer.as_mut_ptr() as *mut _,
                buffer.len() as u32,
                &mut bytes_read,
                &mut overlapped,
            ));
        });

        Ok(IoResult {
            bytes_transferred: bytes_read,
            io_pending: false,
        })
    }

    fn read_directory<P: AsRef<WCStr>>(
        &self,
        context: &mut Self::FileContext,
        _pattern: Option<P>,
        mut marker: DirMarker,
        buffer: &mut [u8],
    ) -> winfsp::Result<u32> {
        if let Ok(mut buffer) = context.dir_buffer.acquire(marker.is_none(), None) {
            let mut dirinfo = DirInfo::<{ MAX_PATH as usize }>::new();
            require_handle!(&context.handle, handle => {
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
                let full_path = unsafe { U16String::from_ptr(&full_path as *const u16, length as usize) };
                eprintln!("rd: {:?}", full_path);
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
            } else path => {
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
            });
        }

        Ok(context.dir_buffer.read(marker, buffer))
    }

    fn write(
        &self,
        context: &Self::FileContext,
        mut buffer: &[u8],
        offset: u64,
        _write_to_eof: bool,
        constrained_io: bool,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> winfsp::Result<IoResult> {
        require_handle!(&context.handle, handle => {
            if constrained_io {
                let mut fsize = 0;
                win32_try!(unsafe GetFileSizeEx(*handle.deref(), &mut fsize));

                if offset >= fsize as u64 {
                    return Ok(IoResult {
                        bytes_transferred: 0,
                        io_pending: false,
                    });
                }

                if offset + buffer.len() as u64 > fsize as u64 {
                    buffer = &buffer[0..(fsize as u64 - offset) as usize]
                }
            }

            let mut overlapped = OVERLAPPED {
                Anonymous: OVERLAPPED_0 {
                    Anonymous: OVERLAPPED_0_0 {
                        Offset: offset as u32,
                        OffsetHigh: (offset >> 32) as u32,
                    },
                },
                ..Default::default()
            };

            let mut bytes_transferred = 0;
            win32_try!(unsafe WriteFile(
                *handle.deref(),
                buffer.as_ptr().cast(),
                buffer.len() as u32,
                &mut bytes_transferred,
                &mut overlapped,
            ));

            self.get_file_info_internal(context, file_info)?;
            Ok(IoResult {
                bytes_transferred,
                io_pending: false,
            })
        })
    }

    fn set_basic_info(
        &self,
        context: &Self::FileContext,
        file_attributes: u32,
        creation_time: u64,
        last_access_time: u64,
        last_write_time: u64,
        last_change_time: u64,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> winfsp::Result<()> {
        require_handle!(&context.handle, handle => {
            let basic_info = FILE_BASIC_INFO {
                FileAttributes: if file_attributes == INVALID_FILE_ATTRIBUTES {
                    0
                } else if file_attributes == 0 {
                    FILE_ATTRIBUTE_NORMAL.0
                } else {
                    file_attributes
                },
                CreationTime: creation_time as i64,
                LastAccessTime: last_access_time as i64,
                LastWriteTime: last_write_time as i64,
                ChangeTime: last_change_time as i64,
            };
            win32_try!(unsafe SetFileInformationByHandle(
                *handle.deref(),
                FileBasicInfo,
                (&basic_info as *const FILE_BASIC_INFO).cast(),
                std::mem::size_of::<FILE_BASIC_INFO>() as u32,
            ));
        });

        self.get_file_info_internal(context, file_info)
    }

    fn set_file_size(
        &self,
        context: &Self::FileContext,
        new_size: u64,
        set_allocation_size: bool,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> winfsp::Result<()> {
        require_handle!(&context.handle, handle => {
            if set_allocation_size {
                let allocation_info = FILE_ALLOCATION_INFO {
                    AllocationSize: new_size as i64,
                };

                win32_try!(unsafe SetFileInformationByHandle(
                    *handle.deref(),
                    FileAllocationInfo,
                    (&allocation_info as *const FILE_ALLOCATION_INFO).cast(),
                    std::mem::size_of::<FILE_ALLOCATION_INFO>() as u32
                ))
            } else {
                let eof_info = FILE_END_OF_FILE_INFO {
                    EndOfFile: new_size as i64,
                };

                win32_try!(unsafe SetFileInformationByHandle(
                    *handle.deref(),
                    FileEndOfFileInfo,
                    (&eof_info as *const FILE_END_OF_FILE_INFO).cast(),
                    std::mem::size_of::<FILE_END_OF_FILE_INFO>() as u32
                ))
            }
        });

        self.get_file_info_internal(context, file_info)
    }

    fn overwrite(
        &self,
        context: &Self::FileContext,
        file_attributes: FILE_FLAGS_AND_ATTRIBUTES,
        replace_file_attributes: bool,
        _allocation_size: u64,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> winfsp::Result<()> {
        // todo: preserve allocation size
        eprintln!("ow {:?}", context.handle.get_real_path());
        require_handle!(&context.handle, handle => {
            let mut attribute_tag_info = FILE_ATTRIBUTE_TAG_INFO::default();
            if replace_file_attributes {
                let basic_info = FILE_BASIC_INFO {
                    FileAttributes: if file_attributes == FILE_FLAGS_AND_ATTRIBUTES(0) {
                        FILE_ATTRIBUTE_NORMAL
                    } else {
                        file_attributes
                    }
                        .0,
                    ..Default::default()
                };

                win32_try!(unsafe SetFileInformationByHandle(
                    *handle.deref(),
                    FileBasicInfo,
                    (&basic_info as *const FILE_BASIC_INFO).cast(),
                    std::mem::size_of::<FILE_BASIC_INFO>() as u32,
                ));

                eprintln!("succ set replace")
            } else if file_attributes != FILE_FLAGS_AND_ATTRIBUTES(0) {
                let mut basic_info = FILE_BASIC_INFO::default();
                win32_try!(unsafe GetFileInformationByHandleEx(
                    *handle.deref(),
                    FileAllocationInfo,
                    (&mut attribute_tag_info as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
                    std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
                ));

                basic_info.FileAttributes = file_attributes.0 | attribute_tag_info.FileAttributes;
                if basic_info.FileAttributes.bitxor(file_attributes.0) != 0 {
                    win32_try!(unsafe SetFileInformationByHandle(
                        *handle.deref(),
                        FileBasicInfo,
                        (&basic_info as *const FILE_BASIC_INFO).cast(),
                        std::mem::size_of::<FILE_BASIC_INFO>() as u32,
                    ));
                }
                eprintln!("succ set not replace")
            }

            eprintln!("ow: try realloc");
            let alloc_info = FILE_ALLOCATION_INFO::default();
            win32_try!(unsafe SetFileInformationByHandle(
                *handle.deref(),
                FileAllocationInfo,
                (&alloc_info as *const FILE_ALLOCATION_INFO).cast(),
                std::mem::size_of::<FILE_ALLOCATION_INFO>() as u32,
            ));
            eprintln!("ow: reallocgood");
        });

        self.get_file_info_internal(context, file_info)
    }

    fn set_delete<P: AsRef<WCStr>>(
        &self,
        context: &Self::FileContext,
        file_name: P,
        delete_file: bool,
    ) -> winfsp::Result<()> {
        // only allow delete of real files.
        eprintln!("del: {:?}", file_name.as_ref());
        if let ProjectedHandle::Real { handle, .. } = &context.handle {
            let disposition_info = FILE_DISPOSITION_INFO_EX {
                Flags: if delete_file {
                    // need to remove from namespace immediately, otherwise the handle is still open.
                    FILE_DISPOSITION_FLAG_DELETE
                } else {
                    FILE_DISPOSITION_FLAG_DO_NOT_DELETE
                },
            };

            win32_try!(unsafe SetFileInformationByHandle(*handle.deref(),
                FileDispositionInfoEx, (&disposition_info as *const FILE_DISPOSITION_INFO_EX).cast(),
                std::mem::size_of::<FILE_DISPOSITION_INFO_EX>() as u32));
            Ok(())
        } else {
            Err(ERROR_ACCESS_DENIED.into())
        }
    }

    fn cleanup<P: AsRef<WCStr>>(
        &self,
        context: &mut Self::FileContext,
        _file_name: Option<P>,
        flags: u32,
    ) {
        if let ProjectedHandle::Real { handle, .. } = &mut context.handle {
            if flags & FspCleanupFlags::FspCleanupDelete as u32 != 0 {
                handle.invalidate();
            }
        }
    }
}
