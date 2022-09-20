use std::ffi::{OsStr, OsString};
use std::fs;
use std::fs::OpenOptions;
use std::mem::MaybeUninit;

use std::ops::{BitXor, Deref, DerefMut};
use std::os::windows::ffi::OsStringExt;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::IntoRawHandle;
use std::path::Component::Prefix;
use std::path::{Path, PathBuf};

use time::OffsetDateTime;
use widestring::{U16Str, U16String};
use windows::core::{HSTRING, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    GetLastError, BOOLEAN, ERROR_ACCESS_DENIED, ERROR_DIRECTORY, ERROR_FILE_NOT_FOUND,
    ERROR_FILE_OFFLINE, ERROR_INVALID_NAME, HANDLE, MAX_PATH, NTSTATUS, STATUS_ACCESS_DENIED,
    STATUS_INVALID_PARAMETER, STATUS_MEDIA_WRITE_PROTECTED, STATUS_OBJECT_NAME_INVALID,
    STATUS_PENDING, STATUS_SHARING_VIOLATION, STATUS_SUCCESS, UNICODE_STRING,
};

use windows::Win32::Security::{
    GetKernelObjectSecurity, DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
};
use windows::Win32::Storage::FileSystem::{
    FileAllocationInfo, FileBasicInfo, FileDispositionInfo, FileDispositionInfoEx,
    FileEndOfFileInfo, FileRenameInfoEx, FlushFileBuffers, GetFileInformationByHandle,
    GetFileInformationByHandleEx, GetFileSizeEx, GetFinalPathNameByHandleW, MoveFileExW,
    NtCreateFile, ReadFile, SetFileInformationByHandle, WriteFile, BY_HANDLE_FILE_INFORMATION,
    CREATE_NEW, FILE_ACCESS_FLAGS, FILE_ALLOCATION_INFO, FILE_ALL_ACCESS, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_OFFLINE, FILE_ATTRIBUTE_READONLY,
    FILE_ATTRIBUTE_TAG_INFO, FILE_BASIC_INFO, FILE_CREATE, FILE_CREATION_DISPOSITION,
    FILE_DISPOSITION_INFO, FILE_END_OF_FILE_INFO, FILE_FLAGS_AND_ATTRIBUTES,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_DELETE_ON_CLOSE, FILE_FLAG_POSIX_SEMANTICS,
    FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_NAME, FILE_OPEN_IF, FILE_OVERWRITE,
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_SUPERSEDE,
    FILE_WRITE_DATA, INVALID_FILE_ATTRIBUTES, MOVEFILE_REPLACE_EXISTING, MOVE_FILE_FLAGS,
    OPEN_EXISTING, READ_CONTROL, SYNCHRONIZE,
};
use windows::Win32::System::WindowsProgramming::{
    RtlInitUnicodeString, FILE_DELETE_ON_CLOSE, FILE_DIRECTORY_FILE, FILE_DISPOSITION_FLAG_DELETE,
    FILE_DISPOSITION_FLAG_DO_NOT_DELETE, FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
    FILE_DISPOSITION_INFO_EX, FILE_MAXIMUM_DISPOSITION, FILE_NON_DIRECTORY_FILE,
    FILE_NO_EA_KNOWLEDGE, FILE_OPEN_FOR_BACKUP_INTENT, FILE_OPEN_REPARSE_POINT,
    FILE_SYNCHRONOUS_IO_NONALERT,
};
use windows::Win32::System::IO::{OVERLAPPED, OVERLAPPED_0, OVERLAPPED_0_0};
use windows_sys::Win32::System::WindowsProgramming::{NtClose, IO_STATUS_BLOCK};

use snowflake_projfs_common::path::{OwnedProjectedPath, ProjectedPath};
use snowflake_projfs_common::projections::{FileAccess, Projection, ProjectionEntry};
use winfsp::error::FspError;
use winfsp::filesystem::constants::FspCleanupFlags;
use winfsp::filesystem::{
    DirBuffer, DirInfo, DirMarker, FileSecurity, FileSystemContext, IoResult, FSP_FSCTL_FILE_INFO,
    FSP_FSCTL_VOLUME_INFO,
};
use winfsp::util::{NtSafeHandle, Win32SafeHandle};
use winfsp::WCStr;

use crate::fsp::host::{ALLOCATION_UNIT, FULLPATH_SIZE, VOLUME_LABEL};
use crate::fsp::lfs::{
    lfs_create_file, lfs_open_file, lfs_read_file, lfs_rename, lfs_unlink, lfs_write_file,
    LfsRenameSemantics,
};
use crate::fsp::nt;
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

#[derive(Debug)]
enum ProjectedHandle {
    /// A real file opened under a portal.
    Real {
        handle: NtSafeHandle,
        portal: OwnedProjectedPath,
        is_directory: bool,
    },
    /// A projected file or directory that points to a real filesystem entry.
    Projected(NtSafeHandle),
    /// A directory with a canonical path in the projection tree.
    Directory(OwnedProjectedPath),
}

fn join_remainder_windows_semantics(left: impl AsRef<OsStr>, right: impl AsRef<OsStr>) -> OsString {
    [left.as_ref(), right.as_ref()].join(OsStr::new("\\"))
}

fn join_remainder_nt_semantics(left: impl AsRef<OsStr>, right: impl AsRef<OsStr>) -> OsString {
    assert!(matches!(
        Path::new(left.as_ref()).components().next(),
        Some(Prefix(_))
    ));
    [OsStr::new(r"\??\"), left.as_ref(), right.as_ref()].join(OsStr::new("\\"))
}

fn dos_path_to_nt_path(path: impl AsRef<OsStr>) -> OsString {
    assert!(matches!(
        Path::new(path.as_ref()).components().next(),
        Some(Prefix(_))
    ));
    [OsStr::new(r"\??\"), path.as_ref()].join(OsStr::new(""))
}

#[repr(C)]
#[derive(Debug)]
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
        opt.share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0);

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

    fn open_handle_internal<P: AsRef<OsStr>>(
        file_path: P,
        is_directory: bool,
        create_options: u32,
        granted_access: FILE_ACCESS_FLAGS,
        request_access: FileAccess,
    ) -> winfsp::Result<NtSafeHandle> {
        // todo: forbid access_delete
        let backup_access = granted_access.0;
        let mut maximum_access = if is_directory {
            granted_access
        } else {
            // MAXIMUM_ALLOWED
            FILE_ACCESS_FLAGS(0x02000000u32)
        };

        let mut create_options =
            create_options & (FILE_DIRECTORY_FILE | FILE_NON_DIRECTORY_FILE | FILE_NO_EA_KNOWLEDGE);

        // WORKAROUND:
        // WOW64 appears to have a bug in some versions of the OS (seen on Win10 1909 and
        // Server 2012 R2), where NtQueryDirectoryFile may produce garbage if called on a
        // directory that has been opened without FILE_SYNCHRONOUS_IO_NONALERT.
        //
        // Garbage:
        // after a STATUS_PENDING has been waited, Iosb.Information reports bytes transferred
        // but the buffer does not get filled

        // Always open directories in a synchronous manner.

        if is_directory {
            maximum_access |= SYNCHRONIZE;
            create_options |= FILE_SYNCHRONOUS_IO_NONALERT
        }

        // todo: use ntsemantics
        let file_path = dos_path_to_nt_path(file_path);
        let file_path = HSTRING::from(&file_path);

        let result = lfs_open_file(
            PCWSTR(file_path.as_ptr()),
            maximum_access.0,
            FILE_OPEN_FOR_BACKUP_INTENT | FILE_OPEN_REPARSE_POINT | create_options,
        );

        eprintln!("op: {:?}: {:?}", file_path, result);

        match result {
            Ok(handle) => Ok(handle),
            Err(FspError::NTSTATUS(
                STATUS_ACCESS_DENIED
                | STATUS_MEDIA_WRITE_PROTECTED
                | STATUS_SHARING_VIOLATION
                | STATUS_INVALID_PARAMETER,
            )) if maximum_access.0 == 0x02000000u32 => lfs_open_file(
                PCWSTR(file_path.as_ptr()),
                backup_access,
                FILE_OPEN_FOR_BACKUP_INTENT | FILE_OPEN_REPARSE_POINT | create_options,
            ),
            Err(e) => Err(e),
        }
    }

    fn create_file_internal<P: AsRef<OsStr>>(
        file_path: P,
        create_options: u32,
        granted_access: FILE_ACCESS_FLAGS,
        file_attributes: FILE_FLAGS_AND_ATTRIBUTES,
        security_descriptor: PSECURITY_DESCRIPTOR,
        allocation_size: i64,
        mut reparse_buffer: Option<&mut [u8]>,
        request_access: FileAccess,
    ) -> winfsp::Result<NtSafeHandle> {
        // todo: forbid access_delete
        let is_directory = create_options & FILE_DIRECTORY_FILE != 0;

        let mut maximum_access = if is_directory {
            granted_access
        } else {
            // MAXIMUM_ALLOWED
            FILE_ACCESS_FLAGS(0x02000000u32)
        };

        let mut create_options =
            create_options & (FILE_DIRECTORY_FILE | FILE_NON_DIRECTORY_FILE | FILE_NO_EA_KNOWLEDGE);

        // WORKAROUND:
        // WOW64 appears to have a bug in some versions of the OS (seen on Win10 1909 and
        // Server 2012 R2), where NtQueryDirectoryFile may produce garbage if called on a
        // directory that has been opened without FILE_SYNCHRONOUS_IO_NONALERT.
        //
        // Garbage:
        // after a STATUS_PENDING has been waited, Iosb.Information reports bytes transferred
        // but the buffer does not get filled

        // Always open directories in a synchronous manner.

        if is_directory {
            maximum_access |= SYNCHRONIZE;
            create_options |= FILE_SYNCHRONOUS_IO_NONALERT
        }

        // todo: use ntsemantics
        let file_path = dos_path_to_nt_path(file_path);
        let file_path = HSTRING::from(&file_path);

        let mut allocation_size = if allocation_size != 0 {
            Some(allocation_size)
        } else {
            None
        };

        let file_attributes = if file_attributes.0 == 0 {
            FILE_ATTRIBUTE_NORMAL
        } else {
            file_attributes
        };

        let result = lfs_create_file(
            PCWSTR(file_path.as_ptr()),
            maximum_access.0,
            security_descriptor,
            allocation_size.as_mut(),
            file_attributes.0,
            FILE_CREATE.0,
            FILE_OPEN_FOR_BACKUP_INTENT | FILE_OPEN_REPARSE_POINT | create_options,
            &mut reparse_buffer,
            None,
        );

        eprintln!("cr: {:?}: {:?}", file_path, result);

        match result {
            Ok(handle) => Ok(handle),
            Err(FspError::NTSTATUS(STATUS_INVALID_PARAMETER))
                if maximum_access.0 == 0x02000000u32 =>
            {
                lfs_create_file(
                    PCWSTR(file_path.as_ptr()),
                    maximum_access.0,
                    security_descriptor,
                    allocation_size.as_mut(),
                    file_attributes.0,
                    FILE_CREATE.0,
                    FILE_OPEN_FOR_BACKUP_INTENT | FILE_OPEN_REPARSE_POINT | create_options,
                    &mut reparse_buffer,
                    None,
                )
            }
            Err(e) => Err(e),
        }
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

        if file_name == "\\" {
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
        if file_name == "\\" {
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

                    let is_directory = unsafe {
                        self.with_operation_response(|ctx| {
                            FILE_ATTRIBUTE_DIRECTORY.0
                                & ctx.Rsp.Create.Opened.FileInfo.FileAttributes
                                != 0
                        })
                    }
                    .unwrap_or(false);

                    let handle = Self::open_handle_internal(
                        source.as_os_str(),
                        is_directory,
                        create_options,
                        granted_access,
                        *access,
                    )?;
                    let context = Self::FileContext {
                        handle: ProjectedHandle::Projected(handle),
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
                    // todo: check with protectlist.

                    let is_directory = unsafe {
                        self.with_operation_response(|ctx| {
                            FILE_ATTRIBUTE_DIRECTORY.0
                                & ctx.Rsp.Create.Opened.FileInfo.FileAttributes
                                != 0
                        })
                    }
                    .unwrap_or(false);

                    let handle = Self::open_handle_internal(
                        file_path.as_os_str(),
                        is_directory,
                        create_options,
                        granted_access,
                        *access,
                    )?;
                    let context = Self::FileContext {
                        handle: ProjectedHandle::Real {
                            handle,
                            portal: name.clone(),
                            is_directory,
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

    fn close(&self, context: Self::FileContext) {
        eprintln!("cl: {:?}", context);
        drop(context)
    }

    fn create<P: AsRef<WCStr>>(
        &self,
        file_name: P,
        create_options: u32,
        granted_access: FILE_ACCESS_FLAGS,
        file_attributes: FILE_FLAGS_AND_ATTRIBUTES,
        security_descriptor: PSECURITY_DESCRIPTOR,
        allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        _extra_buffer_is_reparse_point: bool,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> winfsp::Result<Self::FileContext> {
        let file_name = OsString::from_wide(file_name.as_ref().as_slice());
        let new_path = Path::new(file_name.as_os_str());

        let parent = new_path.parent().ok_or(STATUS_OBJECT_NAME_INVALID)?;
        let new_filename = new_path.file_name().ok_or(STATUS_OBJECT_NAME_INVALID)?;

        // todo: fix semantics when replacing a File projection.
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

                    let handle = Self::create_file_internal(
                        target_path,
                        create_options,
                        granted_access,
                        file_attributes,
                        security_descriptor,
                        allocation_size as i64,
                        None,
                        FileAccess::ReadWrite,
                    )?;

                    let context = Self::FileContext {
                        handle: ProjectedHandle::Real {
                            handle,
                            portal: name.clone(),
                            is_directory: create_options & FILE_DIRECTORY_FILE != 0,
                        },
                        dir_buffer: Default::default(),
                    };

                    self.get_file_info_internal(&context, file_info)?;
                    Ok(context)
                }
                entry => {
                    // todo: allow 'create' under certain circumstances
                    // create error: Directory { name: OwnedProjectedPath("/") } (original: "\\wiiu"), opts: 2200021, access: FILE_ACCESS_FLAGS(1048577), flags: FILE_FLAGS_AND_ATTRIBUTES(16)
                    eprintln!("create error: {:?} (original: {:?}), opts: {:x}, access: {:?}, flags: {:?}", entry, file_name, create_options, granted_access, file_attributes);
                    Err(ERROR_ACCESS_DENIED.into())
                }
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
        if let ProjectedHandle::Real {
            portal,
            is_directory,
            handle,
        } = &context.handle
        {
            let new_file_name = OsString::from_wide(new_file_name.as_ref().as_slice());

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
                        join_remainder_nt_semantics(source, target_remainder.unwrap());
                    // todo: if (FSP_FSCTL_TRANSACT_PATH_SIZEMAX < FileRenInfo.V.FileNameLength)

                    let replace_mode = if replace_if_exists
                        && (!*is_directory
                            || unsafe {
                                self.with_operation_request(|f| {
                                (2 /*POSIX_SEMANTICS*/ & f.Req.SetInformation.Info.RenameEx.Flags)
                                    != 0
                            })
                            }
                            .unwrap_or(false))
                    {
                        LfsRenameSemantics::PosixReplaceSemantics
                    } else if replace_if_exists {
                        LfsRenameSemantics::NtReplaceSemantics
                    } else {
                        LfsRenameSemantics::DoNotReplace
                    };

                    let nt_target_path = HSTRING::from(target_path.as_os_str());

                    let result = lfs_rename(*handle.deref(), nt_target_path, replace_mode);
                    eprintln!("mv: {:?}: {:?}", target_path.as_os_str(), result);
                    return if result.is_ok() {
                        Ok(())
                    } else {
                        Err(result.into())
                    };
                    //
                    // eprintln!("mv: source {:?}", source_path);
                    // eprintln!("mv: target {:?}", target_path);
                    //
                    // let source_path = HSTRING::from(source_path.as_os_str());
                    // let target_path = HSTRING::from(target_path.as_os_str());
                    //
                    // win32_try!(unsafe MoveFileExW(
                    //     PCWSTR::from_raw(source_path.as_ptr()),
                    //     PCWSTR::from_raw(target_path.as_ptr()),
                    //     if replace_if_exists {
                    //         MOVEFILE_REPLACE_EXISTING
                    //     } else {
                    //         MOVE_FILE_FLAGS::default()
                    //     }
                    // ));

                    // return Ok(());
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
        if context.is_none() {
            return Ok(());
        }
        let context = context.unwrap();
        require_handle!(&context.handle, handle => {
            let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::uninit();
            let result = unsafe {
                nt::NtFlushBuffersFile(handle.deref().0, iosb.as_mut_ptr())
            };
            if result != STATUS_SUCCESS.0 {
                return Err(NTSTATUS(result).into())
            }
        });

        // it's fine if we also refresh data for virtdirs
        self.get_file_info_internal(context, file_info)
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
            let result = lfs_read_file(*handle.deref(), buffer, offset, &mut bytes_read);
            if result == STATUS_SUCCESS {
                  return Ok(IoResult {
                    bytes_transferred: bytes_read as u32,
                    io_pending: false,
                })
            } else if result == STATUS_PENDING {
                return Ok(IoResult {
                    bytes_transferred: bytes_read as u32,
                    io_pending: true,
                })
            } else {
                eprintln!("read err: {:x}", result.0);
                return Err(result.into())
            }
        });
    }

    fn read_directory<P: AsRef<WCStr>>(
        &self,
        context: &mut Self::FileContext,
        _pattern: Option<P>,
        mut marker: DirMarker,
        buffer: &mut [u8],
    ) -> winfsp::Result<u32> {
        // todo: fix double slash semantics
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
                // eprintln!("rd: {:?}", full_path);
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

            let mut bytes_read = 0;

            let result = lfs_write_file(*handle.deref(), buffer, offset, &mut bytes_read);
            if result == STATUS_SUCCESS {
                self.get_file_info_internal(context, file_info)?;
                return Ok(IoResult {
                    bytes_transferred: bytes_read as u32,
                    io_pending: false,
                });
            } else if result == STATUS_PENDING {
                self.get_file_info_internal(context, file_info)?;
                return Ok(IoResult {
                    bytes_transferred: bytes_read as u32,
                    io_pending: true,
                });
            } else {
                eprintln!("write err: {:x}", result.0);
                return Err(result.into());
            }
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
        // require_handle!(&context.handle, handle => {
        //     let basic_info = FILE_BASIC_INFO {
        //         FileAttributes: if file_attributes == INVALID_FILE_ATTRIBUTES {
        //             0
        //         } else if file_attributes == 0 {
        //             FILE_ATTRIBUTE_NORMAL.0
        //         } else {
        //             file_attributes
        //         },
        //         CreationTime: creation_time as i64,
        //         LastAccessTime: last_access_time as i64,
        //         LastWriteTime: last_write_time as i64,
        //         ChangeTime: last_change_time as i64,
        //     };
        //     win32_try!(unsafe SetFileInformationByHandle(
        //         *handle.deref(),
        //         FileBasicInfo,
        //         (&basic_info as *const FILE_BASIC_INFO).cast(),
        //         std::mem::size_of::<FILE_BASIC_INFO>() as u32,
        //     ));
        // });

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
        allocation_size: u64,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> winfsp::Result<()> {
        // todo: preserve allocation size
        // eprintln!("ow {:?}", context.handle.get_real_path());
        require_handle!(&context.handle, handle => {

            let mut allocation_size = if allocation_size != 0 {
                Some(allocation_size as i64)
            } else {
                None
            };


            let new_handle = lfs_create_file(windows::w!(""), if replace_file_attributes {
                    0x00010000u32
                } else {
                    FILE_WRITE_DATA.0
                }, PSECURITY_DESCRIPTOR::default(), allocation_size.as_mut(), (if replace_file_attributes {
                    if file_attributes.0 == 0 {
                        FILE_ATTRIBUTE_NORMAL
                    } else {
                        file_attributes
                    }
                } else {
                    file_attributes
                }).0, (if replace_file_attributes {
                    FILE_SUPERSEDE
                } else {
                    FILE_OVERWRITE
                }).0, FILE_OPEN_FOR_BACKUP_INTENT | FILE_OPEN_REPARSE_POINT, &mut None, Some(**handle))?;

            unsafe {
                NtClose(new_handle.0);
            }
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
        if let ProjectedHandle::Real { handle, .. } = &context.handle {
            let result = lfs_unlink(*handle.deref(), delete_file);
            if result.is_ok() {
                Ok(())
            } else {
                Err(result.into())
            }
        } else {
            Err(STATUS_ACCESS_DENIED.into())
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
                lfs_unlink(*handle.deref_mut(), true);
                handle.invalidate();
            }
            // todo: Flags & FspCleanupSetAllocationSize
        }
    }
}
