use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::ErrorKind;
use std::mem::MaybeUninit;

use std::os::windows::fs::MetadataExt;
use std::path::Path;
use widestring::{u16cstr, U16CStr, U16CString, U16String};

use windows::core::{Result, HSTRING, PCWSTR};
use windows::w;
use windows::Win32::Foundation::{GetLastError, HANDLE, MAX_PATH, STATUS_OBJECT_NAME_INVALID};
use windows::Win32::Security::{
    GetKernelObjectSecurity, DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FileAttributeTagInfo, FindClose, FindFirstFileW, FindNextFileW,
    GetDiskFreeSpaceExW, GetFileInformationByHandle, GetFileInformationByHandleEx,
    GetFinalPathNameByHandleW, GetVolumePathNameW, BY_HANDLE_FILE_INFORMATION, FILE_ACCESS_FLAGS,
    FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_DELETE_ON_CLOSE, FILE_NAME,
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    READ_CONTROL, WIN32_FIND_DATAW,
};
use windows::Win32::System::WindowsProgramming::FILE_DELETE_ON_CLOSE;

use winfsp::filesystem::{
    DirBuffer, DirInfo, FileSecurity, FileSystemContext, FileSystemHost, FSP_FSCTL_FILE_INFO,
    FSP_FSCTL_VOLUME_INFO, FSP_FSCTL_VOLUME_PARAMS,
};

use winfsp::util::SafeDropHandle;

const ALLOCATION_UNIT: u16 = 4096;
const VOLUME_LABEL: &HSTRING = w!("Snowflake");
const FULLPATH_SIZE: usize = MAX_PATH as usize
    + (winfsp::filesystem::constants::FSP_FSCTL_TRANSACT_PATH_SIZEMAX as usize
        / std::mem::size_of::<u16>());

pub struct Ptfs {
    pub fs: FileSystemHost,
}

#[repr(C)]
pub struct PtfsContext {
    path: OsString,
}

#[repr(C)]
pub struct PtfsFileContext {
    handle: SafeDropHandle,
    dir_buffer: DirBuffer,
}

#[inline(always)]
const fn quadpart(hi: u32, lo: u32) -> u64 {
    (hi as u64) << 32 | lo as u64
}

impl PtfsContext {
    fn get_file_info_internal(
        &self,
        file_handle: HANDLE,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> Result<()> {
        let mut os_file_info: BY_HANDLE_FILE_INFORMATION = Default::default();
        unsafe {
            if !GetFileInformationByHandle(file_handle, &mut os_file_info).as_bool() {
                return Err(GetLastError().into());
            }
        }

        file_info.FileAttributes = os_file_info.dwFileAttributes;

        // todo: reparse
        file_info.ReparseTag = 0;
        file_info.IndexNumber = 0;
        file_info.HardLinks = 0;

        file_info.FileSize = quadpart(os_file_info.nFileSizeHigh, os_file_info.nFileSizeLow);
        file_info.AllocationSize = (file_info.FileSize + ALLOCATION_UNIT as u64 - 1)
            / ALLOCATION_UNIT as u64
            * ALLOCATION_UNIT as u64;
        file_info.CreationTime = quadpart(
            os_file_info.ftCreationTime.dwHighDateTime,
            os_file_info.ftCreationTime.dwLowDateTime,
        );
        file_info.LastAccessTime = quadpart(
            os_file_info.ftLastAccessTime.dwHighDateTime,
            os_file_info.ftLastAccessTime.dwLowDateTime,
        );
        file_info.LastWriteTime = quadpart(
            os_file_info.ftLastWriteTime.dwHighDateTime,
            os_file_info.ftLastWriteTime.dwLowDateTime,
        );
        file_info.ChangeTime = file_info.LastWriteTime;
        Ok(())
    }
}

impl FileSystemContext for PtfsContext {
    type FileContext = PtfsFileContext;

    fn get_security_by_name<P: AsRef<OsStr>>(
        &self,
        file_name: P,
        security_descriptor: PSECURITY_DESCRIPTOR,
        security_descriptor_len: Option<u64>,
    ) -> Result<FileSecurity> {
        let full_path = [self.path.as_os_str(), file_name.as_ref()].join(OsStr::new(""));
        let handle = unsafe {
            CreateFileW(
                &HSTRING::from(full_path.as_os_str()),
                FILE_READ_ATTRIBUTES | READ_CONTROL,
                Default::default(),
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                None,
            )
        }?;

        let mut attribute_tag_info: MaybeUninit<FILE_ATTRIBUTE_TAG_INFO> = MaybeUninit::uninit();
        let mut len_needed: u32 = 0;

        let handle = SafeDropHandle::from(handle);

        unsafe {
            if !GetFileInformationByHandleEx(
                *handle,
                FileAttributeTagInfo,
                attribute_tag_info.as_mut_ptr() as *mut _,
                std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
            )
            .as_bool()
            {
                return Err(GetLastError().into());
            }
        }

        if let Some(descriptor_len) = security_descriptor_len {
            unsafe {
                if !GetKernelObjectSecurity(
                    *handle,
                    (OWNER_SECURITY_INFORMATION
                        | GROUP_SECURITY_INFORMATION
                        | DACL_SECURITY_INFORMATION)
                        .0,
                    security_descriptor,
                    descriptor_len as u32,
                    &mut len_needed,
                )
                .as_bool()
                {
                    return Err(GetLastError().into());
                }
            }
        }

        Ok(FileSecurity {
            attributes: unsafe { attribute_tag_info.assume_init() }.FileAttributes,
            reparse: false,
            sz_security_descriptor: len_needed as u64,
        })
    }

    fn open<P: AsRef<OsStr>>(
        &self,
        file_name: P,
        create_options: u32,
        granted_access: FILE_ACCESS_FLAGS,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> Result<Self::FileContext> {
        let full_path = [self.path.as_os_str(), file_name.as_ref()].join(OsStr::new(""));
        if full_path.len() > FULLPATH_SIZE {
            return Err(STATUS_OBJECT_NAME_INVALID.into());
        }

        let full_path = U16CString::from_os_str_truncate(full_path);
        let mut create_flags = FILE_FLAG_BACKUP_SEMANTICS;
        if (create_options & FILE_DELETE_ON_CLOSE) != 0 {
            create_flags |= FILE_FLAG_DELETE_ON_CLOSE
        }

        let handle = unsafe {
            CreateFileW(
                PCWSTR(full_path.as_ptr()),
                granted_access,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                create_flags,
                None,
            )
        }?;

        self.get_file_info_internal(handle, file_info)?;
        Ok(Self::FileContext {
            handle: SafeDropHandle::from(handle),
            dir_buffer: DirBuffer::new(),
        })
    }

    fn close(&self, context: Self::FileContext) {
        drop(context)
    }

    fn get_volume_info(&self, out_volume_info: &mut FSP_FSCTL_VOLUME_INFO) -> Result<()> {
        dbg!("get_volume_info");
        let mut root = [0u16; MAX_PATH as usize];
        let mut total_size = 0u64;
        let mut free_size = 0u64;
        unsafe {
            let fname = U16CString::from_os_str_truncate(self.path.as_os_str());
            if !GetVolumePathNameW(PCWSTR(fname.as_ptr()), &mut root[..]).as_bool() {
                return Err(GetLastError().into());
            }

            if !GetDiskFreeSpaceExW(
                PCWSTR(U16CStr::from_slice_truncate(&root).unwrap().as_ptr()),
                std::ptr::null_mut(),
                &mut total_size,
                &mut free_size,
            )
            .as_bool()
            {
                return Err(GetLastError().into());
            }
        }

        out_volume_info.TotalSize = total_size;
        out_volume_info.FreeSize = free_size;
        out_volume_info.VolumeLabel[0..VOLUME_LABEL.len()].copy_from_slice(VOLUME_LABEL.as_wide());
        out_volume_info.VolumeLabelLength =
            (VOLUME_LABEL.len() * std::mem::size_of::<u16>()) as u16;
        Ok(())
    }

    fn get_file_info(
        &self,
        context: &Self::FileContext,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> Result<()> {
        self.get_file_info_internal(*context.handle, file_info)
    }

    fn get_security(
        &self,
        context: &Self::FileContext,
        security_descriptor: PSECURITY_DESCRIPTOR,
        descriptor_len: Option<u64>,
    ) -> Result<u64> {
        let mut descriptor_size_needed = 0;
        unsafe {
            if !GetKernelObjectSecurity(
                *context.handle,
                (OWNER_SECURITY_INFORMATION
                    | GROUP_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION)
                    .0,
                security_descriptor,
                descriptor_len.unwrap_or(0) as u32,
                &mut descriptor_size_needed,
            )
            .as_bool()
            {
                return Err(GetLastError().into());
            }
        }
        Ok(descriptor_size_needed as u64)
    }

    fn read_directory<P: Into<PCWSTR>>(
        &self,
        context: &mut Self::FileContext,
        pattern: Option<P>,
        marker: *const u16,
        buffer: &mut [u8],
    ) -> Result<u32> {
        dbg!("read_dir");
        if let Ok(mut lock) = context.dir_buffer.acquire(marker.is_null(), None) {
            let mut dirinfo = DirInfo::<{ MAX_PATH as usize }>::new();
            let mut full_path = [0; FULLPATH_SIZE];

            let pattern = pattern.map_or(PCWSTR::from(w!("*")), P::into);
            let pattern = unsafe { U16CStr::from_ptr_str(pattern.0) };

            let mut length = unsafe {
                GetFinalPathNameByHandleW(
                    *context.handle,
                    &mut full_path[0..FULLPATH_SIZE - 1],
                    FILE_NAME::default(),
                )
            };

            if length == 0 {
                return Err(unsafe { GetLastError() }.into());
            } else if length as usize + 1 + pattern.len() >= FULLPATH_SIZE {
                return Err(STATUS_OBJECT_NAME_INVALID.into());
            }

            // append '\'
            if full_path[length as usize - 1] != '\\' as u16 {
                full_path[length as usize..][0..2]
                    .copy_from_slice(u16cstr!("\\").as_slice_with_nul());
                length += 1;
            }

            let mut full_path =
                unsafe { U16String::from_ptr(&full_path as *const u16, length as usize) };

            full_path.push(pattern);

            let mut find_data = MaybeUninit::<WIN32_FIND_DATAW>::uninit();
            let full_path = U16CString::from_ustr_truncate(full_path);
            if let Ok(find_handle) = unsafe { FindFirstFileW(PCWSTR::from_raw(full_path.as_ptr()), find_data.as_mut_ptr()) } && !find_handle.is_invalid() {
                let mut find_data = unsafe { find_data.assume_init() };
                loop {
                    dirinfo.reset();
                    let finfo = dirinfo.file_info_mut();
                    finfo.FileAttributes = find_data.dwFileAttributes;
                    finfo.ReparseTag = 0;
                    finfo.FileSize = quadpart(find_data.nFileSizeHigh, find_data.nFileSizeLow);
                    finfo.AllocationSize = ((finfo.FileSize + ALLOCATION_UNIT as u64 - 1) / ALLOCATION_UNIT as u64) * ALLOCATION_UNIT as u64;
                    finfo.CreationTime = quadpart(find_data.ftCreationTime.dwHighDateTime, find_data.ftCreationTime.dwLowDateTime);
                    finfo.LastAccessTime = quadpart(find_data.ftLastAccessTime.dwHighDateTime, find_data.ftLastAccessTime.dwLowDateTime);
                    finfo.LastWriteTime = quadpart(find_data.ftLastWriteTime.dwHighDateTime, find_data.ftLastWriteTime.dwLowDateTime);
                    finfo.ChangeTime = finfo.LastWriteTime;
                    finfo.HardLinks = 0;
                    finfo.IndexNumber = 0;
                    // safety: if this is null then something went very wrong with windows
                    let file_name = unsafe {
                        U16CStr::from_slice_truncate(&find_data.cFileName)
                            .unwrap()
                    };
                    dirinfo.set_file_name(file_name.as_slice());
                    if let Err(e) = lock.fill(&mut dirinfo) {
                        unsafe {
                            FindClose(find_handle);
                        }
                        drop(lock);
                        return Err(e);
                    }
                    if unsafe {
                        !FindNextFileW(HANDLE(find_handle.0), &mut find_data).as_bool()
                    } {
                        break;
                    }
                }
                unsafe {
                    FindClose(find_handle);
                }
                drop(lock);
            }
        }

        Ok(context.dir_buffer.read(marker, buffer))
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

        dbg!(HSTRING::from_wide(&volume_params.FileSystemName), fs_name);
        dbg!(HSTRING::from_wide(&volume_params.Prefix), prefix);

        let context = PtfsContext {
            path: canonical_path.into_os_string(),
        };

        unsafe {
            Ok(Box::new(Ptfs {
                fs: FileSystemHost::new(volume_params, context)?,
            }))
        }
    }
}
