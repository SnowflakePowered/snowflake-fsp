use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::ErrorKind;
use std::mem::MaybeUninit;

use std::os::windows::fs::MetadataExt;
use std::path::Path;

use windows::core::{Result, HSTRING};
use windows::w;
use windows::Win32::Foundation::{GetLastError, HANDLE, MAX_PATH};
use windows::Win32::Security::{
    GetKernelObjectSecurity, DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FileAttributeTagInfo, GetDiskFreeSpaceExW, GetFileInformationByHandle,
    GetFileInformationByHandleEx, GetVolumePathNameW, BY_HANDLE_FILE_INFORMATION,
    FILE_ACCESS_FLAGS, FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_DELETE_ON_CLOSE, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_EXISTING, READ_CONTROL,
};
use windows::Win32::System::WindowsProgramming::FILE_DELETE_ON_CLOSE;

use winfsp::filesystem::{
    DirBuffer, FileSecurity, FileSystemContext, FileSystemHost, FSP_FSCTL_FILE_INFO,
    FSP_FSCTL_VOLUME_INFO, FSP_FSCTL_VOLUME_PARAMS,
};

use winfsp::util::SafeDropHandle;

const ALLOCATION_UNIT: u16 = 4096;
const VOLUME_LABEL: &HSTRING = w!("Snowflake");

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
                &HSTRING::from(dbg!(full_path.as_os_str())),
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
        let mut create_flags = FILE_FLAG_BACKUP_SEMANTICS;
        if (create_options & FILE_DELETE_ON_CLOSE) != 0 {
            create_flags |= FILE_FLAG_DELETE_ON_CLOSE
        }

        let handle = unsafe {
            CreateFileW(
                &HSTRING::from(full_path.as_os_str()),
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
            if !GetVolumePathNameW(&HSTRING::from(self.path.as_os_str()), &mut root[..]).as_bool() {
                return Err(GetLastError().into());
            }

            if !GetDiskFreeSpaceExW(
                &HSTRING::from_wide(&root),
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
