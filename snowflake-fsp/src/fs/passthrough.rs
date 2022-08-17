use std::fs;
use std::io::ErrorKind;
use std::mem::MaybeUninit;

use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};

use windows::core::{Result, HSTRING};
use windows::w;
use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, MAX_PATH};
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

use winfsp_sys::{
    FspFileSystemDeleteDirectoryBuffer, FSP_FSCTL_FILE_INFO, FSP_FSCTL_VOLUME_INFO,
    FSP_FSCTL_VOLUME_PARAMS, PVOID,
};

use crate::fsp::{DropCloseHandle, FileSystemContext, FspFileSystem};

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

    fn get_security_by_name<P: AsRef<Path>>(
        &self,
        file_name: P,
        security_descriptor: PSECURITY_DESCRIPTOR,
        descriptor_len: Option<u32>,
    ) -> Result<(u32, u64)> {
        let full_path = &self.path.join(file_name);
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

        let handle = DropCloseHandle::from(handle);

        let mut attribute_tag_info: MaybeUninit<FILE_ATTRIBUTE_TAG_INFO> = MaybeUninit::uninit();
        let mut len_needed: u32 = 0;

        unsafe {
            if !GetFileInformationByHandleEx(
                handle.clone(),
                FileAttributeTagInfo,
                attribute_tag_info.as_mut_ptr() as *mut _,
                std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
            )
            .as_bool()
            {
                return Err(GetLastError().into());
            }
        }

        if let Some(descriptor_len) = descriptor_len {
            unsafe {
                if !GetKernelObjectSecurity(
                    handle,
                    (OWNER_SECURITY_INFORMATION
                        | GROUP_SECURITY_INFORMATION
                        | DACL_SECURITY_INFORMATION)
                        .0,
                    security_descriptor,
                    descriptor_len,
                    &mut len_needed,
                )
                .as_bool()
                {
                    return Err(GetLastError().into());
                }
            }
        }

        let file_attributes = unsafe { attribute_tag_info.assume_init() }.FileAttributes;

        Ok((file_attributes, len_needed as u64))
    }

    fn open<P: AsRef<Path>>(
        &self,
        file_name: P,
        create_options: u32,
        granted_access: FILE_ACCESS_FLAGS,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> Result<Self::FileContext> {
        let full_path = &self.path.join(file_name);
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
            handle,
            dir_buffer: std::ptr::null_mut(),
        })
    }

    fn close(&self, mut context: Self::FileContext) {
        unsafe {
            CloseHandle(context.handle);
            FspFileSystemDeleteDirectoryBuffer(&mut context.dir_buffer)
        }
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
        out_volume_info.VolumeLabel[0..4].copy_from_slice(w!("SFLK").as_wide());
        out_volume_info.VolumeLabelLength = 4;
        dbg!("get_volume_info", total_size, free_size);
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
            path: canonical_path,
        };

        unsafe {
            Ok(Box::new(Ptfs {
                fs: FspFileSystem::new(volume_params, context)?,
            }))
        }
    }
}
