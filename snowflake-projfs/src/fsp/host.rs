use crate::fsp::filesystem::ProjFsContext;
use snowflake_projfs_common::projections::{Projection, ProjectionEntry};
use time::OffsetDateTime;
use windows::core::HSTRING;
use windows::w;
use windows::Win32::Foundation::MAX_PATH;
use winfsp::filesystem::{FileSystemHost, FSP_FSCTL_VOLUME_PARAMS};

pub const ALLOCATION_UNIT: u16 = 4096;
pub const VOLUME_LABEL: &HSTRING = w!("Snowflake");
const FILESYSTEM_NAME: &HSTRING = w!("snowflake-projfs");

pub const FULLPATH_SIZE: usize = MAX_PATH as usize
    + (winfsp::filesystem::constants::FSP_FSCTL_TRANSACT_PATH_SIZEMAX as usize
        / std::mem::size_of::<u16>());

pub struct ProjFsHost {
    pub fs: FileSystemHost,
}

impl ProjFsHost {
    pub fn create(
        projections: Vec<ProjectionEntry>,
        volume_prefix: &str,
    ) -> anyhow::Result<ProjFsHost> {
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

        volume_params.Prefix[..std::cmp::min(prefix.len(), 192)]
            .copy_from_slice(&prefix.as_wide()[..std::cmp::min(prefix.len(), 192)]);

        volume_params.FileSystemName[..std::cmp::min(FILESYSTEM_NAME.len(), 192)].copy_from_slice(
            &FILESYSTEM_NAME.as_wide()[..std::cmp::min(FILESYSTEM_NAME.len(), 192)],
        );

        let context = ProjFsContext::new(Projection::from(projections.as_slice()));

        unsafe {
            Ok(ProjFsHost {
                fs: FileSystemHost::new(volume_params, context)?,
            })
        }
    }
}
