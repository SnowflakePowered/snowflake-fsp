use crate::fsp::FspService;
use crate::Args;
use windows::core::{HSTRING, PWSTR};
use windows::Win32::Foundation::{NTSTATUS, STATUS_NOT_IMPLEMENTED, STATUS_SUCCESS};
use crate::fs::Ptfs;

#[inline]
pub fn svc_start(mut service: FspService<Ptfs>, args: Args) -> anyhow::Result<()> {
    let mut ptfs = Ptfs::create(&args.directory,
                            &args.volume_prefix.unwrap_or(String::from("")))?;
    ptfs.fs.mount(PWSTR::from_raw(HSTRING::from(args.mountpoint.as_os_str()).as_ptr().cast_mut()))?;
    ptfs.fs.start()?;

    service.set_context(ptfs);
    Ok(())
}

#[inline]
pub fn svc_stop(mut service: FspService<Ptfs>) -> NTSTATUS {
    let context = service.get_context_mut();
    context.and_then(|f| Some(f.fs.stop()))
        .map_or_else(|| STATUS_NOT_IMPLEMENTED, |_| STATUS_SUCCESS)
}
