use crate::fsp::host::ProjFsHost;
use crate::Args;
use snowflake_projfs_common::projections::parse_projection;

#[inline]
pub fn svc_start(args: Args) -> anyhow::Result<ProjFsHost> {
    let projection = "
f(/hello.world|C:\\test.txt|r);
f(/extant.file|C:\\test\\test.txt|r);
f(/extant.file.writable|C:\\test\\test.txt|rw);
d(/directory|);
d(/dir2|);
d(/dir2/dir2nested|);
d(/あ|);
p(/portal|C:\\test|rw|protected:file:|);
p(/dead_portal|C:\\nope|rw|protected:file:|);
f(/dir2/d0|C:\\test\\test.txt|r);
f(/dir2/d1|C:\\test.txt|r);
p(/ps3|E:\\Emulators\\RPCS3|rw|:|);
        ";

    let parsed = parse_projection(projection.as_bytes()).unwrap();
    eprintln!("{:?}", parsed);
    let mut projfs = ProjFsHost::create(parsed, &args.volume_prefix.unwrap_or(String::from("")))?;

    projfs.fs.mount(args.mountpoint.as_os_str())?;
    projfs.fs.start()?;
    Ok(projfs)
}

#[inline]
pub fn svc_stop(fs: Option<&mut ProjFsHost>) {
    if let Some(f) = fs {
        f.fs.stop();
    }
}
