use crate::fsp::fs::SnowflakeProjFs;
use crate::Args;
use snowflake_projfs_common::projections::parse_projection;

#[inline]
pub fn svc_start(args: Args) -> anyhow::Result<SnowflakeProjFs> {
    let projection = "
f(/hello.world|C:\\test.txt|r);
d(/directory|);
d(/dir2|);
d(/あ|);
p(/portal|C:\\test|rw|protected:file:|);
f(/dir2/d0|C:\\test.txt|r);
        ";

    let parsed = parse_projection(projection.as_bytes()).unwrap();
    eprintln!("{:?}", parsed);
    let mut projfs =
        SnowflakeProjFs::create(parsed, &args.volume_prefix.unwrap_or(String::from("")))?;

    projfs.fs.mount(args.mountpoint.as_os_str())?;
    projfs.fs.start()?;
    Ok(projfs)
}

#[inline]
pub fn svc_stop(fs: Option<&mut SnowflakeProjFs>) {
    if let Some(f) = fs {
        f.fs.stop();
    }
}
