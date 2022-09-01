use std::ffi::OsString;
use std::path::PathBuf;

#[derive(Debug, Eq, PartialEq)]
pub enum FileAccess {
    Read,
    ReadWrite,
}

// todo: zero-copy?
#[derive(Debug, Eq, PartialEq)]
pub enum Projection {
    File {
        name: OsString,
        source: PathBuf,
        access: FileAccess,
    },
    Directory {
        name: OsString,
        contents: Vec<Projection>,
    },
    Portal {
        name: OsString,
        source: PathBuf,
        access: FileAccess,
        protect: Vec<PathBuf>,
    },
}
