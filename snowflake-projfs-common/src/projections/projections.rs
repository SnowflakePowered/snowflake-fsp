use std::path::PathBuf;

pub enum FileAccess {
    Read,
    ReadWrite,
}

// todo: zero-copy?
pub enum Projection {
    File(PathBuf, FileAccess),
    Directory(Vec<Projection>),
    Portal {
        root: PathBuf,
        access: FileAccess,
        protect: Vec<PathBuf>,
    },
}
