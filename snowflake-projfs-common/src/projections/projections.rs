use radix_trie::{Trie, TrieCommon};

use crate::path;
use crate::path::{OwnedProjectedPath, ProjectedPath};
use std::ffi::OsStr;
use std::ops::Deref;
use std::path::{Path, PathBuf};

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum FileAccess {
    Read,
    ReadWrite,
}

// todo: zero-copy?
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum ProjectionEntry {
    File {
        name: OwnedProjectedPath,
        source: PathBuf,
        access: FileAccess,
    },
    Directory {
        name: OwnedProjectedPath,
    },
    Portal {
        name: OwnedProjectedPath,
        source: PathBuf,
        access: FileAccess,
        protect: Vec<PathBuf>,
    },
}

pub struct Projection {
    entries: Trie<OwnedProjectedPath, ProjectionEntry>,
}

impl Projection {
    pub fn get_children<P: AsRef<ProjectedPath>>(
        &self,
        canonical_path: P,
    ) -> Option<Vec<&ProjectionEntry>> {
        if let Some(sub) = self.entries.subtrie(canonical_path.as_ref()) {
            let vecs = sub
                .iter()
                .filter_map(|(key, entry)| {
                    if key.parent() == Some(canonical_path.as_ref()) {
                        Some(entry)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            Some(vecs)
        } else {
            None
        }
    }

    /// Gets the entry in the projection with the given canonical path.
    ///
    /// If the path given is not canonical, then this may return None even
    /// if the entry exists in the projection.
    ///
    /// A canonical path can be retried with [`canonicalize_path_segments`](crate::path::canonicalize_path_segments).
    /// The canonical path to an existing entry is always the last member of the returned `Vec`.
    pub fn get_entry<P: AsRef<ProjectedPath>>(
        &self,
        canonical_path: P,
    ) -> Option<&ProjectionEntry> {
        self.entries.get(canonical_path.as_ref())
    }

    /// Searches for an entry given a path from the filesystem driver.
    ///
    /// Canonical path segments are constructed from the input, and searched in longest-to-shortest
    /// match.
    ///
    /// If the longest match exists in the Projection, returns such longest match.
    ///
    /// Otherwise, the segments are progressively searched for a Portal. If a portal is found,
    /// returns the Portal entry, and the path to the target within the Portal.
    ///
    /// If a shorter match exists but is not a Portal, returns None. Only Portals are matched eagerly.
    /// If no match is found, returns None.
    pub fn search_entry<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Option<(&ProjectionEntry, Option<PathBuf>)> {
        let segments = path::canonicalize_path_segments(path.as_ref());

        todo!()
    }
}

impl From<&[ProjectionEntry]> for Projection {
    fn from(parsed_projection: &[ProjectionEntry]) -> Self {
        let mut map = Trie::new();

        // reverse since we want FIFO order.
        // let mut projections: VecDeque<_> = VecDeque::from_iter(projection.iter());
        map.insert(
            OwnedProjectedPath::from("/"),
            ProjectionEntry::Directory {
                name: OwnedProjectedPath::from("/"),
            },
        );

        for projection in parsed_projection {
            match projection {
                ProjectionEntry::File { name, .. }
                | ProjectionEntry::Portal { name, .. }
                | ProjectionEntry::Directory { name, .. } => {
                    let parent = name.parent();
                    if let Some(parent_path) = &parent {
                        if let Some(mut subtrie) = map.subtrie_mut(*parent_path) {
                            subtrie.insert(name.clone(), projection.clone()).unwrap();
                        }
                    }
                }
            }
        }

        Projection { entries: map }
    }
}

impl ProjectionEntry {
    pub fn full_path(&self) -> &ProjectedPath {
        return match self {
            ProjectionEntry::File { name, .. }
            | ProjectionEntry::Portal { name, .. }
            | ProjectionEntry::Directory { name, .. } => name.deref(),
        };
    }

    pub fn file_name(&self) -> Option<&OsStr> {
        let path = Path::new(self.full_path());
        path.file_name()
    }
}

#[cfg(test)]
mod tests {
    use crate::projections::{parse_projection, Projection};

    #[test]
    fn map_test() {
        let projection = br#"
f(/hello.txt|C:\test.txt|r);
p(/portal|C:\test|rw|protected:file:|);
d(/dir|);
f(/dir/d0|C:\test.txt|r);
        "#;
        let projection = parse_projection(projection).unwrap();
        eprintln!("{:?}", projection);
        let trie = Projection::from(projection.as_slice());

        eprintln!("{:?}", trie.get_children("/"))
    }
}
