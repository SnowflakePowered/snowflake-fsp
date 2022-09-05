use crate::path;
use crate::path::{OwnedProjectedPath, ProjectedPath};
use qp_trie::Trie;
use std::ffi::OsStr;
use std::ops::Deref;
use std::path::{Component, Path, PathBuf};

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
    pub fn get_children<'a, P: AsRef<ProjectedPath> + 'a>(
        &'a self,
        canonical_path: P,
    ) -> Option<impl Iterator<Item = &ProjectionEntry>> {
        let subtrie = self.entries.subtrie(canonical_path.as_ref());
        if subtrie.is_empty() {
            return None;
        }
        // todo: figure out a way to do bfs rather than the subtrie dfs order.
        let vecs = subtrie.iter().filter_map(move |(key, entry)| {
            if key.parent() == Some(canonical_path.as_ref()) {
                Some(entry)
            } else {
                None
            }
        });
        Some(vecs)
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
    /// If the canonicalized input exists in the Projection, returns such longest match.
    ///
    /// Otherwise, the longest common path prefix is searched for a Portal. If a Portal is found,
    /// returns the Portal entry, and the path to the target relative to the Portal source.
    ///
    /// If a shorter match exists but is not a Portal, returns None. Only Portals are matched eagerly.
    /// If no match is found, returns None.
    ///
    /// If a portal is found, the returned segment is a non-projected, OS-dependent PathBuf. This means
    /// that the path separator is OS-dependent, and can be directly pushed into a PathBuf of the
    /// real path to the portal.
    pub fn search_entry<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Option<(&ProjectionEntry, Option<PathBuf>)> {
        if path.as_ref().components().count() == 0 {
            return None;
        }

        let full_path = path::canonicalize_path(path.as_ref());

        if let Some(entry) = self.entries.get(&full_path) {
            return Some((entry, None));
        }

        // SAFETY: segments can not be empty.
        // Never use returned prefixes directly because they are in WTF8 on windows.
        let prefix = self.entries.longest_common_prefix(&full_path);
        let entry = self.entries.get(prefix);
        if let Some(entry) = entry {
            if !entry.is_portal() {
                return None;
            }
            let path = entry.full_path();

            let mut proj_iter = path.as_path().components().peekable();
            let mut req_iter = full_path.as_path().components().peekable();

            while let (Some(proj), Some(req)) = (proj_iter.peek(), req_iter.peek()) {
                if proj != req {
                    break;
                }
                proj_iter.next();
                req_iter.next();
            }

            let mut rest = PathBuf::new();
            for component in req_iter {
                match component {
                    Component::Prefix(_) => {}
                    Component::RootDir => rest.push(std::path::MAIN_SEPARATOR_STR),
                    Component::CurDir => {}
                    Component::ParentDir => {
                        rest.pop();
                    }
                    Component::Normal(s) => rest.push(s),
                }
            }

            // If the rest was empty, we should have returned the Portal directly before.
            assert_ne!(rest.as_os_str(), OsStr::new(""));

            return Some((entry, Some(rest)));
        }

        None
    }
}

// todo: this needs to be TryFrom to validate projection portal existence
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
                    map.insert(name.clone(), projection.clone());
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

    // Returns true if the entry is a portal or a directory.
    pub fn is_directory(&self) -> bool {
        matches!(
            self,
            ProjectionEntry::Portal { .. } | ProjectionEntry::Directory { .. }
        )
    }

    pub fn is_portal(&self) -> bool {
        matches!(self, ProjectionEntry::Portal { .. })
    }

    pub fn portal_source(&self) -> Option<&Path> {
        match self {
            ProjectionEntry::Portal { source, .. } => Some(source.as_path()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::path::OwnedProjectedPath;
    use crate::projections::{parse_projection, FileAccess, Projection, ProjectionEntry};
    use std::path::{Path, PathBuf};

    fn get_test_trie() -> Projection {
        let projection = br#"
f(/hello.txt|C:\test.txt|r);
p(/portal|C:\test|rw|protected:file:|);
d(/dir|);
f(/dir/d0|C:\test.txt|r);
f(/dir/d2|C:\test.txt|r);
        "#;
        let projection = parse_projection(projection).unwrap();
        Projection::from(projection.as_slice())
    }
    #[test]
    fn map_test() {
        let trie = get_test_trie();

        eprintln!(
            "{:?}",
            trie.get_children("/dir").map(|s| s.collect::<Vec<_>>())
        );

        // assert_eq!(trie.get_children("/dir").map(|s| s.count()), Some(2));

        assert_eq!(trie.get_children("/").map(|s| s.count()), Some(3))
    }

    #[test]
    fn search_test() {
        let trie = get_test_trie();
        let res = trie.search_entry("/portal/remainder/of/directory");
        assert_eq!(
            res,
            Some((
                &ProjectionEntry::Portal {
                    name: OwnedProjectedPath::from("/portal"),
                    source: Path::new("C:\\test").to_path_buf(),
                    access: FileAccess::ReadWrite,
                    protect: ["protected", "file"]
                        .iter()
                        .map(Path::new)
                        .map(Path::to_path_buf)
                        .collect::<Vec<PathBuf>>()
                },
                Some(Path::new("remainder\\of\\directory").to_path_buf())
            ))
        )
    }

    #[test]
    fn search_direct_portal_test() {
        let trie = get_test_trie();
        let res = trie.search_entry("/portal/");
        assert_eq!(
            res,
            Some((
                &ProjectionEntry::Portal {
                    name: OwnedProjectedPath::from("/portal"),
                    source: Path::new("C:\\test").to_path_buf(),
                    access: FileAccess::ReadWrite,
                    protect: ["protected", "file"]
                        .iter()
                        .map(Path::new)
                        .map(Path::to_path_buf)
                        .collect::<Vec<PathBuf>>()
                },
                None
            ))
        )
    }
}
