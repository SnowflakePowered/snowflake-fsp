use crate::path::{OwnedProjectedPath, ProjectedPath};
use qp_trie::Trie;
use std::borrow::Cow;
use std::ffi::OsStr;
use std::fs::{DirEntry, ReadDir};
use std::ops::Deref;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
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

type ProjectionChildren<'a, P: AsRef<ProjectedPath> + 'a> =
    impl Iterator<Item = &'a ProjectionEntry>;

enum DirSearch<'a, P: AsRef<ProjectedPath> + 'a> {
    Entry(ProjectionChildren<'a, P>),
    Real(ReadDir),
}

impl<'a, P: AsRef<ProjectedPath> + 'a> DirSearch<'a, P> {
    pub fn find_case_insensitive<F: AsRef<OsStr>>(
        &mut self,
        file_name: F,
        projection: &'a Projection,
    ) -> Option<(Cow<OsStr>, Option<DirSearch<'a, &'a OwnedProjectedPath>>)> {
        match self {
            DirSearch::Entry(iterator) => iterator
                .find(|f| {
                    if let Some(f) = f.file_name() {
                        // todo: do proper case folding
                        return f.eq_ignore_ascii_case(file_name.as_ref());
                    }
                    false
                })
                .and_then(|f| {
                    let name = f.file_name().map(Cow::Borrowed);
                    let next = match f {
                        ProjectionEntry::File { .. } => None,
                        ProjectionEntry::Directory { name, .. } => {
                            projection.get_children(name).map(DirSearch::Entry)
                        }
                        ProjectionEntry::Portal { source, .. } => {
                            source.read_dir().ok().map(DirSearch::Real)
                        }
                    };
                    name.map(|n| (n, next))
                }),
            DirSearch::Real(readdir) => readdir
                .find(|f| {
                    if let Ok(f) = f {
                        return f.file_name().eq_ignore_ascii_case(file_name.as_ref());
                    }
                    false
                })
                .and_then(|f| {
                    f.ok().map(|f| {
                        (
                            Cow::Owned(f.file_name()),
                            f.path().read_dir().ok().map(DirSearch::Real),
                        )
                    })
                }),
        }
    }
}

impl Projection {
    pub fn get_parent<'a, P: AsRef<ProjectedPath> + 'a>(
        &'a self,
        canonical_path: P,
    ) -> Option<&ProjectionEntry> {
        let path = canonical_path.as_ref();
        path.parent().and_then(|parent| self.entries.get(parent))
    }

    pub fn get_children<'a, P: AsRef<ProjectedPath> + 'a>(
        &'a self,
        canonical_path: P,
    ) -> Option<ProjectionChildren<'a, P>> {
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

    fn search_entry_internal<P: AsRef<ProjectedPath>>(
        &self,
        full_path: P,
    ) -> Option<(&ProjectionEntry, Option<PathBuf>)> {
        let full_path = full_path.as_ref();
        if let Some(entry) = self.entries.get(full_path) {
            return Some((entry, None));
        }

        // SAFETY: segments can not be empty.
        // Never use returned prefixes directly because they are in WTF8 on windows.
        let prefix = self.entries.longest_common_prefix(full_path);
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

            // The underlying iterator for the Peekable<Components> has already been advanced
            // so we need to manually reconstitute the remainder path.
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

    /// Searches for an entry given a path from the filesystem driver in a case-insensitive manner.
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
    pub fn search_entry_case_insensitive<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Option<(&ProjectionEntry, Option<PathBuf>)> {
        if path.as_ref().components().count() == 0 {
            return None;
        }

        // case-sensitive optimization: if the path already exists in the projection,
        // then we do not need to expensively resolve the case.
        if let Some(result) = self.search_entry(path.as_ref()) {
            return Some(result);
        }

        let full_path = OwnedProjectedPath::new_canonical(path.as_ref());
        let full_path = self.resolve_case_insensitive(&full_path);
        self.search_entry_internal(&full_path)
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

        let full_path = OwnedProjectedPath::new_canonical(path.as_ref());
        self.search_entry_internal(&full_path)
    }

    /// Resolve the **absolute** projected path against the projection as a case insensitive path.
    // panics if the path is not absolute.
    pub fn resolve_case_insensitive<P: AsRef<ProjectedPath>>(&self, path: P) -> OwnedProjectedPath {
        let path = path.as_ref();
        let mut buf = PathBuf::from("/");

        // need the iterator returned from get_children to be &OwnedProjectedPath
        // to get tait unification working
        let root = OwnedProjectedPath::root();
        let root_children = self.get_children(&root);
        // if the projection is completely empty, we can not resolve anything.
        if root_children.is_none() {
            return OwnedProjectedPath::from(path);
        }
        let mut search = DirSearch::Entry(root_children.unwrap());
        let mut components = path.as_path().components();

        for component in components.by_ref() {
            match component {
                Component::Normal(component) => {
                    if let Some((result, next)) = search.find_case_insensitive(component, self) {
                        buf.push(result);
                        if let Some(next) = next {
                            search = next;
                        } else {
                            // no next directory, so we bail.
                            break;
                        }
                    } else {
                        // Can no longer resolve against the projection so just bail.
                        buf.push(component);
                        break;
                    }
                }
                Component::RootDir => {}
                Component::Prefix(_) => {}
                _ => panic!("path must be absolute"),
            }
        }

        for component in components {
            buf.push(component)
        }
        OwnedProjectedPath::new_canonical(buf)
    }
}

// todo: this needs to be TryFrom to validate projection portal existence
impl From<&[ProjectionEntry]> for Projection {
    fn from(parsed_projection: &[ProjectionEntry]) -> Self {
        let mut map = Trie::new();

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

    // Returns true if the entry is a directory.
    pub fn is_directory(&self) -> bool {
        matches!(self, ProjectionEntry::Directory { .. })
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
