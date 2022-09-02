use os_str_bytes::OsStrBytes;
use radix_trie::TrieKey;
use std::borrow::Borrow;
use std::ffi::{OsStr, OsString};
use std::ops::Deref;
use std::path::{Component, Path};

/// Canonicalize path segments relative to the root.
///
/// If `path` is the root directory, will return only "/".
/// Otherwise, "/" is omitted, and only the individual canonical segments
/// of the path are returned, from shortest to longest match.
///
/// Hence, the canonical representation of `path` is the last element
/// of the returned `Vec`.
///
/// When searching for a path segment in the Projection, always search from
/// longest to shortest match.
pub fn canonicalize_path_segments<P: AsRef<Path>>(path: P) -> Vec<OwnedProjectedPath> {
    let path: Vec<Component> = path.as_ref().components().collect();
    if path.len() == 1 && path[0] == Component::RootDir {
        return vec![OwnedProjectedPath::root()];
    }

    let mut prefixes = Vec::new();
    for prefix in path {
        match prefix {
            Component::Prefix(_) => {}
            Component::RootDir => {
            }
            Component::CurDir => {}
            Component::ParentDir => {
                prefixes.pop();
            }
            Component::Normal(component) => {
                let mut prev_string = prefixes.last().cloned().unwrap_or_else(OsString::new);
                prev_string.push("/");
                prev_string.push(component);
                prefixes.push(prev_string)
            }
        }
    }

    prefixes.iter().map(OwnedProjectedPath::from).collect()
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct OwnedProjectedPath(OsString);

impl OwnedProjectedPath {
    pub fn root() -> Self {
        OwnedProjectedPath::from("/")
    }
}

#[derive(Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct ProjectedPath(OsStr);

impl ProjectedPath {
    pub fn root() -> &'static ProjectedPath {
        ProjectedPath::new("/")
    }

    pub fn new<S: AsRef<OsStr> + ?Sized>(s: &S) -> &ProjectedPath {
        unsafe { &*(s.as_ref() as *const OsStr as *const ProjectedPath) }
    }
}

impl Deref for OwnedProjectedPath {
    type Target = ProjectedPath;

    fn deref(&self) -> &Self::Target {
        ProjectedPath::new(self.0.as_os_str())
    }
}

impl<T> From<T> for OwnedProjectedPath
where
    T: AsRef<OsStr>,
{
    fn from(s: T) -> Self {
        OwnedProjectedPath(s.as_ref().to_os_string())
    }
}

impl Borrow<ProjectedPath> for OwnedProjectedPath {
    fn borrow(&self) -> &ProjectedPath {
        self.deref()
    }
}

impl AsRef<OsStr> for ProjectedPath {
    fn as_ref(&self) -> &OsStr {
        &self.0
    }
}

impl AsRef<ProjectedPath> for &OsStr {
    fn as_ref(&self) -> &ProjectedPath {
        ProjectedPath::new(self)
    }
}

impl AsRef<ProjectedPath> for &str {
    fn as_ref(&self) -> &ProjectedPath {
        ProjectedPath::new(self)
    }
}

impl TrieKey for ProjectedPath {
    fn encode_bytes(&self) -> Vec<u8> {
        self.0.to_raw_bytes().to_vec()
    }
}

impl TrieKey for OwnedProjectedPath {
    fn encode_bytes(&self) -> Vec<u8> {
        self.0.to_raw_bytes().to_vec()
    }
}

impl OwnedProjectedPath {
    pub fn parent(&self) -> Option<&ProjectedPath> {
        let path = Path::new(&self.0);
        path.parent().map(ProjectedPath::new)
    }
}

impl PartialEq<&str> for OwnedProjectedPath {
    fn eq(&self, other: &&str) -> bool {
        self.0.eq(other)
    }
}

#[cfg(test)]
mod tests {
    use crate::path::canonicalize_path_segments;

    #[test]
    fn test_normal_path() {
        let path_segments = canonicalize_path_segments("test/path/to/file");
        assert_eq!(
            path_segments,
            vec!["/test", "/test/path", "/test/path/to", "/test/path/to/file"]
        )
    }

    #[test]
    fn test_parent_path() {
        let path_segments = canonicalize_path_segments("test/path/to/../file");
        assert_eq!(
            path_segments,
            vec!["/test", "/test/path", "/test/path/file"]
        )
    }

    #[test]
    fn test_current_path() {
        let path_segments = canonicalize_path_segments("/test/path/to/./file");
        assert_eq!(
            path_segments,
            vec!["/test", "/test/path", "/test/path/to", "/test/path/to/file"]
        )
    }

    #[test]
    fn test_forwardslash_path() {
        let path_segments = canonicalize_path_segments("\\test\\path\\to\\file");
        assert_eq!(
            path_segments,
            vec!["/test", "/test/path", "/test/path/to", "/test/path/to/file"]
        )
    }
}
