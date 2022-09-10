use crate::projections::Projection;
use qp_trie::Break;
use std::borrow::{Borrow, BorrowMut};
use std::ffi::{OsStr, OsString};
use std::ops::Deref;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};

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
#[allow(dead_code)]
fn canonicalize_path_segments<P: AsRef<Path>>(path: P) -> Vec<OwnedProjectedPath> {
    let path: Vec<Component> = path.as_ref().components().collect();
    if path.len() == 1 && path[0] == Component::RootDir {
        return vec![OwnedProjectedPath::root()];
    }

    let mut prefixes = Vec::new();
    for prefix in path {
        match prefix {
            Component::Prefix(_) => {}
            Component::RootDir => {}
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

// canonicalize the path in place?
fn canonicalize_path<P: AsRef<Path>>(path: P) -> OwnedProjectedPath {
    let path: Vec<Component> = path.as_ref().components().collect();
    if path.len() == 1 && path[0] == Component::RootDir {
        return OwnedProjectedPath::root();
    }

    let mut prefixes = PathBuf::new();
    for prefix in path {
        match prefix {
            Component::Prefix(_) => {}
            Component::RootDir => prefixes.push("/"),
            Component::CurDir => {}
            Component::ParentDir => {
                prefixes.pop();
            }
            Component::Normal(component) => prefixes.push(component),
        }
    }

    let result = prefixes.into_os_string();

    let result = if cfg!(target_os = "windows") {
        let bytes: Vec<u16> = result
            .encode_wide()
            .map(|c| if c == b'\\' as u16 { b'/' as u16 } else { c })
            .collect();
        OsString::from_wide(&bytes)
    } else {
        result
    };

    OwnedProjectedPath(result)
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct OwnedProjectedPath(OsString);

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

impl Borrow<[u8]> for OwnedProjectedPath {
    fn borrow(&self) -> &[u8] {
        #[cfg(target_os = "linux")]
        return std::os::unix::ffi::OsStrExt::as_bytes(&self.0);

        // !! crimes ahead !!
        // SAFETY: the resultant encoding is unspecified and can change between compilations.
        #[cfg(target_os = "windows")]
        unsafe {
            std::mem::transmute(self.0.as_os_str())
        }
    }
}

impl PartialEq<&str> for OwnedProjectedPath {
    fn eq(&self, other: &&str) -> bool {
        self.0.eq(other)
    }
}

impl PartialEq<str> for OwnedProjectedPath {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl Break for OwnedProjectedPath {
    type Split = [u8];

    fn empty<'a>() -> &'a Self::Split {
        <&'a [u8]>::default()
    }

    fn find_break(&self, loc: usize) -> &Self::Split {
        &<Self as Borrow<[u8]>>::borrow(self)[..loc]
    }
}

impl OwnedProjectedPath {
    /// The canonical root path of the projection.
    pub const ROOT: &'static str = "/";

    /// A root OwnedProjectedPath.
    pub fn root() -> Self {
        OwnedProjectedPath::from(OwnedProjectedPath::ROOT)
    }

    /// Returns whether or not the path is at the root of the projection.
    pub fn is_root(&self) -> bool {
        self.0 == Self::ROOT
    }

    /// Returns the `ProjectedPath` without its final component, if there is one.
    pub fn parent(&self) -> Option<&ProjectedPath> {
        let path = Path::new(&self.0);
        path.parent().map(ProjectedPath::new)
    }

    /// Create a new `OwnedProjectedPath` in canonical format.
    pub fn new_canonical<P: AsRef<Path>>(path: P) -> Self {
        canonicalize_path(path)
    }
}

#[derive(Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct ProjectedPath(OsStr);

impl ProjectedPath {
    /// Returns whether or not the path is at the root of the projection.
    pub fn root() -> &'static ProjectedPath {
        ProjectedPath::new("/")
    }

    /// Creates a new path from a referenced `OsStr`.
    pub fn new<S: AsRef<OsStr> + ?Sized>(s: &S) -> &ProjectedPath {
        unsafe { &*(s.as_ref() as *const OsStr as *const ProjectedPath) }
    }

    /// Converts to a `Path`.
    pub fn as_path(&self) -> &Path {
        Path::new(&self.0)
    }

    /// Returns the `ProjectedPath` without its final component, if there is one.
    pub fn parent(&self) -> Option<&ProjectedPath> {
        let path = Path::new(&self.0);
        path.parent().map(ProjectedPath::new)
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

impl AsRef<ProjectedPath> for OwnedProjectedPath {
    fn as_ref(&self) -> &ProjectedPath {
        ProjectedPath::new(self.0.as_os_str())
    }
}

impl Borrow<[u8]> for ProjectedPath {
    fn borrow(&self) -> &[u8] {
        #[cfg(target_os = "linux")]
        return std::os::unix::ffi::OsStrExt::as_bytes(&self.0);

        // !! crimes ahead !!
        // SAFETY: the resultant encoding is unspecified and can change between compilations.
        //
        // assumptions:
        // 1. the encoding of OsStr is consistent for the lifetime of the program instance
        // 2. OsStr is layout compatible with [u8]. This follows from `sys::os_str::Slice` being
        //    repr(transparent) on Windows over a Wtf8 { bytes: [u8] }.
        #[cfg(target_os = "windows")]
        unsafe {
            std::mem::transmute(&self.0)
        }
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
