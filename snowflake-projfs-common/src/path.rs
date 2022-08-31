use std::ffi::OsString;
use std::path::{Component, Path};

pub fn normalize_path_segments<P: AsRef<Path>>(path: P) -> Vec<OsString> {
    let path: Vec<Component> = path.as_ref().components().collect();
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

    prefixes
}

#[cfg(test)]
mod tests {
    use crate::path::normalize_path_segments;

    #[test]
    fn test_normal_path() {
        let path_segments = normalize_path_segments("test/path/to/file");
        assert_eq!(
            path_segments,
            vec!["/test", "/test/path", "/test/path/to", "/test/path/to/file"]
        )
    }

    #[test]
    fn test_parent_path() {
        let path_segments = normalize_path_segments("test/path/to/../file");
        assert_eq!(
            path_segments,
            vec!["/test", "/test/path", "/test/path/file"]
        )
    }

    #[test]
    fn test_current_path() {
        let path_segments = normalize_path_segments("/test/path/to/./file");
        assert_eq!(
            path_segments,
            vec!["/test", "/test/path", "/test/path/to", "/test/path/to/file"]
        )
    }

    #[test]
    fn test_forwardslash_path() {
        let path_segments = normalize_path_segments("\\test\\path\\to\\file");
        assert_eq!(
            path_segments,
            vec!["/test", "/test/path", "/test/path/to", "/test/path/to/file"]
        )
    }
}
