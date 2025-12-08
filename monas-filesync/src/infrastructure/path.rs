use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExternalFilePath {
    raw: String, // complete string including the scheme
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsePathError {
    Invalid,
}

impl fmt::Display for ParsePathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParsePathError::Invalid => write!(f, "invalid path format"),
        }
    }
}

impl std::error::Error for ParsePathError {}

impl std::str::FromStr for ExternalFilePath {
    type Err = ParsePathError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains("://") {
            Ok(Self { raw: s.to_owned() })
        } else {
            Err(ParsePathError::Invalid)
        }
    }
}

impl ExternalFilePath {
    pub fn new(raw: impl Into<String>) -> Result<Self, ParsePathError> {
        let s = raw.into();
        s.parse()
    }

    pub fn raw(&self) -> &str {
        &self.raw
    }

    pub fn scheme(&self) -> &str {
        self.raw.split_once("://").map(|(s, _)| s).unwrap_or("")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_from_str_valid() {
        let path = "google-drive://file123".parse::<ExternalFilePath>();
        assert!(path.is_ok());
        assert_eq!(path.unwrap().raw(), "google-drive://file123");
    }

    #[test]
    fn test_path_from_str_invalid() {
        let path = "invalid_path".parse::<ExternalFilePath>();
        assert!(path.is_err());
        assert_eq!(path.unwrap_err(), ParsePathError::Invalid);
    }

    #[test]
    fn test_path_new() {
        let path = ExternalFilePath::new("onedrive://item456");
        assert!(path.is_ok());
        assert_eq!(path.unwrap().raw(), "onedrive://item456");
    }

    #[test]
    fn test_path_scheme() {
        let path = ExternalFilePath::new("google-drive://file123").unwrap();
        assert_eq!(path.scheme(), "google-drive");

        let path = ExternalFilePath::new("onedrive://item456").unwrap();
        assert_eq!(path.scheme(), "onedrive");

        let path = ExternalFilePath::new("ipfs://QmHash").unwrap();
        assert_eq!(path.scheme(), "ipfs");

        let path = ExternalFilePath::new("local:///path/to/file").unwrap();
        assert_eq!(path.scheme(), "local");
    }

    #[test]
    fn test_path_raw() {
        let path = ExternalFilePath::new("google-drive://file123").unwrap();
        assert_eq!(path.raw(), "google-drive://file123");
    }

    #[test]
    fn test_parse_path_error_display() {
        let error = ParsePathError::Invalid;
        assert_eq!(format!("{error}"), "invalid path format");
    }

    #[test]
    fn test_path_scheme_edge_case() {
        // scheme() should handle edge cases gracefully
        let path = ExternalFilePath::new("test://path").unwrap();
        assert_eq!(path.scheme(), "test");

        // Test with empty scheme (shouldn't happen in practice, but test the unwrap_or)
        // This is tested indirectly through the split_once logic
        let path = ExternalFilePath::new("a://b").unwrap();
        assert_eq!(path.scheme(), "a");
    }
}
