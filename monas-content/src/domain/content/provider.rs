use serde::{Deserialize, Serialize};

/// ストレージプロバイダーを表す列挙型。
///
/// サポートされているストレージプロバイダーを型安全に表現します。
/// serdeの`rename_all = "kebab-case"`により、JSONでは`"ipfs"`, `"google-drive"`などの形式でシリアライズされます。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StorageProvider {
    /// IPFS (InterPlanetary File System)
    Ipfs,
    /// Google Drive
    GoogleDrive,
    /// OneDrive
    OneDrive,
    /// ローカルデスクトップストレージ
    Local,
    /// ローカルモバイルストレージ
    LocalMobile,
}

impl StorageProvider {
    /// `StorageProvider`を文字列に変換する
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ipfs => "ipfs",
            Self::GoogleDrive => "google-drive",
            Self::OneDrive => "onedrive",
            Self::Local => "local",
            Self::LocalMobile => "local-mobile",
        }
    }
}

impl std::str::FromStr for StorageProvider {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ipfs" => Ok(Self::Ipfs),
            "google-drive" => Ok(Self::GoogleDrive),
            "onedrive" => Ok(Self::OneDrive),
            "local" => Ok(Self::Local),
            "local-mobile" => Ok(Self::LocalMobile),
            _ => Err(format!("Unknown storage provider: {s}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    mod from_str {
        use super::*;

        #[test]
        fn parses_ipfs() {
            let result = StorageProvider::from_str("ipfs").unwrap();
            assert_eq!(result, StorageProvider::Ipfs);
        }

        #[test]
        fn parses_google_drive() {
            let result = StorageProvider::from_str("google-drive").unwrap();
            assert_eq!(result, StorageProvider::GoogleDrive);
        }

        #[test]
        fn parses_onedrive() {
            let result = StorageProvider::from_str("onedrive").unwrap();
            assert_eq!(result, StorageProvider::OneDrive);
        }

        #[test]
        fn parses_local() {
            let result = StorageProvider::from_str("local").unwrap();
            assert_eq!(result, StorageProvider::Local);
        }

        #[test]
        fn parses_local_mobile() {
            let result = StorageProvider::from_str("local-mobile").unwrap();
            assert_eq!(result, StorageProvider::LocalMobile);
        }

        #[test]
        fn returns_error_for_unknown_provider() {
            let result = StorageProvider::from_str("unknown");
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("Unknown storage provider"));
        }
    }

    mod as_str {
        use super::*;

        #[test]
        fn ipfs_returns_ipfs() {
            assert_eq!(StorageProvider::Ipfs.as_str(), "ipfs");
        }

        #[test]
        fn google_drive_returns_google_drive() {
            assert_eq!(StorageProvider::GoogleDrive.as_str(), "google-drive");
        }

        #[test]
        fn onedrive_returns_onedrive() {
            assert_eq!(StorageProvider::OneDrive.as_str(), "onedrive");
        }

        #[test]
        fn local_returns_local() {
            assert_eq!(StorageProvider::Local.as_str(), "local");
        }

        #[test]
        fn local_mobile_returns_local_mobile() {
            assert_eq!(StorageProvider::LocalMobile.as_str(), "local-mobile");
        }
    }

    mod serde {
        use super::*;

        #[test]
        fn serializes_to_kebab_case() {
            let provider = StorageProvider::GoogleDrive;
            let json = serde_json::to_string(&provider).unwrap();
            assert_eq!(json, "\"google-drive\"");
        }

        #[test]
        fn deserializes_from_kebab_case() {
            let json = "\"google-drive\"";
            let provider: StorageProvider = serde_json::from_str(json).unwrap();
            assert_eq!(provider, StorageProvider::GoogleDrive);
        }

        #[test]
        fn round_trip_serialization() {
            let original = StorageProvider::Ipfs;
            let json = serde_json::to_string(&original).unwrap();
            let deserialized: StorageProvider = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, original);
        }
    }
}
