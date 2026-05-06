use std::{
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    error::{MlockerCoreError, Result},
    vault::EncryptedVaultBlob,
};

pub const DEFAULT_VAULT_BLOB_NAME: &str = "mlocker-vault.json";

/// MVP cloud-drive providers are modeled as folders that sync outside this crate.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum CloudDriveProvider {
    LocalFolder,
    ICloudDrive,
    GoogleDrive,
    Dropbox,
    Custom(String),
}

/// Minimal sync abstraction for encrypted vault blobs.
pub trait EncryptedVaultSync {
    fn export_blob(&self, blob_name: &str, blob: &EncryptedVaultBlob) -> Result<PathBuf>;
    fn import_blob(&self, blob_name: &str) -> Result<EncryptedVaultBlob>;
}

/// Folder-backed sync target suitable for iCloud, Google Drive, Dropbox, or any local folder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FolderSyncTarget {
    pub provider: CloudDriveProvider,
    pub root: PathBuf,
}

impl FolderSyncTarget {
    pub fn new(provider: CloudDriveProvider, root: impl Into<PathBuf>) -> Self {
        Self {
            provider,
            root: root.into(),
        }
    }

    pub fn blob_path(&self, blob_name: &str) -> Result<PathBuf> {
        validate_blob_name(blob_name)?;
        Ok(self.root.join(blob_name))
    }

    pub fn export_default(&self, blob: &EncryptedVaultBlob) -> Result<PathBuf> {
        self.export_blob(DEFAULT_VAULT_BLOB_NAME, blob)
    }

    pub fn import_default(&self) -> Result<EncryptedVaultBlob> {
        self.import_blob(DEFAULT_VAULT_BLOB_NAME)
    }
}

impl EncryptedVaultSync for FolderSyncTarget {
    fn export_blob(&self, blob_name: &str, blob: &EncryptedVaultBlob) -> Result<PathBuf> {
        fs::create_dir_all(&self.root)?;
        let path = self.blob_path(blob_name)?;
        let temp_path = path.with_extension("tmp");
        fs::write(&temp_path, blob.to_json_pretty()?)?;
        if path.exists() {
            fs::remove_file(&path)?;
        }
        fs::rename(&temp_path, &path)?;
        Ok(path)
    }

    fn import_blob(&self, blob_name: &str) -> Result<EncryptedVaultBlob> {
        let path = self.blob_path(blob_name)?;
        let json = fs::read_to_string(path)?;
        EncryptedVaultBlob::from_json(&json)
    }
}

fn validate_blob_name(blob_name: &str) -> Result<()> {
    if blob_name.is_empty()
        || blob_name.contains('/')
        || blob_name.contains('\\')
        || blob_name.contains("..")
        || Path::new(blob_name).components().count() != 1
    {
        return Err(MlockerCoreError::InvalidSyncTarget(format!(
            "invalid blob name {blob_name:?}"
        )));
    }

    Ok(())
}
