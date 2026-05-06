use thiserror::Error;

pub type Result<T> = std::result::Result<T, MlockerCoreError>;

#[derive(Debug, Error)]
pub enum MlockerCoreError {
    #[error("invalid mnemonic: {0}")]
    InvalidMnemonic(String),

    #[error("key derivation failed: {0}")]
    KeyDerivation(String),

    #[error("invalid password options: {0}")]
    InvalidPasswordOptions(String),

    #[error("vault encryption failed")]
    Encryption,

    #[error("vault decryption failed")]
    Decryption,

    #[error("invalid encrypted vault blob: {0}")]
    InvalidVaultBlob(String),

    #[error("serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("io failed: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid sync target: {0}")]
    InvalidSyncTarget(String),

    #[error("invalid derivation path: {0}")]
    InvalidDerivationPath(String),

    #[error("wallet derivation failed: {0}")]
    WalletDerivation(String),

    #[error("ssh key derivation failed: {0}")]
    SshDerivation(String),

    #[error("totp failed: {0}")]
    Totp(String),
}
