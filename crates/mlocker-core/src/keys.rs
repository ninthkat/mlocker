use std::fmt;

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    error::{MlockerCoreError, Result},
    mnemonic::RecoveryPhrase,
};

pub const DEFAULT_APP_DOMAIN: &str = "app.mlocker";

/// 32-byte root secret derived from a BIP39 seed and app domain.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct RootKey([u8; 32]);

/// 32-byte vault content-encryption key derived from a root key and vault context.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct VaultKey([u8; 32]);

impl RootKey {
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl VaultKey {
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for RootKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RootKey").field(&"<redacted>").finish()
    }
}

impl fmt::Debug for VaultKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("VaultKey").field(&"<redacted>").finish()
    }
}

/// Derives a root key using an empty BIP39 passphrase.
pub fn derive_root_key(mnemonic: &RecoveryPhrase, app_domain: &str) -> Result<RootKey> {
    derive_root_key_with_passphrase(mnemonic, "", app_domain)
}

/// Derives a root key from a BIP39 mnemonic, optional BIP39 passphrase, and app domain.
pub fn derive_root_key_with_passphrase(
    mnemonic: &RecoveryPhrase,
    passphrase: &str,
    app_domain: &str,
) -> Result<RootKey> {
    let mut seed = mnemonic.to_seed(passphrase)?;
    let salt = context_hash("mlocker-core/root-key/v1", &[app_domain.trim()]);
    let bytes = hkdf_32(&seed, &salt, b"root-key")?;
    seed.zeroize();
    Ok(RootKey::from_bytes(bytes))
}

/// Derives a vault key from an already-derived root key.
pub fn derive_vault_key(
    root_key: &RootKey,
    vault_path: &str,
    app_domain: &str,
) -> Result<VaultKey> {
    let salt = context_hash(
        "mlocker-core/vault-key/v1",
        &[app_domain.trim(), vault_path.trim()],
    );
    let bytes = hkdf_32(root_key.as_bytes(), &salt, b"vault-key")?;
    Ok(VaultKey::from_bytes(bytes))
}

/// Derives a vault key directly from a mnemonic and vault context.
pub fn derive_vault_key_from_mnemonic(
    mnemonic: &RecoveryPhrase,
    passphrase: &str,
    vault_path: &str,
    app_domain: &str,
) -> Result<VaultKey> {
    let root = derive_root_key_with_passphrase(mnemonic, passphrase, app_domain)?;
    derive_vault_key(&root, vault_path, app_domain)
}

pub(crate) fn context_hash(label: &str, parts: &[&str]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(label.as_bytes());
    hasher.update([0]);

    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
        hasher.update([0]);
    }

    hasher.finalize().into()
}

pub(crate) fn hkdf_32(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = [0u8; 32];
    hkdf.expand(info, &mut out)
        .map_err(|err| MlockerCoreError::KeyDerivation(err.to_string()))?;
    Ok(out)
}
