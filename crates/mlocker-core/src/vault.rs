use std::{
    fs,
    path::{Path, PathBuf},
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chacha20poly1305::{
    aead::{rand_core::RngCore, Aead, AeadCore, KeyInit, OsRng, Payload},
    XChaCha20Poly1305, XNonce,
};
use pbkdf2::pbkdf2_hmac;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::{
    error::{MlockerCoreError, Result},
    keys::{derive_vault_key, RootKey, VaultKey},
};

pub const ENCRYPTED_VAULT_BLOB_VERSION: u32 = 1;
const ENCRYPTION_ALGORITHM: &str = "XChaCha20Poly1305";
const VAULT_KEY_KDF: &str = "HKDF-SHA256";
const MASTER_KEY_ENVELOPE_VERSION: u32 = 1;
const MASTER_KEY_ENVELOPE_METHOD_PASSWORD: &str = "password";
const PASSWORD_KDF_ALGORITHM: &str = "PBKDF2-HMAC-SHA256";
const PASSWORD_KDF_ITERATIONS: u32 = 600_000;
const PASSWORD_KDF_MAX_ITERATIONS: u32 = 2_000_000;
const PASSWORD_KDF_SALT_LEN: usize = 16;
const KEY_LEN: usize = 32;
const XCHACHA20_POLY1305_NONCE_LEN: usize = 24;

/// Plain vault data before encryption.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Vault {
    #[serde(default)]
    pub logins: Vec<LoginItem>,
    #[serde(default)]
    pub wallet_accounts: Vec<WalletAccountMetadata>,
    #[serde(default)]
    pub ssh_keys: Vec<SshKeyMetadata>,
    #[serde(default)]
    pub passkeys: Vec<PasskeyMetadata>,
}

impl Vault {
    /// Encrypts the vault JSON into a portable encrypted blob.
    pub fn encrypt(&self, key: &VaultKey) -> Result<EncryptedVaultBlob> {
        let mut plaintext = serde_json::to_vec(self)?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
            .map_err(|_| MlockerCoreError::Encryption)?;
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let aad = vault_aad(
            ENCRYPTED_VAULT_BLOB_VERSION,
            ENCRYPTION_ALGORITHM,
            VAULT_KEY_KDF,
        );
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext.as_slice(),
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| MlockerCoreError::Encryption)?;
        plaintext.zeroize();

        Ok(EncryptedVaultBlob {
            version: ENCRYPTED_VAULT_BLOB_VERSION,
            algorithm: ENCRYPTION_ALGORITHM.to_owned(),
            kdf: VAULT_KEY_KDF.to_owned(),
            nonce: STANDARD.encode(nonce),
            ciphertext: STANDARD.encode(ciphertext),
            master_key_envelope: None,
        })
    }

    /// Encrypts the vault and stores a PBKDF2/password-wrapped master key envelope.
    pub fn encrypt_with_password(
        &self,
        master_key: &RootKey,
        vault_path: &str,
        app_domain: &str,
        password: &str,
    ) -> Result<EncryptedVaultBlob> {
        let vault_key = derive_vault_key(master_key, vault_path, app_domain)?;
        let mut blob = self.encrypt(&vault_key)?;
        blob.master_key_envelope = Some(MasterKeyEnvelope::encrypt_with_password(
            master_key, password,
        )?);
        Ok(blob)
    }
}

/// Login metadata and password material stored in the encrypted vault.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct LoginItem {
    pub id: String,
    pub title: String,
    pub site_url: String,
    pub username: String,
    pub password: LoginPassword,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<TotpMetadata>,
}

impl<'de> Deserialize<'de> for LoginItem {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct LoginItemWire {
            id: String,
            title: String,
            site_url: String,
            username: String,
            #[serde(default)]
            password: Option<LoginPassword>,
            #[serde(default)]
            password_derivation_path: Option<String>,
            #[serde(default)]
            notes: Option<String>,
            #[serde(default)]
            totp: Option<TotpMetadata>,
        }

        let wire = LoginItemWire::deserialize(deserializer)?;
        let password = wire
            .password
            .or_else(|| {
                wire.password_derivation_path
                    .map(LoginPassword::mnemonic_derived)
            })
            .ok_or_else(|| serde::de::Error::missing_field("password"))?;

        Ok(Self {
            id: wire.id,
            title: wire.title,
            site_url: wire.site_url,
            username: wire.username,
            password,
            notes: wire.notes,
            totp: wire.totp,
        })
    }
}

/// The password attached to a login item.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LoginPassword {
    MnemonicDerived { path: String },
    UserInput { value: String },
}

impl LoginPassword {
    pub fn mnemonic_derived(path: impl Into<String>) -> Self {
        Self::MnemonicDerived { path: path.into() }
    }

    pub fn user_input(value: impl Into<String>) -> Self {
        Self::UserInput {
            value: value.into(),
        }
    }

    pub fn path(&self) -> Option<&str> {
        match self {
            Self::MnemonicDerived { path } => Some(path),
            Self::UserInput { .. } => None,
        }
    }

    pub fn user_input_value(&self) -> Option<&str> {
        match self {
            Self::MnemonicDerived { .. } => None,
            Self::UserInput { value } => Some(value),
        }
    }
}

/// TOTP/2FA metadata stored with a login item.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TotpMetadata {
    pub secret: String,
    #[serde(default = "default_totp_period")]
    pub period: u64,
    #[serde(default = "default_totp_digits")]
    pub digits: u32,
}

/// Crypto wallet account metadata stored in the encrypted vault.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletAccountMetadata {
    pub id: String,
    pub label: String,
    pub network: String,
    pub address: String,
    pub derivation_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
}

/// SSH key metadata stored in the encrypted vault.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SshKeyMetadata {
    pub id: String,
    pub label: String,
    pub derivation_path: String,
    pub public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// Passkey/WebAuthn credential metadata stored in the encrypted vault.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PasskeyMetadata {
    pub id: String,
    pub label: String,
    pub relying_party_id: String,
    pub username: String,
    pub credential_id: String,
    pub public_key: String,
    pub algorithm: String,
    pub derivation_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// Stable JSON envelope for encrypted vault data.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedVaultBlob {
    pub version: u32,
    pub algorithm: String,
    pub kdf: String,
    pub nonce: String,
    pub ciphertext: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub master_key_envelope: Option<MasterKeyEnvelope>,
}

impl EncryptedVaultBlob {
    pub fn decrypt(&self, key: &VaultKey) -> Result<Vault> {
        self.validate()?;

        let nonce_bytes = STANDARD
            .decode(&self.nonce)
            .map_err(|err| MlockerCoreError::InvalidVaultBlob(err.to_string()))?;
        if nonce_bytes.len() != XCHACHA20_POLY1305_NONCE_LEN {
            return Err(MlockerCoreError::InvalidVaultBlob(format!(
                "nonce must be {XCHACHA20_POLY1305_NONCE_LEN} bytes"
            )));
        }

        let ciphertext = STANDARD
            .decode(&self.ciphertext)
            .map_err(|err| MlockerCoreError::InvalidVaultBlob(err.to_string()))?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
            .map_err(|_| MlockerCoreError::Decryption)?;
        let aad = vault_aad(self.version, &self.algorithm, &self.kdf);
        let mut plaintext = cipher
            .decrypt(
                XNonce::from_slice(&nonce_bytes),
                Payload {
                    msg: ciphertext.as_slice(),
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| MlockerCoreError::Decryption)?;

        let vault = serde_json::from_slice(&plaintext).map_err(MlockerCoreError::from);
        plaintext.zeroize();
        vault
    }

    pub fn decrypt_with_password(
        &self,
        vault_path: &str,
        app_domain: &str,
        password: &str,
    ) -> Result<(Vault, RootKey)> {
        let master_key = self.decrypt_master_key_with_password(password)?;
        let vault_key = derive_vault_key(&master_key, vault_path, app_domain)?;
        let vault = self.decrypt(&vault_key)?;
        Ok((vault, master_key))
    }

    pub fn decrypt_master_key_with_password(&self, password: &str) -> Result<RootKey> {
        let envelope = self.master_key_envelope.as_ref().ok_or_else(|| {
            MlockerCoreError::InvalidVaultBlob("master key envelope is missing".to_owned())
        })?;
        envelope.decrypt_with_password(password)
    }

    pub fn is_password_protected(&self) -> bool {
        self.master_key_envelope
            .as_ref()
            .is_some_and(MasterKeyEnvelope::is_password_protected)
    }

    pub fn to_json_pretty(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(MlockerCoreError::from)
    }

    pub fn from_json(input: &str) -> Result<Self> {
        serde_json::from_str(input).map_err(MlockerCoreError::from)
    }

    fn validate(&self) -> Result<()> {
        if self.version != ENCRYPTED_VAULT_BLOB_VERSION {
            return Err(MlockerCoreError::InvalidVaultBlob(format!(
                "unsupported version {}",
                self.version
            )));
        }
        if self.algorithm != ENCRYPTION_ALGORITHM {
            return Err(MlockerCoreError::InvalidVaultBlob(format!(
                "unsupported algorithm {}",
                self.algorithm
            )));
        }
        if self.kdf != VAULT_KEY_KDF {
            return Err(MlockerCoreError::InvalidVaultBlob(format!(
                "unsupported kdf {}",
                self.kdf
            )));
        }

        Ok(())
    }
}

/// Password-wrapped master key material stored alongside the encrypted vault blob.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MasterKeyEnvelope {
    pub version: u32,
    pub method: String,
    pub algorithm: String,
    pub kdf: PasswordKdfParams,
    pub nonce: String,
    pub ciphertext: String,
}

/// Public PBKDF parameters needed to recover the password wrapping key.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PasswordKdfParams {
    pub algorithm: String,
    pub iterations: u32,
    pub salt: String,
}

impl MasterKeyEnvelope {
    fn encrypt_with_password(master_key: &RootKey, password: &str) -> Result<Self> {
        validate_password(password)?;

        let salt = random_bytes::<PASSWORD_KDF_SALT_LEN>();
        let salt_b64 = STANDARD.encode(salt);
        let kdf = PasswordKdfParams {
            algorithm: PASSWORD_KDF_ALGORITHM.to_owned(),
            iterations: PASSWORD_KDF_ITERATIONS,
            salt: salt_b64,
        };
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let mut wrapping_key = password_wrapping_key(password, &salt, PASSWORD_KDF_ITERATIONS);
        let cipher = XChaCha20Poly1305::new_from_slice(&wrapping_key)
            .map_err(|_| MlockerCoreError::Encryption)?;
        let aad = master_key_envelope_aad(
            MASTER_KEY_ENVELOPE_VERSION,
            MASTER_KEY_ENVELOPE_METHOD_PASSWORD,
            ENCRYPTION_ALGORITHM,
            &kdf,
        );
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: master_key.as_bytes(),
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| MlockerCoreError::Encryption)?;
        wrapping_key.zeroize();

        Ok(Self {
            version: MASTER_KEY_ENVELOPE_VERSION,
            method: MASTER_KEY_ENVELOPE_METHOD_PASSWORD.to_owned(),
            algorithm: ENCRYPTION_ALGORITHM.to_owned(),
            kdf,
            nonce: STANDARD.encode(nonce),
            ciphertext: STANDARD.encode(ciphertext),
        })
    }

    fn decrypt_with_password(&self, password: &str) -> Result<RootKey> {
        self.validate()?;
        validate_password(password)?;

        let salt = STANDARD
            .decode(&self.kdf.salt)
            .map_err(|err| MlockerCoreError::InvalidVaultBlob(err.to_string()))?;
        if salt.len() != PASSWORD_KDF_SALT_LEN {
            return Err(MlockerCoreError::InvalidVaultBlob(format!(
                "password kdf salt must be {PASSWORD_KDF_SALT_LEN} bytes"
            )));
        }

        let nonce_bytes = STANDARD
            .decode(&self.nonce)
            .map_err(|err| MlockerCoreError::InvalidVaultBlob(err.to_string()))?;
        if nonce_bytes.len() != XCHACHA20_POLY1305_NONCE_LEN {
            return Err(MlockerCoreError::InvalidVaultBlob(format!(
                "master key envelope nonce must be {XCHACHA20_POLY1305_NONCE_LEN} bytes"
            )));
        }

        let ciphertext = STANDARD
            .decode(&self.ciphertext)
            .map_err(|err| MlockerCoreError::InvalidVaultBlob(err.to_string()))?;
        let mut wrapping_key = password_wrapping_key(password, &salt, self.kdf.iterations);
        let cipher = XChaCha20Poly1305::new_from_slice(&wrapping_key)
            .map_err(|_| MlockerCoreError::Decryption)?;
        let aad = master_key_envelope_aad(self.version, &self.method, &self.algorithm, &self.kdf);
        let mut plaintext = cipher
            .decrypt(
                XNonce::from_slice(&nonce_bytes),
                Payload {
                    msg: ciphertext.as_slice(),
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| MlockerCoreError::Decryption)?;
        wrapping_key.zeroize();

        if plaintext.len() != KEY_LEN {
            plaintext.zeroize();
            return Err(MlockerCoreError::InvalidVaultBlob(format!(
                "master key must be {KEY_LEN} bytes"
            )));
        }

        let mut bytes = [0_u8; KEY_LEN];
        bytes.copy_from_slice(&plaintext);
        plaintext.zeroize();
        Ok(RootKey::from_bytes(bytes))
    }

    fn is_password_protected(&self) -> bool {
        self.method == MASTER_KEY_ENVELOPE_METHOD_PASSWORD
            && self.kdf.algorithm == PASSWORD_KDF_ALGORITHM
    }

    fn validate(&self) -> Result<()> {
        if self.version != MASTER_KEY_ENVELOPE_VERSION {
            return Err(MlockerCoreError::InvalidVaultBlob(format!(
                "unsupported master key envelope version {}",
                self.version
            )));
        }
        if self.method != MASTER_KEY_ENVELOPE_METHOD_PASSWORD {
            return Err(MlockerCoreError::InvalidVaultBlob(format!(
                "unsupported master key envelope method {}",
                self.method
            )));
        }
        if self.algorithm != ENCRYPTION_ALGORITHM {
            return Err(MlockerCoreError::InvalidVaultBlob(format!(
                "unsupported master key envelope algorithm {}",
                self.algorithm
            )));
        }
        if self.kdf.algorithm != PASSWORD_KDF_ALGORITHM {
            return Err(MlockerCoreError::InvalidVaultBlob(format!(
                "unsupported password kdf {}",
                self.kdf.algorithm
            )));
        }
        if self.kdf.iterations == 0 {
            return Err(MlockerCoreError::InvalidVaultBlob(
                "password kdf iterations must be positive".to_owned(),
            ));
        }
        if self.kdf.iterations > PASSWORD_KDF_MAX_ITERATIONS {
            return Err(MlockerCoreError::InvalidVaultBlob(format!(
                "password kdf iterations must not exceed {PASSWORD_KDF_MAX_ITERATIONS}"
            )));
        }

        Ok(())
    }
}

/// File-backed encrypted vault blob persistence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultStore {
    path: PathBuf,
}

impl VaultStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn save_blob(&self, blob: &EncryptedVaultBlob) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&self.path, blob.to_json_pretty()?)?;
        Ok(())
    }

    pub fn load_blob(&self) -> Result<EncryptedVaultBlob> {
        let json = fs::read_to_string(&self.path)?;
        EncryptedVaultBlob::from_json(&json)
    }
}

fn vault_aad(version: u32, algorithm: &str, kdf: &str) -> String {
    format!("mlocker-core/vault-blob/v{version}/{algorithm}/{kdf}")
}

fn default_totp_period() -> u64 {
    crate::totp::DEFAULT_TOTP_PERIOD
}

fn default_totp_digits() -> u32 {
    crate::totp::DEFAULT_TOTP_DIGITS
}

fn master_key_envelope_aad(
    version: u32,
    method: &str,
    algorithm: &str,
    kdf: &PasswordKdfParams,
) -> String {
    format!(
        "mlocker-core/master-key-envelope/v{version}/{method}/{algorithm}/{}/{}/{}",
        kdf.algorithm, kdf.iterations, kdf.salt
    )
}

fn password_wrapping_key(password: &str, salt: &[u8], iterations: u32) -> [u8; KEY_LEN] {
    let mut key = [0_u8; KEY_LEN];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, &mut key);
    key
}

fn validate_password(password: &str) -> Result<()> {
    if password.is_empty() {
        return Err(MlockerCoreError::KeyDerivation(
            "password must not be empty".to_owned(),
        ));
    }
    Ok(())
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0_u8; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}
