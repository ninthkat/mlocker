use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

const DEFAULT_VAULT_DIR: &str = ".mlocker";
const DEFAULT_VAULT_FILE: &str = "personal.vault";
const DEFAULT_VAULT_CONTEXT: &str = "default";
const DEFAULT_PASSWORD_PATH_PREFIX: &str = "m/passwords";
const DEFAULT_SSH_PATH_PREFIX: &str = "m/101010'";
const DEFAULT_PASSKEY_PATH_PREFIX: &str = "m/11010'";
const LOWER: &[u8] = b"abcdefghijkmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
const DIGITS: &[u8] = b"23456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{}";
const BASE58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub struct OpenForm {
    pub open_path: String,
    pub open_passphrase: String,
    pub open_recovery_phrase: String,
    pub create_path: String,
    pub create_passphrase: String,
    pub create_recovery_phrase: String,
    pub restore_path: String,
    pub restore_passphrase: String,
    pub restore_recovery_phrase: String,
}

impl Default for OpenForm {
    fn default() -> Self {
        let path = default_vault_path();

        Self {
            open_path: path.clone(),
            open_passphrase: String::new(),
            open_recovery_phrase: String::new(),
            create_path: path.clone(),
            create_passphrase: String::new(),
            create_recovery_phrase: String::new(),
            restore_path: path,
            restore_passphrase: String::new(),
            restore_recovery_phrase: String::new(),
        }
    }
}

pub struct LoginForm {
    pub title: String,
    pub username: String,
    pub url: String,
    pub totp_secret: String,
    pub notes: String,
    pub password_kind: PasswordKind,
    pub user_password: String,
    pub password_length: usize,
    pub include_symbols: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasswordKind {
    MnemonicDerived,
    UserInput,
}

impl PasswordKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::MnemonicDerived => "Mnemonic derived",
            Self::UserInput => "User input",
        }
    }
}

impl Default for LoginForm {
    fn default() -> Self {
        Self {
            title: String::new(),
            username: String::new(),
            url: String::new(),
            totp_secret: String::new(),
            notes: String::new(),
            password_kind: PasswordKind::MnemonicDerived,
            user_password: String::new(),
            password_length: 24,
            include_symbols: true,
        }
    }
}

impl LoginForm {
    pub fn validate(&self) -> Result<(), String> {
        if self.title.trim().is_empty() {
            return Err(String::from("Add a title before creating the login item."));
        }

        if self.username.trim().is_empty() {
            return Err(String::from(
                "Add a username before creating the login item.",
            ));
        }

        if self.url.trim().is_empty() {
            return Err(String::from("Add a URL before creating the login item."));
        }

        if self.password_kind == PasswordKind::UserInput {
            if self.user_password.is_empty() {
                return Err(String::from("Enter the login password before saving."));
            }
        } else if !(16..=64).contains(&self.password_length) {
            return Err(String::from(
                "Password length must be between 16 and 64 characters.",
            ));
        }

        if !self.totp_secret.trim().is_empty() {
            mlocker_core::normalize_totp_secret(&self.totp_secret)
                .map_err(|err| format!("2FA secret is invalid: {err}"))?;
        }

        Ok(())
    }

    pub fn clear_secret_inputs(&mut self) {
        self.title.clear();
        self.username.clear();
        self.url.clear();
        self.totp_secret.zeroize();
        self.notes.zeroize();
        self.password_kind = PasswordKind::MnemonicDerived;
        self.user_password.zeroize();
        self.password_length = 24;
        self.include_symbols = true;
    }
}

pub struct SshKeyForm {
    pub label: String,
    pub derivation_path: String,
    pub comment: String,
}

impl Default for SshKeyForm {
    fn default() -> Self {
        Self {
            label: String::from("Personal SSH"),
            derivation_path: format!("{DEFAULT_SSH_PATH_PREFIX}/0'"),
            comment: String::from("mlocker"),
        }
    }
}

impl SshKeyForm {
    pub fn validate(&self) -> Result<(), String> {
        if self.label.trim().is_empty() {
            return Err(String::from("Add a label before creating the SSH key."));
        }
        if self.derivation_path.trim().is_empty() {
            return Err(String::from("Add a derivation path for the SSH key."));
        }
        Ok(())
    }

    pub fn clear_inputs(&mut self, next_path: String) {
        self.label.clear();
        self.derivation_path = next_path;
        self.comment.clear();
    }
}

pub struct PasskeyForm {
    pub label: String,
    pub relying_party_id: String,
    pub username: String,
    pub notes: String,
}

impl Default for PasskeyForm {
    fn default() -> Self {
        Self {
            label: String::from("Example Passkey"),
            relying_party_id: String::new(),
            username: String::new(),
            notes: String::new(),
        }
    }
}

impl PasskeyForm {
    pub fn validate(&self) -> Result<(), String> {
        if self.label.trim().is_empty() {
            return Err(String::from("Add a label before creating the passkey."));
        }
        if self.relying_party_id.trim().is_empty() {
            return Err(String::from(
                "Add a relying party id before creating the passkey.",
            ));
        }
        if self.username.trim().is_empty() {
            return Err(String::from("Add a username before creating the passkey."));
        }
        Ok(())
    }

    pub fn clear_secret_inputs(&mut self) {
        self.label.clear();
        self.relying_party_id.clear();
        self.username.clear();
        self.notes.zeroize();
    }
}

pub struct VaultSession {
    pub path: String,
    pub seed: [u8; 32],
    pub items: Vec<LoginItem>,
    pub ssh_keys: Vec<SshKeyItem>,
    pub passkeys: Vec<PasskeyItem>,
    pub wallet_accounts: Vec<WalletAccount>,
    #[cfg(feature = "core-integration")]
    core_root_key: Option<mlocker_core::RootKey>,
    #[cfg(feature = "core-integration")]
    core_vault_key: Option<mlocker_core::VaultKey>,
    #[cfg(feature = "core-integration")]
    core_vault: Option<mlocker_core::Vault>,
}

impl VaultSession {
    pub fn open(path: &str, passphrase: &str, recovery_phrase: &str) -> Result<Self, String> {
        #[cfg(feature = "core-integration")]
        {
            let blob = mlocker_core::VaultStore::new(path)
                .load_blob()
                .map_err(|err| format!("Failed to read encrypted vault: {err}"))?;

            let (vault, unlock) = if blob.is_password_protected() && !passphrase.is_empty() {
                match blob.decrypt_with_password(
                    DEFAULT_VAULT_CONTEXT,
                    mlocker_core::DEFAULT_APP_DOMAIN,
                    passphrase,
                ) {
                    Ok((vault, master_key)) => {
                        let mnemonic = optional_recovery_phrase(recovery_phrase)?;
                        if let Some(mnemonic) = &mnemonic {
                            let expected = mlocker_core::derive_root_key(
                                mnemonic,
                                mlocker_core::DEFAULT_APP_DOMAIN,
                            )
                            .map_err(|err| format!("Root key derivation failed: {err}"))?;
                            if expected != master_key {
                                return Err(String::from(
                                    "Recovery phrase does not match the vault master key.",
                                ));
                            }
                        }
                        let unlock = core_unlock_from_master_key(path, master_key, mnemonic)?;
                        (vault, unlock)
                    }
                    Err(password_err) if recovery_phrase.split_whitespace().count() >= 12 => {
                        core_decrypt_with_recovery(&blob, path, recovery_phrase, passphrase)
                            .map_err(|recovery_err| {
                                format!(
                                    "Failed to decrypt vault with password: {password_err}; recovery fallback: {recovery_err}"
                                )
                            })?
                    }
                    Err(err) => {
                        return Err(format!("Failed to decrypt vault with password: {err}"));
                    }
                }
            } else {
                core_decrypt_with_recovery(&blob, path, recovery_phrase, passphrase)?
            };

            Self::from_core_vault(path, vault, unlock)
        }

        #[cfg(not(feature = "core-integration"))]
        {
            let seed = hash_parts(&[b"open-vault", path.as_bytes(), passphrase.as_bytes()]);
            Ok(Self {
                path: path.to_owned(),
                seed,
                items: Vec::new(),
                ssh_keys: Vec::new(),
                passkeys: Vec::new(),
                wallet_accounts: derive_wallet_accounts(&seed),
            })
        }
    }

    pub fn restore(path: &str, passphrase: &str, recovery_phrase: &str) -> Result<Self, String> {
        #[cfg(feature = "core-integration")]
        {
            if std::path::Path::new(path).exists() {
                return Err(format!(
                    "A vault already exists at {path}. Use Open vault instead."
                ));
            }

            let unlock = core_unlock_from_recovery(path, recovery_phrase, "")?;
            let vault = mlocker_core::Vault::default();
            let blob = vault
                .encrypt_with_password(
                    &unlock.root_key,
                    DEFAULT_VAULT_CONTEXT,
                    mlocker_core::DEFAULT_APP_DOMAIN,
                    passphrase,
                )
                .map_err(|err| format!("Failed to encrypt restored vault: {err}"))?;
            mlocker_core::VaultStore::new(path)
                .save_blob(&blob)
                .map_err(|err| format!("Failed to write restored vault: {err}"))?;

            Self::from_core_vault(path, vault, unlock)
        }

        #[cfg(not(feature = "core-integration"))]
        {
            let seed = hash_parts(&[
                b"restore-vault",
                path.as_bytes(),
                passphrase.as_bytes(),
                recovery_phrase.as_bytes(),
            ]);

            Ok(Self {
                path: path.to_owned(),
                seed,
                items: Vec::new(),
                ssh_keys: Vec::new(),
                passkeys: Vec::new(),
                wallet_accounts: derive_wallet_accounts(&seed),
            })
        }
    }

    #[cfg(feature = "core-integration")]
    fn from_core_vault(
        path: &str,
        vault: mlocker_core::Vault,
        unlock: CoreUnlock,
    ) -> Result<Self, String> {
        let wallet_accounts = if vault.wallet_accounts.is_empty() {
            if let Some(mnemonic) = &unlock.mnemonic {
                core_wallet_accounts(mnemonic, "", &unlock.seed)?
            } else {
                derive_wallet_accounts(&unlock.seed)
            }
        } else {
            vault
                .wallet_accounts
                .iter()
                .map(|account| WalletAccount {
                    chain: account.network.clone(),
                    path: account.derivation_path.clone(),
                    address: account.address.clone(),
                })
                .collect()
        };
        let items = core_login_items(vault.logins.clone(), &unlock.root_key)?;
        let ssh_keys = core_ssh_key_items(vault.ssh_keys.clone());
        let passkeys = core_passkey_items(vault.passkeys.clone());

        Ok(Self {
            path: path.to_owned(),
            seed: unlock.seed,
            items,
            ssh_keys,
            passkeys,
            wallet_accounts,
            core_root_key: Some(unlock.root_key),
            core_vault_key: Some(unlock.vault_key),
            core_vault: Some(vault),
        })
    }

    pub fn build_login_password(&self, form: &LoginForm) -> Result<LoginPassword, String> {
        if form.password_kind == PasswordKind::UserInput {
            return Ok(LoginPassword::user_input(form.user_password.clone()));
        }

        let path = self.next_password_path();
        #[cfg(feature = "core-integration")]
        if let Some(root_key) = &self.core_root_key {
            if form.include_symbols {
                return core_login_password(root_key, &path, form)
                    .map(|value| LoginPassword::mnemonic_derived(value, path));
            }
        }

        Ok(LoginPassword::mnemonic_derived(
            derive_login_password(&self.seed, form, &path),
            path,
        ))
    }

    pub fn next_password_path(&self) -> String {
        format!("{DEFAULT_PASSWORD_PATH_PREFIX}/{}", self.items.len())
    }

    pub fn next_ssh_derivation_path(&self) -> String {
        format!("{DEFAULT_SSH_PATH_PREFIX}/{}'", self.ssh_keys.len())
    }

    pub fn next_passkey_derivation_path(&self) -> String {
        format!("{DEFAULT_PASSKEY_PATH_PREFIX}/{}'", self.passkeys.len())
    }

    pub fn uses_core_persistence(&self) -> bool {
        #[cfg(feature = "core-integration")]
        {
            self.core_vault_key.is_some()
        }

        #[cfg(not(feature = "core-integration"))]
        {
            false
        }
    }

    pub fn persist_login_item(&mut self, item: &LoginItem) -> Result<(), String> {
        #[cfg(feature = "core-integration")]
        if let (Some(vault), Some(vault_key)) = (&mut self.core_vault, &self.core_vault_key) {
            vault.logins.push(mlocker_core::LoginItem {
                id: item.id.clone(),
                title: item.title.clone(),
                site_url: item.url.clone(),
                username: item.username.clone(),
                password: item.password.to_core(),
                notes: (!item.notes.is_empty()).then(|| item.notes.clone()),
                totp: item
                    .totp_secret
                    .as_ref()
                    .map(|secret| mlocker_core::TotpMetadata {
                        secret: secret.clone(),
                        period: mlocker_core::DEFAULT_TOTP_PERIOD,
                        digits: mlocker_core::DEFAULT_TOTP_DIGITS,
                    }),
            });
            let store = mlocker_core::VaultStore::new(&self.path);
            let master_key_envelope = store
                .load_blob()
                .ok()
                .and_then(|blob| blob.master_key_envelope);
            let blob = vault
                .encrypt(vault_key)
                .map_err(|err| format!("Failed to encrypt vault update: {err}"))?;
            let mut blob = blob;
            blob.master_key_envelope = master_key_envelope;
            store
                .save_blob(&blob)
                .map_err(|err| format!("Failed to save vault update: {err}"))?;
        }

        Ok(())
    }

    pub fn derive_ssh_key(&self, form: &SshKeyForm) -> Result<SshKeyItem, String> {
        #[cfg(feature = "core-integration")]
        if let Some(root_key) = &self.core_root_key {
            let derived = mlocker_core::derive_ssh_key_from_root_key(
                root_key,
                form.derivation_path.trim(),
                form.comment.trim(),
            )
            .map_err(|err| format!("Core SSH key derivation failed: {err}"))?;
            return Ok(SshKeyItem::from_derived(form, derived));
        }

        #[cfg(not(feature = "core-integration"))]
        {
            Ok(SshKeyItem::from_preview_seed(&self.seed, form))
        }

        #[cfg(feature = "core-integration")]
        {
            Err(String::from(
                "Open a core-backed vault before adding SSH keys.",
            ))
        }
    }

    pub fn persist_ssh_key_item(&mut self, item: &SshKeyItem) -> Result<(), String> {
        #[cfg(feature = "core-integration")]
        if let (Some(vault), Some(vault_key)) = (&mut self.core_vault, &self.core_vault_key) {
            vault.ssh_keys.push(mlocker_core::SshKeyMetadata {
                id: item.id.clone(),
                label: item.label.clone(),
                derivation_path: item.derivation_path.clone(),
                public_key: item.public_key.clone(),
                comment: (!item.comment.is_empty()).then(|| item.comment.clone()),
            });
            let store = mlocker_core::VaultStore::new(&self.path);
            let master_key_envelope = store
                .load_blob()
                .ok()
                .and_then(|blob| blob.master_key_envelope);
            let mut blob = vault
                .encrypt(vault_key)
                .map_err(|err| format!("Failed to encrypt vault update: {err}"))?;
            blob.master_key_envelope = master_key_envelope;
            store
                .save_blob(&blob)
                .map_err(|err| format!("Failed to save vault update: {err}"))?;
        }

        Ok(())
    }

    pub fn derive_passkey(&self, form: &PasskeyForm) -> Result<PasskeyItem, String> {
        let path = self.next_passkey_derivation_path();
        #[cfg(feature = "core-integration")]
        if let Some(root_key) = &self.core_root_key {
            let derived = mlocker_core::derive_passkey_from_root_key(
                root_key,
                &path,
                form.relying_party_id.trim(),
                form.username.trim(),
            )
            .map_err(|err| format!("Core passkey derivation failed: {err}"))?;
            return Ok(PasskeyItem::from_derived(form, derived));
        }

        #[cfg(not(feature = "core-integration"))]
        {
            Ok(PasskeyItem::from_preview_seed(&self.seed, form, path))
        }

        #[cfg(feature = "core-integration")]
        {
            Err(String::from(
                "Open a core-backed vault before adding passkeys.",
            ))
        }
    }

    pub fn persist_passkey_item(&mut self, item: &PasskeyItem) -> Result<(), String> {
        #[cfg(feature = "core-integration")]
        if let (Some(vault), Some(vault_key)) = (&mut self.core_vault, &self.core_vault_key) {
            vault.passkeys.push(mlocker_core::PasskeyMetadata {
                id: item.id.clone(),
                label: item.label.clone(),
                relying_party_id: item.relying_party_id.clone(),
                username: item.username.clone(),
                credential_id: item.credential_id.clone(),
                public_key: item.public_key.clone(),
                algorithm: item.algorithm.clone(),
                derivation_path: item.derivation_path.clone(),
                notes: (!item.notes.is_empty()).then(|| item.notes.clone()),
            });
            let store = mlocker_core::VaultStore::new(&self.path);
            let master_key_envelope = store
                .load_blob()
                .ok()
                .and_then(|blob| blob.master_key_envelope);
            let mut blob = vault
                .encrypt(vault_key)
                .map_err(|err| format!("Failed to encrypt vault update: {err}"))?;
            blob.master_key_envelope = master_key_envelope;
            store
                .save_blob(&blob)
                .map_err(|err| format!("Failed to save vault update: {err}"))?;
        }

        Ok(())
    }
}

pub fn default_vault_path() -> String {
    default_vault_path_from_home(&user_home_dir())
        .to_string_lossy()
        .into_owned()
}

pub fn generate_recovery_phrase() -> Result<String, String> {
    #[cfg(feature = "core-integration")]
    {
        mlocker_core::generate_mnemonic(12)
            .map(|phrase| phrase.expose_phrase().to_owned())
            .map_err(|err| format!("Failed to generate recovery phrase: {err}"))
    }

    #[cfg(not(feature = "core-integration"))]
    {
        Err(String::from(
            "Recovery phrase generation requires core integration.",
        ))
    }
}

fn user_home_dir() -> PathBuf {
    env_path("HOME")
        .or_else(|| env_path("USERPROFILE"))
        .unwrap_or_else(|| PathBuf::from("."))
}

fn env_path(name: &str) -> Option<PathBuf> {
    let value = std::env::var_os(name)?;
    if value.as_os_str().is_empty() {
        None
    } else {
        Some(PathBuf::from(value))
    }
}

fn default_vault_path_from_home(home: &Path) -> PathBuf {
    home.join(DEFAULT_VAULT_DIR).join(DEFAULT_VAULT_FILE)
}

#[derive(Clone)]
pub struct LoginItem {
    pub id: String,
    pub title: String,
    pub username: String,
    pub url: String,
    pub password: LoginPassword,
    pub totp_secret: Option<String>,
    pub notes: String,
}

impl LoginItem {
    pub fn from_form(seed: &[u8; 32], form: &LoginForm, password: LoginPassword) -> Self {
        let id_hash = hash_parts(&[
            b"login-id",
            seed,
            form.title.trim().as_bytes(),
            form.username.trim().as_bytes(),
            form.url.trim().as_bytes(),
        ]);
        let totp_secret = if form.totp_secret.trim().is_empty() {
            None
        } else {
            mlocker_core::normalize_totp_secret(&form.totp_secret).ok()
        };

        Self {
            id: hex::encode(&id_hash[..8]),
            title: form.title.trim().to_owned(),
            username: form.username.trim().to_owned(),
            url: form.url.trim().to_owned(),
            password,
            totp_secret,
            notes: form.notes.trim().to_owned(),
        }
    }
}

#[derive(Clone)]
pub enum LoginPassword {
    MnemonicDerived { value: String, path: String },
    UserInput { value: String },
}

impl LoginPassword {
    pub fn mnemonic_derived(value: String, path: String) -> Self {
        Self::MnemonicDerived { value, path }
    }

    pub fn user_input(value: String) -> Self {
        Self::UserInput { value }
    }

    pub fn value(&self) -> &str {
        match self {
            Self::MnemonicDerived { value, .. } | Self::UserInput { value } => value,
        }
    }

    pub fn path(&self) -> Option<&str> {
        match self {
            Self::MnemonicDerived { path, .. } => Some(path),
            Self::UserInput { .. } => None,
        }
    }

    pub fn kind(&self) -> PasswordKind {
        match self {
            Self::MnemonicDerived { .. } => PasswordKind::MnemonicDerived,
            Self::UserInput { .. } => PasswordKind::UserInput,
        }
    }

    #[cfg(feature = "core-integration")]
    fn to_core(&self) -> mlocker_core::LoginPassword {
        match self {
            Self::MnemonicDerived { path, .. } => {
                mlocker_core::LoginPassword::mnemonic_derived(path.clone())
            }
            Self::UserInput { value } => mlocker_core::LoginPassword::user_input(value.clone()),
        }
    }
}

pub struct WalletAccount {
    pub chain: String,
    pub path: String,
    pub address: String,
}

#[derive(Clone)]
pub struct SshKeyItem {
    pub id: String,
    pub label: String,
    pub derivation_path: String,
    pub public_key: String,
    pub comment: String,
}

#[derive(Clone)]
pub struct PasskeyItem {
    pub id: String,
    pub label: String,
    pub relying_party_id: String,
    pub username: String,
    pub credential_id: String,
    pub public_key: String,
    pub algorithm: String,
    pub derivation_path: String,
    pub notes: String,
}

impl PasskeyItem {
    #[cfg(feature = "core-integration")]
    fn from_derived(form: &PasskeyForm, derived: mlocker_core::DerivedPasskey) -> Self {
        let id_hash = hash_parts(&[
            b"passkey-id",
            form.relying_party_id.trim().as_bytes(),
            form.username.trim().as_bytes(),
            derived.credential_id.as_bytes(),
        ]);

        Self {
            id: hex::encode(&id_hash[..8]),
            label: form.label.trim().to_owned(),
            relying_party_id: form.relying_party_id.trim().to_ascii_lowercase(),
            username: form.username.trim().to_owned(),
            credential_id: derived.credential_id,
            public_key: derived.public_key,
            algorithm: derived.algorithm,
            derivation_path: derived.derivation_path,
            notes: form.notes.trim().to_owned(),
        }
    }

    #[cfg(not(feature = "core-integration"))]
    fn from_preview_seed(seed: &[u8; 32], form: &PasskeyForm, derivation_path: String) -> Self {
        let digest = hash_parts(&[
            b"passkey-preview",
            seed,
            derivation_path.as_bytes(),
            form.relying_party_id.trim().as_bytes(),
            form.username.trim().as_bytes(),
        ]);
        let public_key = base58_encode(&digest);
        let credential_id = hex::encode(&digest[..16]);
        let id_hash = hash_parts(&[b"passkey-id", credential_id.as_bytes()]);

        Self {
            id: hex::encode(&id_hash[..8]),
            label: form.label.trim().to_owned(),
            relying_party_id: form.relying_party_id.trim().to_ascii_lowercase(),
            username: form.username.trim().to_owned(),
            credential_id,
            public_key,
            algorithm: String::from("EdDSA-preview"),
            derivation_path,
            notes: form.notes.trim().to_owned(),
        }
    }
}

impl SshKeyItem {
    #[cfg(feature = "core-integration")]
    fn from_derived(form: &SshKeyForm, derived: mlocker_core::DerivedSshKey) -> Self {
        let id_hash = hash_parts(&[
            b"ssh-key-id",
            form.label.trim().as_bytes(),
            derived.derivation_path.as_bytes(),
            derived.public_key_openssh.as_bytes(),
        ]);

        Self {
            id: hex::encode(&id_hash[..8]),
            label: form.label.trim().to_owned(),
            derivation_path: derived.derivation_path,
            public_key: derived.public_key_openssh,
            comment: form.comment.trim().to_owned(),
        }
    }

    #[cfg(not(feature = "core-integration"))]
    fn from_preview_seed(seed: &[u8; 32], form: &SshKeyForm) -> Self {
        let digest = hash_parts(&[
            b"ssh-key-preview",
            seed,
            form.derivation_path.trim().as_bytes(),
            form.label.trim().as_bytes(),
        ]);
        let public_key = format!("ssh-ed25519 {}", base58_encode(&digest));
        let id_hash = hash_parts(&[b"ssh-key-id", public_key.as_bytes()]);

        Self {
            id: hex::encode(&id_hash[..8]),
            label: form.label.trim().to_owned(),
            derivation_path: form.derivation_path.trim().to_owned(),
            public_key,
            comment: form.comment.trim().to_owned(),
        }
    }
}

pub fn derive_login_password(seed: &[u8; 32], form: &LoginForm, path: &str) -> String {
    let mut alphabet = Vec::with_capacity(LOWER.len() + UPPER.len() + DIGITS.len() + SYMBOLS.len());
    alphabet.extend_from_slice(LOWER);
    alphabet.extend_from_slice(UPPER);
    alphabet.extend_from_slice(DIGITS);

    if form.include_symbols {
        alphabet.extend_from_slice(SYMBOLS);
    }

    let mut output = Vec::with_capacity(form.password_length);
    let mut counter = 0_u64;

    while output.len() < form.password_length {
        let counter_bytes = counter.to_le_bytes();
        let block = hash_parts(&[
            b"login-password",
            seed,
            path.trim().as_bytes(),
            form.title.trim().as_bytes(),
            form.username.trim().as_bytes(),
            form.url.trim().as_bytes(),
            &counter_bytes,
        ]);

        for byte in block {
            output.push(alphabet[usize::from(byte) % alphabet.len()]);
            if output.len() == form.password_length {
                break;
            }
        }

        counter += 1;
    }

    let policy_block = hash_parts(&[b"login-password-policy", seed, form.title.trim().as_bytes()]);
    output[0] = UPPER[usize::from(policy_block[0]) % UPPER.len()];
    output[1] = LOWER[usize::from(policy_block[1]) % LOWER.len()];
    output[2] = DIGITS[usize::from(policy_block[2]) % DIGITS.len()];

    if form.include_symbols && output.len() > 3 {
        output[3] = SYMBOLS[usize::from(policy_block[3]) % SYMBOLS.len()];
    }

    String::from_utf8(output).expect("password alphabet is valid UTF-8")
}

pub fn derive_wallet_accounts(seed: &[u8; 32]) -> Vec<WalletAccount> {
    (0..3)
        .flat_map(|index| {
            [
                WalletAccount {
                    chain: String::from("Ethereum"),
                    path: format!("m/44'/60'/0'/0/{index}"),
                    address: ethereum_preview(seed, index),
                },
                WalletAccount {
                    chain: String::from("Bitcoin"),
                    path: format!("m/84'/0'/0'/0/{index}"),
                    address: bitcoin_preview(seed, index),
                },
                WalletAccount {
                    chain: String::from("Solana"),
                    path: format!("m/44'/501'/{index}'/0'"),
                    address: solana_preview(seed, index),
                },
            ]
        })
        .collect()
}

#[cfg(feature = "core-integration")]
fn core_login_password(
    root_key: &mlocker_core::RootKey,
    path: &str,
    form: &LoginForm,
) -> Result<String, String> {
    let request = mlocker_core::PasswordDerivationRequest::new(
        path,
        form.url.trim().to_ascii_lowercase(),
        form.username.trim(),
    )
    .with_options(mlocker_core::PasswordOptions {
        length: form.password_length,
        symbols: mlocker_core::PasswordOptions::default().symbols,
    });

    mlocker_core::derive_password(root_key, &request)
        .map_err(|err| format!("Core password derivation failed: {err}"))
}

#[cfg(feature = "core-integration")]
struct CoreUnlock {
    mnemonic: Option<mlocker_core::RecoveryPhrase>,
    root_key: mlocker_core::RootKey,
    vault_key: mlocker_core::VaultKey,
    seed: [u8; 32],
}

#[cfg(feature = "core-integration")]
fn core_decrypt_with_recovery(
    blob: &mlocker_core::EncryptedVaultBlob,
    path: &str,
    recovery_phrase: &str,
    legacy_passphrase: &str,
) -> Result<(mlocker_core::Vault, CoreUnlock), String> {
    let unlock = core_unlock_from_recovery(path, recovery_phrase, "")?;
    match blob.decrypt(&unlock.vault_key) {
        Ok(vault) => Ok((vault, unlock)),
        Err(primary_err) if !legacy_passphrase.is_empty() => {
            let legacy_unlock =
                core_unlock_from_recovery(path, recovery_phrase, legacy_passphrase)?;
            let vault = blob.decrypt(&legacy_unlock.vault_key).map_err(|err| {
                format!(
                    "check the recovery phrase and password: {primary_err}; legacy passphrase fallback: {err}"
                )
            })?;
            Ok((vault, legacy_unlock))
        }
        Err(err) => Err(format!("check the recovery phrase and password: {err}")),
    }
}

#[cfg(feature = "core-integration")]
fn core_unlock_from_recovery(
    path: &str,
    recovery_phrase: &str,
    bip39_passphrase: &str,
) -> Result<CoreUnlock, String> {
    let mnemonic = mlocker_core::parse_mnemonic(recovery_phrase)
        .map_err(|err| format!("Recovery phrase parsing failed: {err}"))?;
    let root_key = mlocker_core::derive_root_key_with_passphrase(
        &mnemonic,
        bip39_passphrase,
        mlocker_core::DEFAULT_APP_DOMAIN,
    )
    .map_err(|err| format!("Root key derivation failed: {err}"))?;
    core_unlock_from_master_key(path, root_key, Some(mnemonic))
}

#[cfg(feature = "core-integration")]
fn core_unlock_from_master_key(
    path: &str,
    root_key: mlocker_core::RootKey,
    mnemonic: Option<mlocker_core::RecoveryPhrase>,
) -> Result<CoreUnlock, String> {
    let vault_key = mlocker_core::derive_vault_key(
        &root_key,
        DEFAULT_VAULT_CONTEXT,
        mlocker_core::DEFAULT_APP_DOMAIN,
    )
    .map_err(|err| format!("Vault key derivation failed: {err}"))?;
    let seed = hash_parts(&[b"core-vault-session", path.as_bytes(), root_key.as_bytes()]);

    Ok(CoreUnlock {
        mnemonic,
        root_key,
        vault_key,
        seed,
    })
}

#[cfg(feature = "core-integration")]
fn optional_recovery_phrase(
    recovery_phrase: &str,
) -> Result<Option<mlocker_core::RecoveryPhrase>, String> {
    if recovery_phrase.trim().is_empty() {
        return Ok(None);
    }

    mlocker_core::parse_mnemonic(recovery_phrase)
        .map(Some)
        .map_err(|err| format!("Recovery phrase parsing failed: {err}"))
}

#[cfg(feature = "core-integration")]
fn core_login_items(
    items: Vec<mlocker_core::LoginItem>,
    root_key: &mlocker_core::RootKey,
) -> Result<Vec<LoginItem>, String> {
    items
        .into_iter()
        .map(|item| {
            let password = match item.password {
                mlocker_core::LoginPassword::MnemonicDerived { path } => {
                    let request = mlocker_core::PasswordDerivationRequest::new(
                        path.clone(),
                        item.site_url.trim().to_ascii_lowercase(),
                        item.username.trim(),
                    )
                    .with_options(mlocker_core::PasswordOptions {
                        length: 24,
                        symbols: mlocker_core::PasswordOptions::default().symbols,
                    });
                    let value = mlocker_core::derive_password(root_key, &request)
                        .map_err(|err| format!("Core password derivation failed: {err}"))?;
                    LoginPassword::mnemonic_derived(value, path)
                }
                mlocker_core::LoginPassword::UserInput { value } => {
                    LoginPassword::user_input(value)
                }
            };

            Ok(LoginItem {
                id: item.id,
                title: item.title,
                username: item.username,
                url: item.site_url,
                password,
                totp_secret: item.totp.map(|totp| totp.secret),
                notes: item.notes.unwrap_or_default(),
            })
        })
        .collect()
}

#[cfg(feature = "core-integration")]
fn core_ssh_key_items(items: Vec<mlocker_core::SshKeyMetadata>) -> Vec<SshKeyItem> {
    items
        .into_iter()
        .map(|item| SshKeyItem {
            id: item.id,
            label: item.label,
            derivation_path: item.derivation_path,
            public_key: item.public_key,
            comment: item.comment.unwrap_or_default(),
        })
        .collect()
}

#[cfg(feature = "core-integration")]
fn core_passkey_items(items: Vec<mlocker_core::PasskeyMetadata>) -> Vec<PasskeyItem> {
    items
        .into_iter()
        .map(|item| PasskeyItem {
            id: item.id,
            label: item.label,
            relying_party_id: item.relying_party_id,
            username: item.username,
            credential_id: item.credential_id,
            public_key: item.public_key,
            algorithm: item.algorithm,
            derivation_path: item.derivation_path,
            notes: item.notes.unwrap_or_default(),
        })
        .collect()
}

#[cfg(feature = "core-integration")]
fn core_wallet_accounts(
    mnemonic: &mlocker_core::RecoveryPhrase,
    passphrase: &str,
    seed: &[u8; 32],
) -> Result<Vec<WalletAccount>, String> {
    let mut accounts = Vec::new();

    for index in 0..3 {
        let eth =
            mlocker_core::derive_ethereum_account_with_passphrase(mnemonic, passphrase, index)
                .map_err(|err| format!("Core Ethereum derivation failed: {err}"))?;
        accounts.push(WalletAccount {
            chain: String::from("Ethereum"),
            path: eth.derivation_path,
            address: eth.address,
        });

        let sol = mlocker_core::derive_solana_account_with_passphrase(mnemonic, passphrase, index)
            .map_err(|err| format!("Core Solana derivation failed: {err}"))?;
        accounts.push(WalletAccount {
            chain: String::from("Solana"),
            path: sol.derivation_path,
            address: sol.address,
        });
    }

    accounts.extend(
        derive_wallet_accounts(seed)
            .into_iter()
            .filter(|account| account.chain == "Bitcoin"),
    );
    Ok(accounts)
}

pub fn fingerprint(seed: &[u8; 32]) -> String {
    let digest = hash_parts(&[b"vault-fingerprint", seed]);
    hex::encode(&digest[..6])
}

fn ethereum_preview(seed: &[u8; 32], index: u32) -> String {
    let index_bytes = index.to_le_bytes();
    let digest = hash_parts(&[b"wallet-ethereum", seed, &index_bytes]);
    format!("0x{}", hex::encode(&digest[12..32]))
}

fn bitcoin_preview(seed: &[u8; 32], index: u32) -> String {
    let index_bytes = index.to_le_bytes();
    let digest = hash_parts(&[b"wallet-bitcoin", seed, &index_bytes]);
    format!("bc1q{}", base58_encode(&digest[..20]).to_lowercase())
}

fn solana_preview(seed: &[u8; 32], index: u32) -> String {
    let index_bytes = index.to_le_bytes();
    let digest = hash_parts(&[b"wallet-solana", seed, &index_bytes]);
    base58_encode(&digest)
}

fn hash_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();

    for part in parts {
        hasher.update((part.len() as u64).to_le_bytes());
        hasher.update(part);
    }

    hasher.finalize().into()
}

fn base58_encode(bytes: &[u8]) -> String {
    let mut digits = vec![0_u8];

    for byte in bytes {
        let mut carry = u32::from(*byte);

        for digit in &mut digits {
            let value = u32::from(*digit) * 256 + carry;
            *digit = (value % 58) as u8;
            carry = value / 58;
        }

        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }

    for byte in bytes {
        if *byte == 0 {
            digits.push(0);
        } else {
            break;
        }
    }

    digits
        .iter()
        .rev()
        .map(|digit| BASE58[usize::from(*digit)] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn filled_form() -> LoginForm {
        LoginForm {
            title: String::from("GitHub"),
            username: String::from("dev@example.com"),
            url: String::from("https://github.com"),
            totp_secret: String::new(),
            notes: String::new(),
            password_kind: PasswordKind::MnemonicDerived,
            user_password: String::new(),
            password_length: 24,
            include_symbols: true,
        }
    }

    #[test]
    fn default_vault_path_uses_user_mlocker_directory() {
        let path = default_vault_path_from_home(Path::new("/tmp/mlocker-home"));

        assert_eq!(
            path,
            PathBuf::from("/tmp/mlocker-home/.mlocker/personal.vault")
        );
    }

    #[test]
    fn open_form_defaults_to_personal_vault_path() {
        let form = OpenForm::default();

        assert!(form.open_path.ends_with(".mlocker/personal.vault"));
        assert_eq!(form.open_path, form.create_path);
        assert_eq!(form.open_path, form.restore_path);
    }

    #[cfg(feature = "core-integration")]
    #[test]
    fn generated_recovery_phrase_has_twelve_words() {
        let phrase = generate_recovery_phrase().unwrap();

        assert_eq!(phrase.split_whitespace().count(), 12);
    }

    #[test]
    fn login_password_derivation_is_stable() {
        let seed = hash_parts(&[b"test-vault", b"correct horse battery staple"]);
        let form = filled_form();

        assert_eq!(
            derive_login_password(&seed, &form, "m/passwords/0"),
            derive_login_password(&seed, &form, "m/passwords/0")
        );
    }

    #[test]
    fn login_password_derivation_changes_with_username() {
        let seed = hash_parts(&[b"test-vault", b"correct horse battery staple"]);
        let mut first = filled_form();
        let mut second = filled_form();
        second.username = String::from("ops@example.com");

        assert_ne!(
            derive_login_password(&seed, &first, "m/passwords/0"),
            derive_login_password(&seed, &second, "m/passwords/0")
        );

        first.password_length = 32;
        assert_eq!(
            derive_login_password(&seed, &first, "m/passwords/0").len(),
            32
        );
    }

    #[test]
    fn wallet_accounts_are_deterministic() {
        let seed = hash_parts(&[b"test-wallets", MNEMONIC.as_bytes()]);

        let first = derive_wallet_accounts(&seed);
        let second = derive_wallet_accounts(&seed);

        assert_eq!(first.len(), 9);
        assert_eq!(first[0].address, second[0].address);
        assert_ne!(first[0].address, first[1].address);
    }

    #[cfg(feature = "core-integration")]
    #[test]
    fn restore_creates_encrypted_core_vault_file() {
        let path = temp_vault_path("restore");

        let session =
            VaultSession::restore(path.to_str().unwrap(), "local-password", MNEMONIC).unwrap();

        assert!(path.exists());
        assert_eq!(session.path, path.to_string_lossy());
        assert!(session.items.is_empty());
        let blob = mlocker_core::VaultStore::new(&path).load_blob().unwrap();
        assert!(blob.is_password_protected());
        assert!(VaultSession::open(path.to_str().unwrap(), "local-password", "").is_ok());
        assert!(VaultSession::open(path.to_str().unwrap(), "", MNEMONIC).is_ok());
        assert!(VaultSession::open(path.to_str().unwrap(), "wrong-password", "").is_err());

        std::fs::remove_file(path).unwrap();
    }

    #[cfg(feature = "core-integration")]
    #[test]
    fn open_reads_encrypted_core_vault_items() {
        let path = temp_vault_path("open");
        let recovery = mlocker_core::parse_mnemonic(MNEMONIC).unwrap();
        let key = mlocker_core::derive_vault_key_from_mnemonic(
            &recovery,
            "",
            DEFAULT_VAULT_CONTEXT,
            mlocker_core::DEFAULT_APP_DOMAIN,
        )
        .unwrap();
        let vault = mlocker_core::Vault {
            logins: vec![mlocker_core::LoginItem {
                id: String::from("item-1"),
                title: String::from("Example"),
                site_url: String::from("https://example.com"),
                username: String::from("alice"),
                password: mlocker_core::LoginPassword::mnemonic_derived("m/passwords/0"),
                notes: Some(String::from("saved note")),
                totp: None,
            }],
            wallet_accounts: Vec::new(),
            ssh_keys: Vec::new(),
            passkeys: Vec::new(),
        };
        let blob = vault.encrypt(&key).unwrap();
        mlocker_core::VaultStore::new(&path)
            .save_blob(&blob)
            .unwrap();

        let session = VaultSession::open(path.to_str().unwrap(), "", MNEMONIC).unwrap();

        assert_eq!(session.items.len(), 1);
        assert_eq!(session.items[0].title, "Example");
        assert_eq!(session.items[0].username, "alice");
        assert_eq!(session.items[0].password.path(), Some("m/passwords/0"));
        assert_eq!(session.items[0].notes, "saved note");
        assert!(!session.items[0].password.value().is_empty());

        std::fs::remove_file(path).unwrap();
    }

    #[cfg(feature = "core-integration")]
    #[test]
    fn open_reads_password_wrapped_core_vault_without_recovery_phrase() {
        let path = temp_vault_path("password-open");
        let recovery = mlocker_core::parse_mnemonic(MNEMONIC).unwrap();
        let root_key =
            mlocker_core::derive_root_key(&recovery, mlocker_core::DEFAULT_APP_DOMAIN).unwrap();
        let vault = mlocker_core::Vault {
            logins: vec![mlocker_core::LoginItem {
                id: String::from("item-1"),
                title: String::from("Example"),
                site_url: String::from("https://example.com"),
                username: String::from("alice"),
                password: mlocker_core::LoginPassword::mnemonic_derived("m/passwords/0"),
                notes: Some(String::from("saved note")),
                totp: Some(mlocker_core::TotpMetadata {
                    secret: String::from("JBSWY3DPEHPK3PXP"),
                    period: mlocker_core::DEFAULT_TOTP_PERIOD,
                    digits: mlocker_core::DEFAULT_TOTP_DIGITS,
                }),
            }],
            wallet_accounts: Vec::new(),
            ssh_keys: Vec::new(),
            passkeys: Vec::new(),
        };
        let blob = vault
            .encrypt_with_password(
                &root_key,
                DEFAULT_VAULT_CONTEXT,
                mlocker_core::DEFAULT_APP_DOMAIN,
                "local-password",
            )
            .unwrap();
        mlocker_core::VaultStore::new(&path)
            .save_blob(&blob)
            .unwrap();

        let session = VaultSession::open(path.to_str().unwrap(), "local-password", "").unwrap();

        assert_eq!(session.items.len(), 1);
        assert_eq!(session.items[0].title, "Example");
        assert_eq!(
            session.items[0].totp_secret.as_deref(),
            Some("JBSWY3DPEHPK3PXP")
        );
        assert!(!session.items[0].password.value().is_empty());

        std::fs::remove_file(path).unwrap();
    }

    #[cfg(feature = "core-integration")]
    #[test]
    fn user_input_login_password_persists_without_path() {
        let path = temp_vault_path("user-input-login");
        let mut session =
            VaultSession::restore(path.to_str().unwrap(), "local-password", MNEMONIC).unwrap();
        let form = LoginForm {
            title: String::from("Manual"),
            username: String::from("alice"),
            url: String::from("https://manual.example"),
            totp_secret: String::new(),
            notes: String::from("manual secret"),
            password_kind: PasswordKind::UserInput,
            user_password: String::from("user-entered-secret"),
            password_length: 24,
            include_symbols: true,
        };

        let password = session.build_login_password(&form).unwrap();
        let item = LoginItem::from_form(&session.seed, &form, password);
        session.persist_login_item(&item).unwrap();
        session.items.push(item);

        let reopened = VaultSession::open(path.to_str().unwrap(), "local-password", "").unwrap();
        assert_eq!(reopened.items.len(), 1);
        assert_eq!(reopened.items[0].title, "Manual");
        assert_eq!(reopened.items[0].password.path(), None);
        assert_eq!(reopened.items[0].password.value(), "user-entered-secret");

        std::fs::remove_file(path).unwrap();
    }

    #[cfg(feature = "core-integration")]
    #[test]
    fn ssh_key_items_are_derived_and_persisted() {
        let path = temp_vault_path("ssh-key");
        let mut session =
            VaultSession::restore(path.to_str().unwrap(), "local-password", MNEMONIC).unwrap();
        let form = SshKeyForm {
            label: String::from("GitHub SSH"),
            derivation_path: String::from("m/101010'/0'"),
            comment: String::from("mlocker-test"),
        };

        let item = session.derive_ssh_key(&form).unwrap();
        session.persist_ssh_key_item(&item).unwrap();
        session.ssh_keys.push(item.clone());

        let reopened = VaultSession::open(path.to_str().unwrap(), "local-password", "").unwrap();
        assert_eq!(reopened.ssh_keys.len(), 1);
        assert_eq!(reopened.ssh_keys[0].label, "GitHub SSH");
        assert_eq!(reopened.ssh_keys[0].derivation_path, "m/101010'/0'");
        assert_eq!(reopened.ssh_keys[0].public_key, item.public_key);

        std::fs::remove_file(path).unwrap();
    }

    #[cfg(feature = "core-integration")]
    #[test]
    fn passkey_items_are_derived_and_persisted() {
        let path = temp_vault_path("passkey");
        let mut session =
            VaultSession::restore(path.to_str().unwrap(), "local-password", MNEMONIC).unwrap();
        let form = PasskeyForm {
            label: String::from("Example Passkey"),
            relying_party_id: String::from("example.com"),
            username: String::from("alice@example.com"),
            notes: String::from("test note"),
        };

        let item = session.derive_passkey(&form).unwrap();
        session.persist_passkey_item(&item).unwrap();
        session.passkeys.push(item.clone());

        let reopened = VaultSession::open(path.to_str().unwrap(), "local-password", "").unwrap();
        assert_eq!(reopened.passkeys.len(), 1);
        assert_eq!(reopened.passkeys[0].label, "Example Passkey");
        assert_eq!(reopened.passkeys[0].relying_party_id, "example.com");
        assert_eq!(reopened.passkeys[0].credential_id, item.credential_id);
        assert_eq!(reopened.passkeys[0].public_key, item.public_key);

        std::fs::remove_file(path).unwrap();
    }

    #[cfg(feature = "core-integration")]
    fn temp_vault_path(name: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "mlocker-desktop-{name}-{}-{nanos}.vault",
            std::process::id()
        ))
    }
}
