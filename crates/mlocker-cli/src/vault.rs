use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use mlocker_core::{
    derive_root_key, derive_vault_key, derive_vault_key_from_mnemonic, normalize_totp_secret,
    parse_mnemonic, CloudDriveProvider, EncryptedVaultSync, FolderSyncTarget, LoginPassword,
    PasskeyMetadata, RootKey, SshKeyMetadata, TotpMetadata, Vault, VaultKey, VaultStore,
    WalletAccountMetadata, DEFAULT_APP_DOMAIN, DEFAULT_TOTP_DIGITS, DEFAULT_TOTP_PERIOD,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};

const DEFAULT_VAULT_CONTEXT: &str = "default";
const DEFAULT_LOGIN_PATH_PREFIX: &str = "m/passwords";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultState {
    pub items: Vec<LoginItem>,
    #[serde(default)]
    wallet_accounts: Vec<WalletAccountMetadata>,
    #[serde(default)]
    ssh_keys: Vec<SshKeyMetadata>,
    #[serde(default)]
    passkeys: Vec<PasskeyMetadata>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LoginItem {
    pub id: String,
    pub title: String,
    pub username: String,
    pub url: String,
    pub password: LoginPassword,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub totp: Option<TotpMetadata>,
}

#[derive(Debug)]
pub struct UnlockedVault {
    pub state: VaultState,
    pub root_key: RootKey,
    pub mnemonic: Option<String>,
}

impl VaultState {
    pub fn empty() -> Self {
        Self {
            items: Vec::new(),
            wallet_accounts: Vec::new(),
            ssh_keys: Vec::new(),
            passkeys: Vec::new(),
        }
    }

    pub fn find_login(&self, query: &str) -> Result<&LoginItem> {
        let index = self.find_login_index(query)?;
        Ok(&self.items[index])
    }

    pub fn find_login_index(&self, query: &str) -> Result<usize> {
        let needle = query.trim().to_ascii_lowercase();
        if needle.is_empty() {
            bail!("query must not be empty");
        }

        let exact_matches: Vec<_> = self
            .items
            .iter()
            .enumerate()
            .filter(|(_, item)| {
                item.id.eq_ignore_ascii_case(query)
                    || item.title.eq_ignore_ascii_case(query)
                    || item.url.eq_ignore_ascii_case(query)
            })
            .map(|(index, _)| index)
            .collect();
        if !exact_matches.is_empty() {
            return single_match(query, exact_matches);
        }

        let contains_matches: Vec<_> = self
            .items
            .iter()
            .enumerate()
            .filter(|(_, item)| {
                item.title.to_ascii_lowercase().contains(&needle)
                    || item.url.to_ascii_lowercase().contains(&needle)
            })
            .map(|(index, _)| index)
            .collect();
        single_match(query, contains_matches)
    }

    pub fn ssh_keys(&self) -> &[SshKeyMetadata] {
        &self.ssh_keys
    }

    fn from_core(vault: Vault) -> Self {
        Self {
            items: vault
                .logins
                .into_iter()
                .map(|item| LoginItem {
                    id: item.id,
                    title: item.title,
                    username: item.username,
                    url: item.site_url,
                    password: item.password,
                    notes: item.notes,
                    totp: item.totp,
                })
                .collect(),
            wallet_accounts: vault.wallet_accounts,
            ssh_keys: vault.ssh_keys,
            passkeys: vault.passkeys,
        }
    }

    fn into_core(self) -> Vault {
        Vault {
            logins: self
                .items
                .into_iter()
                .map(|item| mlocker_core::LoginItem {
                    id: item.id,
                    title: item.title,
                    site_url: item.url,
                    username: item.username,
                    password: item.password,
                    notes: item.notes,
                    totp: item.totp,
                })
                .collect(),
            wallet_accounts: self.wallet_accounts,
            ssh_keys: self.ssh_keys,
            passkeys: self.passkeys,
        }
    }
}

pub fn create_vault(path: &Path, mnemonic: &str) -> Result<()> {
    if path.exists() {
        bail!("vault already exists at {}", path.display());
    }

    save_vault(path, mnemonic, &VaultState::empty())
}

pub fn create_password_vault(path: &Path, mnemonic: &str, password: &str) -> Result<()> {
    if path.exists() {
        bail!("vault already exists at {}", path.display());
    }
    let recovery = parse_mnemonic(mnemonic)?;
    let root_key = derive_root_key(&recovery, DEFAULT_APP_DOMAIN)?;
    let blob = Vault::default().encrypt_with_password(
        &root_key,
        DEFAULT_VAULT_CONTEXT,
        DEFAULT_APP_DOMAIN,
        password,
    )?;
    VaultStore::new(path)
        .save_blob(&blob)
        .with_context(|| format!("write encrypted vault {}", path.display()))
}

#[cfg(test)]
pub fn load_vault(path: &Path, mnemonic: &str) -> Result<VaultState> {
    let store = VaultStore::new(path);
    let blob = store
        .load_blob()
        .with_context(|| format!("load encrypted vault {}", path.display()))?;
    let key = vault_key(mnemonic)?;
    let vault = blob
        .decrypt(&key)
        .with_context(|| "failed to decrypt vault; check MLOCKER_MNEMONIC")?;
    Ok(VaultState::from_core(vault))
}

pub fn unlock_vault(
    path: &Path,
    mnemonic: Option<&str>,
    password: Option<&str>,
) -> Result<UnlockedVault> {
    let store = VaultStore::new(path);
    let blob = store
        .load_blob()
        .with_context(|| format!("load encrypted vault {}", path.display()))?;

    if let Some(password) = password.filter(|password| !password.is_empty()) {
        if !blob.is_password_protected() {
            bail!("vault is not password-protected; set MLOCKER_MNEMONIC instead");
        }
        let (vault, root_key) = blob
            .decrypt_with_password(DEFAULT_VAULT_CONTEXT, DEFAULT_APP_DOMAIN, password)
            .with_context(|| "failed to decrypt vault; check MLOCKER_PASSWORD")?;
        if let Some(mnemonic) = mnemonic {
            let recovery = parse_mnemonic(mnemonic)?;
            let expected = derive_root_key(&recovery, DEFAULT_APP_DOMAIN)?;
            if expected != root_key {
                bail!("MLOCKER_MNEMONIC does not match the password-protected vault");
            }
        }
        return Ok(UnlockedVault {
            state: VaultState::from_core(vault),
            root_key,
            mnemonic: mnemonic.map(str::to_owned),
        });
    }

    let mnemonic = mnemonic.ok_or_else(|| {
        anyhow!("set MLOCKER_MNEMONIC or MLOCKER_PASSWORD to unlock this MVP vault")
    })?;
    let recovery = parse_mnemonic(mnemonic)?;
    let root_key = derive_root_key(&recovery, DEFAULT_APP_DOMAIN)?;
    let key = derive_vault_key(&root_key, DEFAULT_VAULT_CONTEXT, DEFAULT_APP_DOMAIN)?;
    let vault = blob
        .decrypt(&key)
        .with_context(|| "failed to decrypt vault; check MLOCKER_MNEMONIC")?;
    Ok(UnlockedVault {
        state: VaultState::from_core(vault),
        root_key,
        mnemonic: Some(mnemonic.to_owned()),
    })
}

pub fn save_vault(path: &Path, mnemonic: &str, state: &VaultState) -> Result<()> {
    let key = vault_key(mnemonic)?;
    let blob = state.clone().into_core().encrypt(&key)?;
    let store = VaultStore::new(path);
    store
        .save_blob(&blob)
        .with_context(|| format!("write encrypted vault {}", path.display()))
}

pub fn save_unlocked_vault(path: &Path, unlocked: &UnlockedVault) -> Result<()> {
    let store = VaultStore::new(path);
    let master_key_envelope = store
        .load_blob()
        .ok()
        .and_then(|blob| blob.master_key_envelope);
    let key = derive_vault_key(
        &unlocked.root_key,
        DEFAULT_VAULT_CONTEXT,
        DEFAULT_APP_DOMAIN,
    )?;
    let mut blob = unlocked.state.clone().into_core().encrypt(&key)?;
    blob.master_key_envelope = master_key_envelope;
    store
        .save_blob(&blob)
        .with_context(|| format!("write encrypted vault {}", path.display()))
}

pub fn add_login(
    state: &mut VaultState,
    title: String,
    username: String,
    url: String,
    path: Option<String>,
    password: Option<String>,
    totp: Option<String>,
) -> Result<LoginItem> {
    validate_non_empty("title", &title)?;
    validate_non_empty("username", &username)?;
    validate_non_empty("url", &url)?;

    let password = match password {
        Some(password) => {
            if path.is_some() {
                bail!("path applies only to mnemonic-derived passwords");
            }
            validate_non_empty("password", &password)?;
            LoginPassword::user_input(password)
        }
        None => LoginPassword::mnemonic_derived(
            path.unwrap_or_else(|| format!("{DEFAULT_LOGIN_PATH_PREFIX}/{}", state.items.len())),
        ),
    };

    let item = LoginItem {
        id: new_item_id(),
        title,
        username,
        url,
        password,
        notes: None,
        totp: totp
            .map(|secret| {
                normalize_totp_secret(&secret).map(|secret| TotpMetadata {
                    secret,
                    period: DEFAULT_TOTP_PERIOD,
                    digits: DEFAULT_TOTP_DIGITS,
                })
            })
            .transpose()?,
    };

    state.items.push(item.clone());
    Ok(item)
}

#[derive(Debug, Default)]
pub struct EditLoginRequest {
    pub title: Option<String>,
    pub username: Option<String>,
    pub url: Option<String>,
    pub path: Option<String>,
    pub password: Option<String>,
    pub totp: Option<String>,
    pub clear_totp: bool,
}

impl EditLoginRequest {
    fn has_changes(&self) -> bool {
        self.title.is_some()
            || self.username.is_some()
            || self.url.is_some()
            || self.path.is_some()
            || self.password.is_some()
            || self.totp.is_some()
            || self.clear_totp
    }
}

pub fn edit_login(
    state: &mut VaultState,
    query: &str,
    request: EditLoginRequest,
) -> Result<LoginItem> {
    if !request.has_changes() {
        bail!("at least one edit option is required");
    }
    if request.totp.is_some() && request.clear_totp {
        bail!("totp and clear-totp cannot be used together");
    }

    let index = state.find_login_index(query)?;
    let item = &mut state.items[index];

    if let Some(title) = request.title {
        validate_non_empty("title", &title)?;
        item.title = title;
    }
    if let Some(username) = request.username {
        validate_non_empty("username", &username)?;
        item.username = username;
    }
    if let Some(url) = request.url {
        validate_non_empty("url", &url)?;
        item.url = url;
    }
    if let Some(path) = request.path {
        validate_non_empty("path", &path)?;
        item.password = LoginPassword::mnemonic_derived(path);
    }
    if let Some(password) = request.password {
        validate_non_empty("password", &password)?;
        item.password = LoginPassword::user_input(password);
    }
    if let Some(secret) = request.totp {
        item.totp = Some(totp_metadata(secret)?);
    }
    if request.clear_totp {
        item.totp = None;
    }

    Ok(item.clone())
}

pub fn delete_login(state: &mut VaultState, query: &str) -> Result<LoginItem> {
    let index = state.find_login_index(query)?;
    Ok(state.items.remove(index))
}

#[derive(Debug)]
pub struct ImportLoginRequest {
    pub title: String,
    pub username: String,
    pub url: String,
    pub password: String,
    pub notes: Option<String>,
    pub totp: Option<String>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ImportLoginsSummary {
    pub created: usize,
    pub updated: usize,
}

pub fn import_logins(
    state: &mut VaultState,
    logins: Vec<ImportLoginRequest>,
) -> Result<ImportLoginsSummary> {
    let mut summary = ImportLoginsSummary::default();

    for login in logins {
        validate_non_empty("title", &login.title)?;
        validate_non_empty("username", &login.username)?;
        validate_non_empty("url", &login.url)?;
        validate_non_empty("password", &login.password)?;
        let totp = login.totp.map(totp_metadata).transpose()?;

        if let Some(existing) = state.items.iter_mut().find(|item| {
            item.url.eq_ignore_ascii_case(&login.url)
                && item.username.eq_ignore_ascii_case(&login.username)
        }) {
            existing.title = login.title;
            existing.password = LoginPassword::user_input(login.password);
            existing.notes = login.notes;
            existing.totp = totp;
            summary.updated += 1;
        } else {
            state.items.push(LoginItem {
                id: new_item_id(),
                title: login.title,
                username: login.username,
                url: login.url,
                password: LoginPassword::user_input(login.password),
                notes: login.notes,
                totp,
            });
            summary.created += 1;
        }
    }

    Ok(summary)
}

pub fn copy_export(vault: &Path, cloud_dir: &Path) -> Result<PathBuf> {
    let blob = VaultStore::new(vault)
        .load_blob()
        .with_context(|| format!("load encrypted vault {}", vault.display()))?;
    let sync = FolderSyncTarget::new(CloudDriveProvider::LocalFolder, cloud_dir);
    sync.export_blob(vault_file_name(vault)?, &blob)
        .with_context(|| format!("export encrypted vault to {}", cloud_dir.display()))
}

pub fn copy_import(vault: &Path, cloud_dir: &Path) -> Result<PathBuf> {
    let sync = FolderSyncTarget::new(CloudDriveProvider::LocalFolder, cloud_dir);
    let blob_name = vault_file_name(vault)?;
    let blob = sync
        .import_blob(blob_name)
        .with_context(|| format!("import encrypted vault from {}", cloud_dir.display()))?;
    VaultStore::new(vault)
        .save_blob(&blob)
        .with_context(|| format!("write encrypted vault {}", vault.display()))?;
    sync.blob_path(blob_name).map_err(Into::into)
}

fn vault_key(mnemonic: &str) -> Result<VaultKey> {
    let recovery = parse_mnemonic(mnemonic)?;
    derive_vault_key_from_mnemonic(&recovery, "", DEFAULT_VAULT_CONTEXT, DEFAULT_APP_DOMAIN)
        .map_err(Into::into)
}

fn validate_non_empty(name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        bail!("{name} must not be empty");
    }
    Ok(())
}

fn single_match(query: &str, matches: Vec<usize>) -> Result<usize> {
    match matches.as_slice() {
        [] => bail!("no item matched query '{query}'"),
        [index] => Ok(*index),
        _ => bail!("query '{query}' matched multiple items"),
    }
}

fn totp_metadata(secret: String) -> Result<TotpMetadata> {
    Ok(normalize_totp_secret(&secret).map(|secret| TotpMetadata {
        secret,
        period: DEFAULT_TOTP_PERIOD,
        digits: DEFAULT_TOTP_DIGITS,
    })?)
}

fn new_item_id() -> String {
    let mut bytes = [0_u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn vault_file_name(vault: &Path) -> Result<&str> {
    vault
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .ok_or_else(|| anyhow!("vault path must include a UTF-8 file name"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn vault_round_trip_keeps_login_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("vault.blob");

        create_vault(&vault_path, MNEMONIC).unwrap();
        let mut state = load_vault(&vault_path, MNEMONIC).unwrap();
        add_login(
            &mut state,
            "Example".to_string(),
            "alice".to_string(),
            "https://example.com".to_string(),
            None,
            None,
            None,
        )
        .unwrap();
        save_vault(&vault_path, MNEMONIC, &state).unwrap();

        let state = load_vault(&vault_path, MNEMONIC).unwrap();
        let item = state.find_login("example").unwrap();

        assert_eq!(item.title, "Example");
        assert_eq!(item.username, "alice");
        assert_eq!(item.password.path(), Some("m/passwords/0"));
    }

    #[test]
    fn wrong_mnemonic_does_not_decrypt() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("vault.blob");

        create_vault(&vault_path, MNEMONIC).unwrap();

        assert!(load_vault(
            &vault_path,
            "legal winner thank year wave sausage worth useful legal winner thank yellow"
        )
        .is_err());
    }
}
