use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::cli::BrowserKind;
use crate::inject::login_password_value;
use crate::vault::{self, LoginItem};

const HOST_NAME: &str = "com.mlocker.native";
const MNEMONIC_ENV: &str = "MLOCKER_MNEMONIC";
const PASSWORD_ENV: &str = "MLOCKER_PASSWORD";
const MAX_NATIVE_MESSAGE_SIZE: u32 = 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
pub struct BrowserHostConfig {
    pub vault: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum NativeRequest {
    Ping,
    CredentialQuery {
        origin: String,
        #[serde(default)]
        url: Option<String>,
    },
    SaveLogin {
        origin: String,
        url: String,
        #[serde(default)]
        title: Option<String>,
        username: String,
        password: String,
    },
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum NativeResponse {
    Pong { host: &'static str },
    CredentialSuggestions { items: Vec<CredentialSuggestion> },
    SavedLogin { item: CredentialSuggestion },
    Error { message: String },
}

#[derive(Debug, Serialize)]
struct CredentialSuggestion {
    id: String,
    title: String,
    username: String,
    url: String,
    password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    totp: Option<String>,
}

pub fn run_from_default_config(input: &mut impl Read, output: &mut impl Write) -> Result<()> {
    let config_path = default_config_path()?;
    let config = load_config(&config_path)
        .with_context(|| format!("load browser host config {}", config_path.display()))?;
    run_native_host(&config.vault, input, output)
}

pub fn run_native_host(
    vault_path: &Path,
    input: &mut impl Read,
    output: &mut impl Write,
) -> Result<()> {
    while let Some(request) = read_native_message(input)? {
        let response = match handle_request(vault_path, request) {
            Ok(response) => response,
            Err(err) => NativeResponse::Error {
                message: format!("{err:#}"),
            },
        };
        write_native_message(output, &response)?;
    }

    Ok(())
}

pub fn write_config(config_path: Option<&Path>, vault_path: &Path) -> Result<PathBuf> {
    let config_path = match config_path {
        Some(path) => path.to_path_buf(),
        None => default_config_path()?,
    };
    let config = BrowserHostConfig {
        vault: vault_path.to_path_buf(),
    };

    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create config directory {}", parent.display()))?;
    }
    fs::write(&config_path, serde_json::to_string_pretty(&config)?)
        .with_context(|| format!("write browser host config {}", config_path.display()))?;
    Ok(config_path)
}

pub fn render_manifest(
    browser: BrowserKind,
    extension_id: &str,
    host_path: &Path,
) -> Result<String> {
    validate_extension_id(extension_id)?;
    if !host_path.is_absolute() {
        bail!("native host path must be absolute");
    }
    let host_path = host_path.to_string_lossy().into_owned();

    let manifest = match browser {
        BrowserKind::Chrome | BrowserKind::Chromium => json!({
            "name": HOST_NAME,
            "description": "mlocker browser integration native host",
            "path": host_path,
            "type": "stdio",
            "allowed_origins": [format!("chrome-extension://{extension_id}/")]
        }),
        BrowserKind::Firefox => json!({
            "name": HOST_NAME,
            "description": "mlocker browser integration native host",
            "path": host_path,
            "type": "stdio",
            "allowed_extensions": [extension_id]
        }),
    };

    Ok(serde_json::to_string_pretty(&manifest)?)
}

pub fn write_manifest(
    browser: BrowserKind,
    extension_id: &str,
    host_path: &Path,
    manifest_path: &Path,
) -> Result<()> {
    let manifest = render_manifest(browser, extension_id, host_path)?;
    if let Some(parent) = manifest_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create manifest directory {}", parent.display()))?;
    }
    fs::write(manifest_path, manifest).with_context(|| {
        format!(
            "write native messaging manifest {}",
            manifest_path.display()
        )
    })
}

pub fn install_manifest(
    browser: BrowserKind,
    extension_id: &str,
    host_path: &Path,
    manifest_dir: Option<&Path>,
) -> Result<PathBuf> {
    let manifest_dir = match manifest_dir {
        Some(path) => path.to_path_buf(),
        None => default_manifest_dir(browser)?,
    };
    let manifest_path = manifest_dir.join(format!("{HOST_NAME}.json"));
    write_manifest(browser, extension_id, host_path, &manifest_path)?;
    Ok(manifest_path)
}

pub fn default_config_path() -> Result<PathBuf> {
    Ok(home_dir()?.join(".mlocker").join("browser-host.json"))
}

pub fn default_host_executable_path() -> Result<PathBuf> {
    let mut path = std::env::current_exe().context("resolve current executable path")?;
    path.set_file_name(browser_host_binary_name());
    Ok(path)
}

fn load_config(path: &Path) -> Result<BrowserHostConfig> {
    let json = fs::read_to_string(path)?;
    serde_json::from_str(&json).map_err(Into::into)
}

fn handle_request(vault_path: &Path, request: NativeRequest) -> Result<NativeResponse> {
    match request {
        NativeRequest::Ping => Ok(NativeResponse::Pong { host: HOST_NAME }),
        NativeRequest::CredentialQuery { origin, url } => {
            let origin_host = extract_host(&origin)
                .or_else(|| url.as_deref().and_then(extract_host))
                .ok_or_else(|| anyhow!("credential query origin must include a host"))?;
            let unlocked = unlock_vault(vault_path)?;
            let mut items = Vec::new();

            for item in unlocked
                .state
                .items
                .iter()
                .filter(|item| item_matches_host(item, &origin_host))
            {
                items.push(credential_suggestion(item, &unlocked)?);
            }

            items.sort_by(|left, right| {
                exact_host_match(right, &origin_host)
                    .cmp(&exact_host_match(left, &origin_host))
                    .then_with(|| left.title.cmp(&right.title))
                    .then_with(|| left.username.cmp(&right.username))
            });

            Ok(NativeResponse::CredentialSuggestions { items })
        }
        NativeRequest::SaveLogin {
            origin,
            url,
            title,
            username,
            password,
        } => {
            let origin_host = extract_host(&origin)
                .ok_or_else(|| anyhow!("save_login origin must include a host"))?;
            let url_host =
                extract_host(&url).ok_or_else(|| anyhow!("save_login url must include a host"))?;
            if !same_site_or_subdomain(&url_host, &origin_host) {
                bail!("save_login url host must match the page origin");
            }
            let username = username.trim().to_owned();
            if username.is_empty() {
                bail!("save_login username must not be empty");
            }
            if password.is_empty() {
                bail!("save_login password must not be empty");
            }

            let mut unlocked = unlock_vault(vault_path)?;
            let title = title
                .as_deref()
                .map(str::trim)
                .filter(|title| !title.is_empty())
                .unwrap_or(&origin_host)
                .to_owned();
            let item = if let Some(existing) = unlocked.state.items.iter_mut().find(|item| {
                item_matches_host(item, &origin_host)
                    && item.username.eq_ignore_ascii_case(&username)
            }) {
                existing.title = title;
                existing.url = url;
                existing.password = mlocker_core::LoginPassword::user_input(password);
                existing.clone()
            } else {
                vault::add_login(
                    &mut unlocked.state,
                    title,
                    username,
                    url,
                    None,
                    Some(password),
                    None,
                )?
            };
            vault::save_unlocked_vault(vault_path, &unlocked)?;
            Ok(NativeResponse::SavedLogin {
                item: credential_suggestion(&item, &unlocked)?,
            })
        }
    }
}

fn credential_suggestion(
    item: &LoginItem,
    unlocked: &vault::UnlockedVault,
) -> Result<CredentialSuggestion> {
    let password = login_password_value(unlocked, item)?;
    let totp = item
        .totp
        .as_ref()
        .and_then(|totp| mlocker_core::generate_totp_now(&totp.secret).ok())
        .map(|code| code.code);
    Ok(CredentialSuggestion {
        id: item.id.clone(),
        title: item.title.clone(),
        username: item.username.clone(),
        url: item.url.clone(),
        password,
        totp,
    })
}

fn read_native_message(input: &mut impl Read) -> Result<Option<NativeRequest>> {
    let mut len_bytes = [0_u8; 4];
    match input.read_exact(&mut len_bytes) {
        Ok(()) => {}
        Err(err) if err.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err.into()),
    }

    let len = u32::from_le_bytes(len_bytes);
    if len > MAX_NATIVE_MESSAGE_SIZE {
        bail!("native message is too large");
    }

    let mut body = vec![0_u8; len as usize];
    input.read_exact(&mut body)?;
    Ok(Some(serde_json::from_slice(&body)?))
}

fn write_native_message(output: &mut impl Write, response: &NativeResponse) -> Result<()> {
    let body = serde_json::to_vec(response)?;
    let len: u32 = body
        .len()
        .try_into()
        .map_err(|_| anyhow!("native response is too large"))?;
    output.write_all(&len.to_le_bytes())?;
    output.write_all(&body)?;
    output.flush()?;
    Ok(())
}

fn unlock_vault(path: &Path) -> Result<vault::UnlockedVault> {
    let mnemonic = optional_env(MNEMONIC_ENV)?;
    let password = optional_env(PASSWORD_ENV)?;
    vault::unlock_vault(path, mnemonic.as_deref(), password.as_deref())
}

fn optional_env(name: &str) -> Result<Option<String>> {
    match std::env::var(name) {
        Ok(value) if value.trim().is_empty() => bail!("{name} must not be empty"),
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(err) => Err(err).with_context(|| format!("read {name}")),
    }
}

fn item_matches_host(item: &LoginItem, origin_host: &str) -> bool {
    extract_host(&item.url).is_some_and(|item_host| same_site_or_subdomain(origin_host, &item_host))
}

fn exact_host_match(item: &CredentialSuggestion, origin_host: &str) -> bool {
    extract_host(&item.url).is_some_and(|item_host| item_host == origin_host)
}

fn same_site_or_subdomain(host: &str, parent_host: &str) -> bool {
    host == parent_host || host.ends_with(&format!(".{parent_host}"))
}

fn extract_host(input: &str) -> Option<String> {
    let trimmed = input.trim().to_ascii_lowercase();
    if trimmed.is_empty() {
        return None;
    }

    let after_scheme = trimmed
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(trimmed.as_str());
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .rsplit('@')
        .next()
        .unwrap_or_default();
    let host = authority.split(':').next().unwrap_or_default();
    let host = host.strip_prefix("www.").unwrap_or(host).trim();

    (!host.is_empty()).then(|| host.to_owned())
}

fn validate_extension_id(extension_id: &str) -> Result<()> {
    if extension_id.trim().is_empty() {
        bail!("extension id must not be empty");
    }
    if extension_id.contains('/') || extension_id.contains('\\') {
        bail!("extension id must not contain path separators");
    }
    Ok(())
}

fn default_manifest_dir(browser: BrowserKind) -> Result<PathBuf> {
    let home = home_dir()?;
    match (std::env::consts::OS, browser) {
        ("macos", BrowserKind::Chrome) => Ok(home
            .join("Library/Application Support/Google/Chrome/NativeMessagingHosts")),
        ("macos", BrowserKind::Chromium) => Ok(home
            .join("Library/Application Support/Chromium/NativeMessagingHosts")),
        ("macos", BrowserKind::Firefox) => Ok(home
            .join("Library/Application Support/Mozilla/NativeMessagingHosts")),
        ("linux", BrowserKind::Chrome) => Ok(home.join(".config/google-chrome/NativeMessagingHosts")),
        ("linux", BrowserKind::Chromium) => Ok(home.join(".config/chromium/NativeMessagingHosts")),
        ("linux", BrowserKind::Firefox) => Ok(home.join(".mozilla/native-messaging-hosts")),
        ("windows", _) => bail!(
            "automatic native messaging registry install is not implemented on Windows in the CLI; use dist/windows/install-native-host.ps1"
        ),
        (os, _) => bail!("unsupported OS for native host install: {os}"),
    }
}

fn home_dir() -> Result<PathBuf> {
    if let Some(home) = std::env::var_os("HOME").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(home));
    }
    if let Some(home) = std::env::var_os("USERPROFILE").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(home));
    }
    bail!("could not resolve home directory")
}

fn browser_host_binary_name() -> &'static str {
    if cfg!(windows) {
        "mlocker-browser-host.exe"
    } else {
        "mlocker-browser-host"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome_manifest_uses_allowed_origins() {
        let manifest = render_manifest(
            BrowserKind::Chrome,
            "abcdefghijklmnopabcdefghijklmnop",
            Path::new("/usr/local/bin/mlocker-browser-host"),
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&manifest).unwrap();

        assert_eq!(value["name"], HOST_NAME);
        assert_eq!(value["type"], "stdio");
        assert_eq!(
            value["allowed_origins"][0],
            "chrome-extension://abcdefghijklmnopabcdefghijklmnop/"
        );
    }

    #[test]
    fn firefox_manifest_uses_allowed_extensions() {
        let manifest = render_manifest(
            BrowserKind::Firefox,
            "mlocker@example.local",
            Path::new("/usr/local/bin/mlocker-browser-host"),
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&manifest).unwrap();

        assert_eq!(value["allowed_extensions"][0], "mlocker@example.local");
        assert!(value.get("allowed_origins").is_none());
    }

    #[test]
    fn host_matching_allows_subdomains_only() {
        let item = LoginItem {
            id: "1".to_owned(),
            title: "Example".to_owned(),
            username: "alice".to_owned(),
            url: "https://example.com/login".to_owned(),
            password: mlocker_core::LoginPassword::user_input("secret"),
            totp: None,
        };

        assert!(item_matches_host(&item, "example.com"));
        assert!(item_matches_host(&item, "accounts.example.com"));
        assert!(!item_matches_host(&item, "evilexample.com"));
    }
}
