use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::{
    error::{MlockerCoreError, Result},
    keys::{context_hash, derive_root_key, RootKey},
    mnemonic::RecoveryPhrase,
};

const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const DEFAULT_SYMBOLS: &str = "!@#$%^&*()-_=+[]{}:,.?";
const MIN_PASSWORD_LENGTH: usize = 12;
const MAX_PASSWORD_LENGTH: usize = 128;

/// Options for deterministic printable password generation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PasswordOptions {
    pub length: usize,
    pub symbols: String,
}

/// Backward-compatible name for downstream UI policy wiring.
pub type PasswordPolicy = PasswordOptions;

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 20,
            symbols: DEFAULT_SYMBOLS.to_owned(),
        }
    }
}

/// Context that identifies a deterministic password.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PasswordDerivationRequest {
    pub derivation_path: String,
    pub site: String,
    pub username: String,
    pub options: PasswordOptions,
}

impl PasswordDerivationRequest {
    pub fn new(
        derivation_path: impl Into<String>,
        site: impl Into<String>,
        username: impl Into<String>,
    ) -> Self {
        Self {
            derivation_path: derivation_path.into(),
            site: site.into(),
            username: username.into(),
            options: PasswordOptions::default(),
        }
    }

    pub fn with_options(mut self, options: PasswordOptions) -> Self {
        self.options = options;
        self
    }
}

/// Derives a deterministic password from a mnemonic-derived root key.
pub fn derive_password(root_key: &RootKey, request: &PasswordDerivationRequest) -> Result<String> {
    validate_options(&request.options)?;

    let length = request.options.length;
    let length_part = length.to_string();
    let salt = context_hash(
        "mlocker-core/password/v1",
        &[
            request.derivation_path.trim(),
            request.site.trim(),
            request.username.trim(),
            request.options.symbols.as_str(),
            length_part.as_str(),
        ],
    );
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), root_key.as_bytes());
    let mut material = vec![0u8; length * 2 + 32];
    hkdf.expand(b"deterministic-password", &mut material)
        .map_err(|err| MlockerCoreError::KeyDerivation(err.to_string()))?;

    let symbols = request.options.symbols.as_bytes();
    let mut all =
        Vec::with_capacity(LOWERCASE.len() + UPPERCASE.len() + DIGITS.len() + symbols.len());
    all.extend_from_slice(LOWERCASE);
    all.extend_from_slice(UPPERCASE);
    all.extend_from_slice(DIGITS);
    all.extend_from_slice(symbols);

    let mut chars = Vec::with_capacity(length);
    chars.push(pick(LOWERCASE, material[0]));
    chars.push(pick(UPPERCASE, material[1]));
    chars.push(pick(DIGITS, material[2]));
    chars.push(pick(symbols, material[3]));

    for byte in material.iter().take(length).skip(4) {
        chars.push(pick(&all, *byte));
    }

    let mut cursor = length;
    for index in (1..chars.len()).rev() {
        let swap_with = material[cursor] as usize % (index + 1);
        chars.swap(index, swap_with);
        cursor += 1;
    }

    let password = chars.into_iter().collect();
    material.zeroize();
    Ok(password)
}

/// Derives a deterministic password directly from a mnemonic and app domain.
pub fn derive_password_from_mnemonic(
    mnemonic: &RecoveryPhrase,
    app_domain: &str,
    request: &PasswordDerivationRequest,
) -> Result<String> {
    let root = derive_root_key(mnemonic, app_domain)?;
    derive_password(&root, request)
}

fn validate_options(options: &PasswordOptions) -> Result<()> {
    if options.length < MIN_PASSWORD_LENGTH {
        return Err(MlockerCoreError::InvalidPasswordOptions(format!(
            "length must be at least {MIN_PASSWORD_LENGTH}"
        )));
    }
    if options.length > MAX_PASSWORD_LENGTH {
        return Err(MlockerCoreError::InvalidPasswordOptions(format!(
            "length must be at most {MAX_PASSWORD_LENGTH}"
        )));
    }
    if options.symbols.is_empty() {
        return Err(MlockerCoreError::InvalidPasswordOptions(
            "at least one symbol is required".to_owned(),
        ));
    }
    if !options.symbols.is_ascii() || options.symbols.chars().any(char::is_whitespace) {
        return Err(MlockerCoreError::InvalidPasswordOptions(
            "symbols must be printable non-whitespace ASCII".to_owned(),
        ));
    }

    Ok(())
}

fn pick(charset: &[u8], byte: u8) -> char {
    charset[byte as usize % charset.len()] as char
}
