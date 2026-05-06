use anyhow::{bail, Result};
use mlocker_core::{
    derive_ethereum_account, derive_password as derive_password_from_root,
    derive_password_from_mnemonic, derive_solana_account, parse_mnemonic,
    PasswordDerivationRequest, PasswordOptions, RootKey, DEFAULT_APP_DOMAIN,
};
use serde::Serialize;

use crate::cli::Chain;

pub const DEFAULT_PASSWORD_PATH: &str = "m/passwords/0";

pub fn derive_password(
    mnemonic: &str,
    site: &str,
    username: &str,
    path: Option<&str>,
) -> Result<String> {
    if mnemonic.trim().is_empty() {
        bail!("mnemonic must not be empty");
    }
    if site.trim().is_empty() {
        bail!("site must not be empty");
    }
    if username.trim().is_empty() {
        bail!("username must not be empty");
    }

    let recovery = parse_mnemonic(mnemonic)?;
    let site = site.trim().to_ascii_lowercase();
    let request = PasswordDerivationRequest::new(
        path.unwrap_or(DEFAULT_PASSWORD_PATH),
        site,
        username.trim(),
    )
    .with_options(PasswordOptions {
        length: 24,
        symbols: PasswordOptions::default().symbols,
    });
    Ok(derive_password_from_mnemonic(
        &recovery,
        DEFAULT_APP_DOMAIN,
        &request,
    )?)
}

pub fn derive_password_with_root_key(
    root_key: &RootKey,
    site: &str,
    username: &str,
    path: Option<&str>,
) -> Result<String> {
    if site.trim().is_empty() {
        bail!("site must not be empty");
    }
    if username.trim().is_empty() {
        bail!("username must not be empty");
    }

    let site = site.trim().to_ascii_lowercase();
    let request = PasswordDerivationRequest::new(
        path.unwrap_or(DEFAULT_PASSWORD_PATH),
        site,
        username.trim(),
    )
    .with_options(PasswordOptions {
        length: 24,
        symbols: PasswordOptions::default().symbols,
    });
    Ok(derive_password_from_root(root_key, &request)?)
}

#[derive(Debug, Serialize)]
pub struct WalletInfo {
    pub chain: &'static str,
    pub index: u32,
    pub path: String,
    pub address: String,
    pub public_key: String,
}

pub fn derive_wallet(mnemonic: &str, chain: Chain, index: u32) -> Result<WalletInfo> {
    if mnemonic.trim().is_empty() {
        bail!("mnemonic must not be empty");
    }

    let recovery = parse_mnemonic(mnemonic)?;
    let (chain_name, account) = match chain {
        Chain::Ethereum => ("ethereum", derive_ethereum_account(&recovery, index)?),
        Chain::Solana => ("solana", derive_solana_account(&recovery, index)?),
    };

    Ok(WalletInfo {
        chain: chain_name,
        index,
        path: account.derivation_path,
        address: account.address,
        public_key: account.public_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn password_derivation_is_deterministic() {
        let first = derive_password(MNEMONIC, "Example.com", "alice", None).unwrap();
        let second = derive_password(MNEMONIC, "Example.com", "alice", None).unwrap();

        assert_eq!(first, second);
        assert_eq!(first.len(), 24);
        assert!(first.chars().any(|ch| ch.is_ascii_uppercase()));
        assert!(first.chars().any(|ch| ch.is_ascii_lowercase()));
        assert!(first.chars().any(|ch| ch.is_ascii_digit()));
    }

    #[test]
    fn password_path_changes_output() {
        let default_password = derive_password(MNEMONIC, "example.com", "alice", None).unwrap();
        let custom_password =
            derive_password(MNEMONIC, "example.com", "alice", Some("m/custom/1")).unwrap();

        assert_ne!(default_password, custom_password);
    }

    #[test]
    fn wallet_derivation_is_deterministic() {
        let first = derive_wallet(MNEMONIC, Chain::Ethereum, 0).unwrap();
        let second = derive_wallet(MNEMONIC, Chain::Ethereum, 0).unwrap();

        assert_eq!(first.address, second.address);
        assert!(first.address.starts_with("0x"));
        assert!(!first.public_key.is_empty());
    }
}
