//! Core cryptographic and persistence APIs for the mlocker password manager MVP.
//!
//! This crate intentionally keeps IO and UI concerns small. CLI and desktop layers
//! can build on these types to derive keys, generate deterministic passwords,
//! persist encrypted vault blobs, and expose wallet or SSH helpers.

mod derivation;
mod error;
mod keys;
mod mnemonic;
mod passkey;
mod password;
mod ssh;
mod sync;
mod totp;
mod vault;
mod wallet;

pub use error::{MlockerCoreError, Result};
pub use keys::{
    derive_root_key, derive_root_key_with_passphrase, derive_vault_key,
    derive_vault_key_from_mnemonic, RootKey, VaultKey, DEFAULT_APP_DOMAIN,
};
pub use mnemonic::{generate_mnemonic, parse_mnemonic, RecoveryPhrase};
pub use passkey::{derive_passkey_from_root_key, DerivedPasskey, DEFAULT_PASSKEY_DERIVATION_PATH};
pub use password::{
    derive_password, derive_password_from_mnemonic, PasswordDerivationRequest, PasswordOptions,
    PasswordPolicy,
};
pub use ssh::{
    derive_ssh_key, derive_ssh_key_from_root_key, derive_ssh_private_key_seed,
    derive_ssh_private_key_seed_from_root_key, sign_ssh_data_from_root_key, DerivedSshKey,
    DEFAULT_SSH_DERIVATION_PATH,
};
pub use sync::{CloudDriveProvider, EncryptedVaultSync, FolderSyncTarget, DEFAULT_VAULT_BLOB_NAME};
pub use totp::{
    generate_totp, generate_totp_now, normalize_totp_secret, TotpCode, DEFAULT_TOTP_DIGITS,
    DEFAULT_TOTP_PERIOD,
};
pub use vault::{
    EncryptedVaultBlob, LoginItem, LoginPassword, MasterKeyEnvelope, PasskeyMetadata,
    PasswordKdfParams, SshKeyMetadata, TotpMetadata, Vault, VaultStore, WalletAccountMetadata,
    ENCRYPTED_VAULT_BLOB_VERSION,
};
pub use wallet::{
    derive_ethereum_account, derive_ethereum_account_with_passphrase, derive_ethereum_private_key,
    derive_solana_account, derive_solana_account_with_passphrase, derive_solana_private_key_seed,
    derive_wallet_account, Chain, DerivedWalletAccount, WalletNetwork,
};

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const OTHER_MNEMONIC: &str =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";
    const TEST_DOMAIN: &str = "app.mlocker.test";
    const TEST_VAULT_PATH: &str = "personal";

    #[test]
    fn deterministic_password_is_stable_and_strong() {
        let mnemonic = parse_mnemonic(TEST_MNEMONIC).unwrap();
        let root = derive_root_key(&mnemonic, TEST_DOMAIN).unwrap();
        let request = PasswordDerivationRequest::new(
            "m/passwords/0",
            "https://example.com/login",
            "alice@example.com",
        );

        let password = derive_password(&root, &request).unwrap();
        let repeated = derive_password(&root, &request).unwrap();

        assert_eq!(password, repeated);
        assert_eq!(password.len(), PasswordOptions::default().length);
        assert!(password.chars().any(|c| c.is_ascii_lowercase()));
        assert!(password.chars().any(|c| c.is_ascii_uppercase()));
        assert!(password.chars().any(|c| c.is_ascii_digit()));
        assert!(password
            .chars()
            .any(|c| PasswordOptions::default().symbols.contains(c)));
    }

    #[test]
    fn vault_encrypt_decrypt_roundtrip() {
        let mnemonic = parse_mnemonic(TEST_MNEMONIC).unwrap();
        let key =
            derive_vault_key_from_mnemonic(&mnemonic, "", TEST_VAULT_PATH, TEST_DOMAIN).unwrap();
        let vault = sample_vault();

        let blob = vault.encrypt(&key).unwrap();
        assert_eq!(blob.version, ENCRYPTED_VAULT_BLOB_VERSION);
        assert!(!blob.nonce.is_empty());
        assert!(!blob.ciphertext.is_empty());

        let decrypted = blob.decrypt(&key).unwrap();
        assert_eq!(decrypted, vault);
    }

    #[test]
    fn login_password_path_is_nested_under_password() {
        let login = &sample_vault().logins[0];
        let json = serde_json::to_value(login).unwrap();

        assert!(json.get("password_derivation_path").is_none());
        assert_eq!(json["password"]["type"], "mnemonic_derived");
        assert_eq!(json["password"]["path"], "m/passwords/0");
    }

    #[test]
    fn login_password_reads_legacy_derivation_path() {
        let json = serde_json::json!({
            "id": "legacy",
            "title": "Legacy",
            "site_url": "https://legacy.example",
            "username": "alice",
            "password_derivation_path": "m/passwords/7"
        });

        let item: LoginItem = serde_json::from_value(json).unwrap();

        assert_eq!(item.password.path(), Some("m/passwords/7"));
    }

    #[test]
    fn password_envelope_wraps_mnemonic_master_key() {
        let mnemonic = parse_mnemonic(TEST_MNEMONIC).unwrap();
        let master_key = derive_root_key(&mnemonic, TEST_DOMAIN).unwrap();
        let vault = sample_vault();

        let blob = vault
            .encrypt_with_password(&master_key, TEST_VAULT_PATH, TEST_DOMAIN, "local-password")
            .unwrap();

        assert!(blob.is_password_protected());
        let envelope = blob.master_key_envelope.as_ref().unwrap();
        assert_eq!(envelope.method, "password");
        assert_eq!(envelope.kdf.algorithm, "PBKDF2-HMAC-SHA256");
        assert!(envelope.kdf.iterations >= 600_000);

        let json = blob.to_json_pretty().unwrap();
        assert!(json.contains("master_key_envelope"));
        assert!(json.contains("PBKDF2-HMAC-SHA256"));
        assert!(!json.contains("local-password"));

        let (decrypted, unwrapped_key) = blob
            .decrypt_with_password(TEST_VAULT_PATH, TEST_DOMAIN, "local-password")
            .unwrap();
        assert_eq!(decrypted, vault);
        assert_eq!(unwrapped_key, master_key);
        assert!(blob
            .decrypt_with_password(TEST_VAULT_PATH, TEST_DOMAIN, "wrong-password")
            .is_err());
    }

    #[test]
    fn wrong_mnemonic_fails_to_decrypt_vault() {
        let mnemonic = parse_mnemonic(TEST_MNEMONIC).unwrap();
        let wrong_mnemonic = parse_mnemonic(OTHER_MNEMONIC).unwrap();
        let key =
            derive_vault_key_from_mnemonic(&mnemonic, "", TEST_VAULT_PATH, TEST_DOMAIN).unwrap();
        let wrong_key =
            derive_vault_key_from_mnemonic(&wrong_mnemonic, "", TEST_VAULT_PATH, TEST_DOMAIN)
                .unwrap();

        let blob = sample_vault().encrypt(&key).unwrap();

        assert!(blob.decrypt(&wrong_key).is_err());
    }

    #[test]
    fn wallet_derivation_is_stable() {
        let mnemonic = parse_mnemonic(TEST_MNEMONIC).unwrap();

        let eth = derive_ethereum_account(&mnemonic, 0).unwrap();
        let eth_again = derive_ethereum_account(&mnemonic, 0).unwrap();
        assert_eq!(eth, eth_again);
        assert_eq!(eth.network, WalletNetwork::Ethereum);
        assert_eq!(eth.derivation_path, "m/44'/60'/0'/0/0");
        assert_eq!(eth.address, "0x9858EfFD232B4033E47d90003D41EC34EcaEda94");

        let sol = derive_solana_account(&mnemonic, 0).unwrap();
        let sol_again = derive_solana_account(&mnemonic, 0).unwrap();
        assert_eq!(sol, sol_again);
        assert_eq!(sol.network, WalletNetwork::Solana);
        assert_eq!(sol.derivation_path, "m/44'/501'/0'/0'");
        assert!(!sol.address.is_empty());
        assert_eq!(sol.address, sol.public_key);
    }

    #[test]
    fn root_key_ssh_signature_verifies_against_public_key() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let mnemonic = parse_mnemonic(TEST_MNEMONIC).unwrap();
        let root = derive_root_key(&mnemonic, TEST_DOMAIN).unwrap();
        let key = derive_ssh_key_from_root_key(&root, DEFAULT_SSH_DERIVATION_PATH, "mlocker-test")
            .unwrap();
        let data = b"ssh-agent challenge";

        let signature_bytes =
            sign_ssh_data_from_root_key(&root, DEFAULT_SSH_DERIVATION_PATH, data).unwrap();

        let public_key: [u8; 32] = STANDARD
            .decode(key.public_key_base64)
            .unwrap()
            .try_into()
            .unwrap();
        let verifying_key = VerifyingKey::from_bytes(&public_key).unwrap();
        let signature = Signature::from_bytes(&signature_bytes);
        verifying_key.verify(data, &signature).unwrap();
    }

    #[test]
    fn root_key_passkey_derivation_is_stable() {
        let mnemonic = parse_mnemonic(TEST_MNEMONIC).unwrap();
        let root = derive_root_key(&mnemonic, TEST_DOMAIN).unwrap();

        let first = derive_passkey_from_root_key(
            &root,
            DEFAULT_PASSKEY_DERIVATION_PATH,
            "example.com",
            "alice",
        )
        .unwrap();
        let second = derive_passkey_from_root_key(
            &root,
            DEFAULT_PASSKEY_DERIVATION_PATH,
            "example.com",
            "alice",
        )
        .unwrap();

        assert_eq!(first, second);
        assert_eq!(first.algorithm, "EdDSA");
        assert!(!first.credential_id.is_empty());
        assert!(!first.public_key.is_empty());
    }

    #[test]
    fn totp_matches_rfc6238_sha1_vector() {
        let code = generate_totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59, 30, 8).unwrap();

        assert_eq!(code.code, "94287082");
        assert_eq!(code.seconds_remaining, 1);
    }

    #[test]
    fn folder_sync_exports_and_imports_encrypted_blob() {
        let mnemonic = parse_mnemonic(TEST_MNEMONIC).unwrap();
        let key =
            derive_vault_key_from_mnemonic(&mnemonic, "", TEST_VAULT_PATH, TEST_DOMAIN).unwrap();
        let blob = sample_vault().encrypt(&key).unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let sync = FolderSyncTarget::new(CloudDriveProvider::LocalFolder, temp_dir.path());

        let path = sync.export_default(&blob).unwrap();
        let imported = sync.import_default().unwrap();

        assert_eq!(path.file_name().unwrap(), DEFAULT_VAULT_BLOB_NAME);
        assert_eq!(imported, blob);
    }

    fn sample_vault() -> Vault {
        Vault {
            logins: vec![LoginItem {
                id: "login-example".to_owned(),
                title: "Example".to_owned(),
                site_url: "https://example.com".to_owned(),
                username: "alice@example.com".to_owned(),
                password: LoginPassword::mnemonic_derived("m/passwords/0"),
                notes: Some("seeded deterministic login".to_owned()),
                totp: Some(TotpMetadata {
                    secret: "JBSWY3DPEHPK3PXP".to_owned(),
                    period: DEFAULT_TOTP_PERIOD,
                    digits: DEFAULT_TOTP_DIGITS,
                }),
            }],
            wallet_accounts: vec![WalletAccountMetadata {
                id: "eth-0".to_owned(),
                label: "Ethereum 0".to_owned(),
                network: "ethereum".to_owned(),
                address: "0x9858EfFD232B4033E47d90003D41EC34EcaEda94".to_owned(),
                derivation_path: "m/44'/60'/0'/0/0".to_owned(),
                public_key: None,
            }],
            ssh_keys: vec![SshKeyMetadata {
                id: "ssh-main".to_owned(),
                label: "Main SSH".to_owned(),
                derivation_path: DEFAULT_SSH_DERIVATION_PATH.to_owned(),
                public_key: "ssh-ed25519 AAAA...".to_owned(),
                comment: Some("alice@mlocker".to_owned()),
            }],
            passkeys: vec![PasskeyMetadata {
                id: "passkey-example".to_owned(),
                label: "Example Passkey".to_owned(),
                relying_party_id: "example.com".to_owned(),
                username: "alice@example.com".to_owned(),
                credential_id: "credential-id".to_owned(),
                public_key: "public-key".to_owned(),
                algorithm: "EdDSA".to_owned(),
                derivation_path: DEFAULT_PASSKEY_DERIVATION_PATH.to_owned(),
                notes: Some("webauthn mediation pending".to_owned()),
            }],
        }
    }
}
