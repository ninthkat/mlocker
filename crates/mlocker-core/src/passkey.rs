use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::{
    derivation::parse_derivation_path,
    error::{MlockerCoreError, Result},
    keys::{context_hash, hkdf_32, RootKey},
};

pub const DEFAULT_PASSKEY_DERIVATION_PATH: &str = "m/11010'/0'";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DerivedPasskey {
    pub derivation_path: String,
    pub credential_id: String,
    pub public_key: String,
    pub algorithm: String,
}

pub fn derive_passkey_from_root_key(
    root_key: &RootKey,
    derivation_path: &str,
    relying_party_id: &str,
    username: &str,
) -> Result<DerivedPasskey> {
    validate_passkey_request(derivation_path, relying_party_id, username)?;

    let normalized_rp = relying_party_id.trim().to_ascii_lowercase();
    let normalized_username = username.trim();
    let mut private_seed = passkey_private_seed(
        root_key,
        derivation_path.trim(),
        &normalized_rp,
        normalized_username,
    )?;
    let signing_key = SigningKey::from_bytes(&private_seed);
    let public_key = signing_key.verifying_key().to_bytes();
    private_seed.zeroize();

    let credential_id = credential_id(derivation_path.trim(), &normalized_rp, normalized_username);

    Ok(DerivedPasskey {
        derivation_path: derivation_path.trim().to_owned(),
        credential_id,
        public_key: URL_SAFE_NO_PAD.encode(public_key),
        algorithm: String::from("EdDSA"),
    })
}

fn passkey_private_seed(
    root_key: &RootKey,
    derivation_path: &str,
    relying_party_id: &str,
    username: &str,
) -> Result<[u8; 32]> {
    let salt = context_hash(
        "mlocker-core/passkey/v1",
        &[derivation_path, relying_party_id, username],
    );
    hkdf_32(root_key.as_bytes(), &salt, b"passkey-ed25519-seed")
}

fn credential_id(derivation_path: &str, relying_party_id: &str, username: &str) -> String {
    let id = context_hash(
        "mlocker-core/passkey-credential-id/v1",
        &[derivation_path, relying_party_id, username],
    );
    URL_SAFE_NO_PAD.encode(id)
}

fn validate_passkey_request(
    derivation_path: &str,
    relying_party_id: &str,
    username: &str,
) -> Result<()> {
    if relying_party_id.trim().is_empty() {
        return Err(MlockerCoreError::InvalidDerivationPath(
            "passkey relying party id is empty".to_owned(),
        ));
    }
    if username.trim().is_empty() {
        return Err(MlockerCoreError::InvalidDerivationPath(
            "passkey username is empty".to_owned(),
        ));
    }
    for index in parse_derivation_path(derivation_path)? {
        if !index.hardened {
            return Err(MlockerCoreError::InvalidDerivationPath(
                "passkey ed25519 keys only support hardened child indices".to_owned(),
            ));
        }
    }
    Ok(())
}
