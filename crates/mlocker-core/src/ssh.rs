use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::{
    derivation::{derive_slip10_ed25519, parse_derivation_path},
    error::{MlockerCoreError, Result},
    keys::{context_hash, hkdf_32, RootKey},
    mnemonic::RecoveryPhrase,
};

pub const DEFAULT_SSH_DERIVATION_PATH: &str = "m/101010'/0'";

/// Public SSH ed25519 material derived from a mnemonic and derivation path.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DerivedSshKey {
    pub derivation_path: String,
    pub public_key_base64: String,
    pub public_key_blob: Vec<u8>,
    pub public_key_openssh: String,
}

/// Derives an SSH ed25519 public key using SLIP-0010 hardened derivation.
pub fn derive_ssh_key(
    mnemonic: &RecoveryPhrase,
    derivation_path: &str,
    comment: &str,
) -> Result<DerivedSshKey> {
    let mut seed = mnemonic.to_seed("")?;
    let derived = derive_slip10_ed25519(&seed, derivation_path)?;
    seed.zeroize();

    Ok(derived_ssh_key_from_private_seed(
        *derived.private_key(),
        derivation_path,
        comment,
    ))
}

/// Derives an SSH ed25519 public key from the unlocked vault root key.
pub fn derive_ssh_key_from_root_key(
    root_key: &RootKey,
    derivation_path: &str,
    comment: &str,
) -> Result<DerivedSshKey> {
    let seed = derive_ssh_private_key_seed_from_root_key(root_key, derivation_path)?;
    Ok(derived_ssh_key_from_private_seed(
        seed,
        derivation_path,
        comment,
    ))
}

/// Explicitly exports the SSH ed25519 private seed for a derivation path.
pub fn derive_ssh_private_key_seed(
    mnemonic: &RecoveryPhrase,
    derivation_path: &str,
) -> Result<[u8; 32]> {
    let mut seed = mnemonic.to_seed("")?;
    let derived = derive_slip10_ed25519(&seed, derivation_path)?;
    seed.zeroize();
    Ok(*derived.private_key())
}

/// Derives the SSH ed25519 private seed from the unlocked vault root key.
pub fn derive_ssh_private_key_seed_from_root_key(
    root_key: &RootKey,
    derivation_path: &str,
) -> Result<[u8; 32]> {
    validate_ssh_derivation_path(derivation_path)?;
    let salt = context_hash("mlocker-core/ssh-key/v1", &[derivation_path.trim()]);
    hkdf_32(root_key.as_bytes(), &salt, b"ssh-ed25519-seed")
}

/// Signs SSH agent data with the ed25519 key at the requested derivation path.
pub fn sign_ssh_data_from_root_key(
    root_key: &RootKey,
    derivation_path: &str,
    data: &[u8],
) -> Result<[u8; 64]> {
    let mut seed = derive_ssh_private_key_seed_from_root_key(root_key, derivation_path)?;
    let signing_key = SigningKey::from_bytes(&seed);
    let signature = signing_key.sign(data).to_bytes();
    seed.zeroize();
    Ok(signature)
}

fn derived_ssh_key_from_private_seed(
    mut private_seed: [u8; 32],
    derivation_path: &str,
    comment: &str,
) -> DerivedSshKey {
    let signing_key = SigningKey::from_bytes(&private_seed);
    let public_key = signing_key.verifying_key().to_bytes();
    let public_key_base64 = STANDARD.encode(public_key);
    let public_key_blob = ssh_public_key_blob(&public_key);
    let public_key_openssh = openssh_public_key(&public_key_blob, comment);
    private_seed.zeroize();

    DerivedSshKey {
        derivation_path: derivation_path.to_owned(),
        public_key_base64,
        public_key_blob,
        public_key_openssh,
    }
}

fn validate_ssh_derivation_path(path: &str) -> Result<()> {
    for index in parse_derivation_path(path)? {
        if !index.hardened {
            return Err(MlockerCoreError::InvalidDerivationPath(
                "ed25519 SSH keys only support hardened child indices".to_owned(),
            ));
        }
    }
    Ok(())
}

fn ssh_public_key_blob(public_key: &[u8; 32]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(4 + 11 + 4 + public_key.len());
    write_ssh_string(&mut payload, b"ssh-ed25519");
    write_ssh_string(&mut payload, public_key);
    payload
}

fn openssh_public_key(public_key_blob: &[u8], comment: &str) -> String {
    let encoded = STANDARD.encode(public_key_blob);
    let comment = comment.trim();
    if comment.is_empty() {
        format!("ssh-ed25519 {encoded}")
    } else {
        format!("ssh-ed25519 {encoded} {comment}")
    }
}

fn write_ssh_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}
