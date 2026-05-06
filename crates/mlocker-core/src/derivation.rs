use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{MlockerCoreError, Result};

pub(crate) const HARDENED_OFFSET: u32 = 1 << 31;

type HmacSha512 = Hmac<Sha512>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DerivationIndex {
    pub index: u32,
    pub hardened: bool,
}

impl DerivationIndex {
    pub fn bip32_value(self) -> u32 {
        if self.hardened {
            self.index | HARDENED_OFFSET
        } else {
            self.index
        }
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct Slip10Ed25519Key {
    private_key: [u8; 32],
    chain_code: [u8; 32],
}

impl Slip10Ed25519Key {
    pub fn private_key(&self) -> &[u8; 32] {
        &self.private_key
    }
}

pub(crate) fn parse_derivation_path(path: &str) -> Result<Vec<DerivationIndex>> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err(MlockerCoreError::InvalidDerivationPath(
            "path is empty".to_owned(),
        ));
    }

    let without_master = trimmed.strip_prefix("m/").unwrap_or(trimmed);
    if without_master == "m" || without_master.is_empty() {
        return Ok(Vec::new());
    }

    without_master
        .split('/')
        .map(parse_index)
        .collect::<Result<Vec<_>>>()
}

pub(crate) fn derive_slip10_ed25519(seed: &[u8], path: &str) -> Result<Slip10Ed25519Key> {
    let mut key = slip10_master(seed)?;

    for index in parse_derivation_path(path)? {
        if !index.hardened {
            return Err(MlockerCoreError::InvalidDerivationPath(
                "ed25519 SLIP-0010 only supports hardened child indices".to_owned(),
            ));
        }
        key = slip10_child(&key, index.bip32_value())?;
    }

    Ok(key)
}

pub(crate) fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut mac = HmacSha512::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn parse_index(raw: &str) -> Result<DerivationIndex> {
    if raw.is_empty() {
        return Err(MlockerCoreError::InvalidDerivationPath(
            "empty index segment".to_owned(),
        ));
    }

    let hardened = raw.ends_with('\'') || raw.ends_with('h') || raw.ends_with('H');
    let number = if hardened { &raw[..raw.len() - 1] } else { raw };
    let index = number.parse::<u32>().map_err(|_| {
        MlockerCoreError::InvalidDerivationPath(format!("invalid index segment {raw:?}"))
    })?;

    if index >= HARDENED_OFFSET {
        return Err(MlockerCoreError::InvalidDerivationPath(format!(
            "index {index} is too large"
        )));
    }

    Ok(DerivationIndex { index, hardened })
}

fn slip10_master(seed: &[u8]) -> Result<Slip10Ed25519Key> {
    let digest = hmac_sha512(b"ed25519 seed", seed);
    split_slip10_digest(digest)
}

fn slip10_child(parent: &Slip10Ed25519Key, child_index: u32) -> Result<Slip10Ed25519Key> {
    let mut data = Vec::with_capacity(1 + 32 + 4);
    data.push(0);
    data.extend_from_slice(&parent.private_key);
    data.extend_from_slice(&child_index.to_be_bytes());

    let digest = hmac_sha512(&parent.chain_code, &data);
    data.zeroize();
    split_slip10_digest(digest)
}

fn split_slip10_digest(mut digest: [u8; 64]) -> Result<Slip10Ed25519Key> {
    let mut private_key = [0u8; 32];
    let mut chain_code = [0u8; 32];
    private_key.copy_from_slice(&digest[..32]);
    chain_code.copy_from_slice(&digest[32..]);
    digest.zeroize();

    Ok(Slip10Ed25519Key {
        private_key,
        chain_code,
    })
}
