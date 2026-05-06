use ed25519_dalek::SigningKey;
use k256::{elliptic_curve::sec1::ToEncodedPoint, SecretKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use zeroize::Zeroize;

use crate::{
    derivation::{derive_slip10_ed25519, hmac_sha512, parse_derivation_path, DerivationIndex},
    error::{MlockerCoreError, Result},
    mnemonic::RecoveryPhrase,
};

/// Supported wallet networks for MVP derivation helpers.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum WalletNetwork {
    Ethereum,
    Solana,
}

/// Short downstream-facing alias for wallet network selection.
pub type Chain = WalletNetwork;

/// Public wallet account material derived from a mnemonic.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DerivedWalletAccount {
    pub network: WalletNetwork,
    pub address: String,
    pub derivation_path: String,
    pub public_key: String,
}

/// Derives a public wallet account for a supported network and account index.
pub fn derive_wallet_account(
    mnemonic: &RecoveryPhrase,
    network: WalletNetwork,
    index: u32,
) -> Result<DerivedWalletAccount> {
    match network {
        WalletNetwork::Ethereum => derive_ethereum_account(mnemonic, index),
        WalletNetwork::Solana => derive_solana_account(mnemonic, index),
    }
}

#[derive(Clone)]
struct Secp256k1ExtendedPrivateKey {
    secret_key: SecretKey,
    chain_code: [u8; 32],
}

/// Derives the Ethereum account at `m/44'/60'/0'/0/{index}`.
pub fn derive_ethereum_account(
    mnemonic: &RecoveryPhrase,
    index: u32,
) -> Result<DerivedWalletAccount> {
    derive_ethereum_account_with_passphrase(mnemonic, "", index)
}

/// Derives the Ethereum account at `m/44'/60'/0'/0/{index}` with a BIP39 passphrase.
pub fn derive_ethereum_account_with_passphrase(
    mnemonic: &RecoveryPhrase,
    passphrase: &str,
    index: u32,
) -> Result<DerivedWalletAccount> {
    let path = ethereum_path(index);
    let secret_key = derive_ethereum_secret_key(mnemonic, passphrase, &path)?;
    let public_key = secret_key.public_key();
    let encoded = public_key.to_encoded_point(false);
    let address = ethereum_address(encoded.as_bytes())?;

    Ok(DerivedWalletAccount {
        network: WalletNetwork::Ethereum,
        address,
        derivation_path: path,
        public_key: format!("0x{}", hex::encode(encoded.as_bytes())),
    })
}

/// Explicitly exports the Ethereum private key bytes for `m/44'/60'/0'/0/{index}`.
pub fn derive_ethereum_private_key(mnemonic: &RecoveryPhrase, index: u32) -> Result<[u8; 32]> {
    let secret_key = derive_ethereum_secret_key(mnemonic, "", &ethereum_path(index))?;
    Ok(secret_key.to_bytes().into())
}

/// Derives the Solana account at `m/44'/501'/{index}'/0'`.
pub fn derive_solana_account(
    mnemonic: &RecoveryPhrase,
    index: u32,
) -> Result<DerivedWalletAccount> {
    derive_solana_account_with_passphrase(mnemonic, "", index)
}

/// Derives the Solana account at `m/44'/501'/{index}'/0'` with a BIP39 passphrase.
pub fn derive_solana_account_with_passphrase(
    mnemonic: &RecoveryPhrase,
    passphrase: &str,
    index: u32,
) -> Result<DerivedWalletAccount> {
    let path = solana_path(index);
    let mut seed = mnemonic.to_seed(passphrase)?;
    let derived = derive_slip10_ed25519(&seed, &path)?;
    seed.zeroize();

    let signing_key = SigningKey::from_bytes(derived.private_key());
    let public_key = signing_key.verifying_key().to_bytes();
    let public_key = bs58::encode(public_key).into_string();

    Ok(DerivedWalletAccount {
        network: WalletNetwork::Solana,
        address: public_key.clone(),
        derivation_path: path,
        public_key,
    })
}

/// Explicitly exports the Solana ed25519 private seed for `m/44'/501'/{index}'/0'`.
pub fn derive_solana_private_key_seed(mnemonic: &RecoveryPhrase, index: u32) -> Result<[u8; 32]> {
    let mut seed = mnemonic.to_seed("")?;
    let derived = derive_slip10_ed25519(&seed, &solana_path(index))?;
    seed.zeroize();
    Ok(*derived.private_key())
}

fn derive_ethereum_secret_key(
    mnemonic: &RecoveryPhrase,
    passphrase: &str,
    path: &str,
) -> Result<SecretKey> {
    let mut seed = mnemonic.to_seed(passphrase)?;
    let key = derive_secp256k1_path(&seed, path)?;
    seed.zeroize();
    Ok(key.secret_key)
}

fn derive_secp256k1_path(seed: &[u8], path: &str) -> Result<Secp256k1ExtendedPrivateKey> {
    let mut key = secp256k1_master(seed)?;
    for index in parse_derivation_path(path)? {
        key = secp256k1_child(&key, index)?;
    }
    Ok(key)
}

fn secp256k1_master(seed: &[u8]) -> Result<Secp256k1ExtendedPrivateKey> {
    let digest = hmac_sha512(b"Bitcoin seed", seed);
    split_secp256k1_digest(digest)
}

fn secp256k1_child(
    parent: &Secp256k1ExtendedPrivateKey,
    index: DerivationIndex,
) -> Result<Secp256k1ExtendedPrivateKey> {
    let child_index = index.bip32_value();
    let mut data = Vec::with_capacity(37);

    if index.hardened {
        data.push(0);
        data.extend_from_slice(parent.secret_key.to_bytes().as_slice());
    } else {
        let public_key = parent.secret_key.public_key();
        data.extend_from_slice(public_key.to_encoded_point(true).as_bytes());
    }
    data.extend_from_slice(&child_index.to_be_bytes());

    let digest = hmac_sha512(&parent.chain_code, &data);
    data.zeroize();
    let mut child = split_secp256k1_digest(digest)?;
    child.secret_key = add_private_keys(&parent.secret_key, &child.secret_key)?;
    Ok(child)
}

fn split_secp256k1_digest(mut digest: [u8; 64]) -> Result<Secp256k1ExtendedPrivateKey> {
    let secret_key = SecretKey::from_slice(&digest[..32]).map_err(|err| {
        MlockerCoreError::WalletDerivation(format!("invalid secp256k1 key material: {err}"))
    })?;
    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(&digest[32..]);
    digest.zeroize();

    Ok(Secp256k1ExtendedPrivateKey {
        secret_key,
        chain_code,
    })
}

fn add_private_keys(parent: &SecretKey, tweak: &SecretKey) -> Result<SecretKey> {
    let parent_scalar = *parent.to_nonzero_scalar().as_ref();
    let tweak_scalar = *tweak.to_nonzero_scalar().as_ref();
    let child_scalar = parent_scalar + tweak_scalar;

    if bool::from(child_scalar.is_zero()) {
        return Err(MlockerCoreError::WalletDerivation(
            "derived zero secp256k1 private key".to_owned(),
        ));
    }

    SecretKey::from_slice(child_scalar.to_bytes().as_slice()).map_err(|err| {
        MlockerCoreError::WalletDerivation(format!("invalid secp256k1 child key: {err}"))
    })
}

fn ethereum_address(uncompressed_public_key: &[u8]) -> Result<String> {
    if uncompressed_public_key.len() != 65 || uncompressed_public_key[0] != 0x04 {
        return Err(MlockerCoreError::WalletDerivation(
            "ethereum public key must be uncompressed secp256k1".to_owned(),
        ));
    }

    let digest = Keccak256::digest(&uncompressed_public_key[1..]);
    let mut address = [0u8; 20];
    address.copy_from_slice(&digest[12..]);
    Ok(eip55_address(&address))
}

fn eip55_address(address: &[u8; 20]) -> String {
    let lower = hex::encode(address);
    let hash = Keccak256::digest(lower.as_bytes());
    let mut checksummed = String::with_capacity(42);
    checksummed.push_str("0x");

    for (index, ch) in lower.chars().enumerate() {
        if ch.is_ascii_digit() {
            checksummed.push(ch);
            continue;
        }

        let byte = hash[index / 2];
        let nibble = if index % 2 == 0 {
            byte >> 4
        } else {
            byte & 0x0f
        };
        if nibble >= 8 {
            checksummed.push(ch.to_ascii_uppercase());
        } else {
            checksummed.push(ch);
        }
    }

    checksummed
}

fn ethereum_path(index: u32) -> String {
    format!("m/44'/60'/0'/0/{index}")
}

fn solana_path(index: u32) -> String {
    format!("m/44'/501'/{index}'/0'")
}
