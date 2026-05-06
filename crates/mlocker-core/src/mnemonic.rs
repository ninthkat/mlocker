use std::fmt;

use bip39::{Language, Mnemonic};

use crate::error::{MlockerCoreError, Result};

/// Parsed and normalized BIP39 recovery phrase.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryPhrase {
    phrase: String,
}

impl RecoveryPhrase {
    /// Returns the normalized mnemonic words.
    ///
    /// Callers should avoid logging this value.
    pub fn expose_phrase(&self) -> &str {
        &self.phrase
    }

    /// Derives the 64-byte BIP39 seed using the optional BIP39 passphrase.
    pub fn to_seed(&self, passphrase: &str) -> Result<[u8; 64]> {
        let mnemonic = parse_bip39(&self.phrase)?;
        Ok(mnemonic.to_seed(passphrase))
    }
}

impl fmt::Debug for RecoveryPhrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryPhrase")
            .field("phrase", &"<redacted>")
            .finish()
    }
}

/// Generates an English BIP39 mnemonic with the requested word count.
///
/// Valid BIP39 word counts are 12, 15, 18, 21, and 24.
pub fn generate_mnemonic(word_count: usize) -> Result<RecoveryPhrase> {
    let mnemonic = Mnemonic::generate_in(Language::English, word_count)
        .map_err(|err| MlockerCoreError::InvalidMnemonic(err.to_string()))?;

    Ok(RecoveryPhrase {
        phrase: mnemonic.to_string(),
    })
}

/// Parses and normalizes an English BIP39 mnemonic.
pub fn parse_mnemonic(phrase: &str) -> Result<RecoveryPhrase> {
    let mnemonic = parse_bip39(phrase)?;

    Ok(RecoveryPhrase {
        phrase: mnemonic.to_string(),
    })
}

fn parse_bip39(phrase: &str) -> Result<Mnemonic> {
    Mnemonic::parse_in_normalized(Language::English, phrase)
        .map_err(|err| MlockerCoreError::InvalidMnemonic(err.to_string()))
}
