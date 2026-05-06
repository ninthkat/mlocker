use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::error::{MlockerCoreError, Result};

pub const DEFAULT_TOTP_PERIOD: u64 = 30;
pub const DEFAULT_TOTP_DIGITS: u32 = 6;

type HmacSha1 = Hmac<Sha1>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TotpCode {
    pub code: String,
    pub period: u64,
    pub digits: u32,
    pub seconds_remaining: u64,
}

pub fn generate_totp_now(secret: &str) -> Result<TotpCode> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|err| MlockerCoreError::Totp(err.to_string()))?
        .as_secs();
    generate_totp(secret, now, DEFAULT_TOTP_PERIOD, DEFAULT_TOTP_DIGITS)
}

pub fn generate_totp(secret: &str, timestamp: u64, period: u64, digits: u32) -> Result<TotpCode> {
    validate_totp_params(period, digits)?;
    let secret = extract_totp_secret(secret)?;
    let secret_bytes = decode_base32(&secret)?;
    let counter = timestamp / period;
    let code = hotp(&secret_bytes, counter, digits)?;

    Ok(TotpCode {
        code,
        period,
        digits,
        seconds_remaining: period - (timestamp % period),
    })
}

pub fn normalize_totp_secret(input: &str) -> Result<String> {
    let secret = extract_totp_secret(input)?;
    decode_base32(&secret)?;
    Ok(secret)
}

fn extract_totp_secret(input: &str) -> Result<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(MlockerCoreError::Totp("TOTP secret is empty".to_owned()));
    }

    let secret = if let Some(query) = trimmed.strip_prefix("otpauth://") {
        query
            .split_once('?')
            .map(|(_, query)| query)
            .and_then(|query| {
                query.split('&').find_map(|part| {
                    let (key, value) = part.split_once('=')?;
                    key.eq_ignore_ascii_case("secret").then_some(value)
                })
            })
            .ok_or_else(|| MlockerCoreError::Totp("otpauth URL is missing secret".to_owned()))?
    } else {
        trimmed
    };

    let normalized: String = percent_decode(secret)
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace() && *ch != '-')
        .map(|ch| ch.to_ascii_uppercase())
        .collect();
    if normalized.is_empty() {
        return Err(MlockerCoreError::Totp("TOTP secret is empty".to_owned()));
    }
    Ok(normalized.trim_end_matches('=').to_owned())
}

fn hotp(secret: &[u8], counter: u64, digits: u32) -> Result<String> {
    let mut mac =
        HmacSha1::new_from_slice(secret).map_err(|err| MlockerCoreError::Totp(err.to_string()))?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let binary = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    let divisor = 10_u32.pow(digits);
    Ok(format!(
        "{:0width$}",
        binary % divisor,
        width = digits as usize
    ))
}

fn decode_base32(input: &str) -> Result<Vec<u8>> {
    let mut buffer = 0_u32;
    let mut bits = 0_u8;
    let mut output = Vec::new();

    for ch in input.chars() {
        let value = match ch {
            'A'..='Z' => ch as u8 - b'A',
            '2'..='7' => ch as u8 - b'2' + 26,
            _ => {
                return Err(MlockerCoreError::Totp(format!(
                    "invalid base32 character {ch:?}"
                )))
            }
        };
        buffer = (buffer << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            output.push(((buffer >> bits) & 0xff) as u8);
        }
    }

    if output.is_empty() {
        return Err(MlockerCoreError::Totp(
            "TOTP secret is too short".to_owned(),
        ));
    }
    Ok(output)
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let Ok(hex) = std::str::from_utf8(&bytes[index + 1..index + 3]) {
                if let Ok(value) = u8::from_str_radix(hex, 16) {
                    output.push(value);
                    index += 3;
                    continue;
                }
            }
        }
        output.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&output).into_owned()
}

fn validate_totp_params(period: u64, digits: u32) -> Result<()> {
    if period == 0 {
        return Err(MlockerCoreError::Totp(
            "TOTP period must be positive".to_owned(),
        ));
    }
    if !(6..=8).contains(&digits) {
        return Err(MlockerCoreError::Totp(
            "TOTP digits must be between 6 and 8".to_owned(),
        ));
    }
    Ok(())
}
