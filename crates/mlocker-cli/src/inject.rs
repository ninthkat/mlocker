use anyhow::{anyhow, bail, Result};
use mlocker_core::generate_totp_now;

use crate::core_adapter;
use crate::vault::{LoginItem, UnlockedVault};

const SECRET_REF_PREFIX: &str = "mlocker://";

pub fn render_template(input: &str, unlocked: &UnlockedVault) -> Result<String> {
    let mut output = String::with_capacity(input.len());
    let mut rest = input;

    while let Some(index) = rest.find(SECRET_REF_PREFIX) {
        output.push_str(&rest[..index]);
        let after_prefix = &rest[index + SECRET_REF_PREFIX.len()..];
        let token_len = secret_ref_token_len(after_prefix);
        if token_len == 0 {
            bail!("empty mlocker secret reference");
        }

        let token = &after_prefix[..token_len];
        output.push_str(&resolve_secret_reference(token, unlocked)?);
        rest = &after_prefix[token_len..];
    }

    output.push_str(rest);
    Ok(output)
}

fn resolve_secret_reference(token: &str, unlocked: &UnlockedVault) -> Result<String> {
    let (query, field) = token
        .rsplit_once('/')
        .ok_or_else(|| anyhow!("secret reference must be mlocker://<item>/<field>"))?;
    let query = percent_decode(query)?;
    let field = percent_decode(field)?.to_ascii_lowercase();
    if query.trim().is_empty() {
        bail!("secret reference item query must not be empty");
    }

    let item = unlocked.state.find_login(&query)?;
    match field.as_str() {
        "id" => Ok(item.id.clone()),
        "title" => Ok(item.title.clone()),
        "username" => Ok(item.username.clone()),
        "url" => Ok(item.url.clone()),
        "password" => login_password_value(unlocked, item),
        "totp" => {
            let Some(totp) = &item.totp else {
                bail!("totp is not stored for '{}'", item.title);
            };
            Ok(generate_totp_now(&totp.secret)?.code)
        }
        _ => bail!("unsupported secret reference field '{field}'"),
    }
}

pub fn login_password_value(unlocked: &UnlockedVault, item: &LoginItem) -> Result<String> {
    match &item.password {
        mlocker_core::LoginPassword::MnemonicDerived { path } => {
            core_adapter::derive_password_with_root_key(
                &unlocked.root_key,
                &item.url,
                &item.username,
                Some(path),
            )
        }
        mlocker_core::LoginPassword::UserInput { value } => Ok(value.clone()),
    }
}

fn secret_ref_token_len(input: &str) -> usize {
    input
        .char_indices()
        .find_map(|(index, ch)| is_secret_ref_delimiter(ch).then_some(index))
        .unwrap_or(input.len())
}

fn is_secret_ref_delimiter(ch: char) -> bool {
    ch.is_whitespace()
        || matches!(
            ch,
            '"' | '\'' | '`' | '<' | '>' | ')' | ']' | '}' | ',' | ';'
        )
}

fn percent_decode(input: &str) -> Result<String> {
    let bytes = input.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                bail!("invalid percent escape in secret reference");
            }
            let high = hex_value(bytes[index + 1])?;
            let low = hex_value(bytes[index + 2])?;
            output.push((high << 4) | low);
            index += 3;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }

    String::from_utf8(output).map_err(Into::into)
}

fn hex_value(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => bail!("invalid percent escape in secret reference"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{self, UnlockedVault};
    use mlocker_core::{derive_root_key, parse_mnemonic, DEFAULT_APP_DOMAIN};

    const MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn renders_username_and_password_references() {
        let mut state = vault::VaultState::empty();
        vault::add_login(
            &mut state,
            "Example".to_owned(),
            "alice".to_owned(),
            "https://example.com".to_owned(),
            None,
            Some("secret".to_owned()),
            None,
        )
        .unwrap();

        let unlocked = unlocked_state(state);
        let rendered = render_template(
            "USER=mlocker://Example/username\nPASS=mlocker://Example/password\n",
            &unlocked,
        )
        .unwrap();

        assert_eq!(rendered, "USER=alice\nPASS=secret\n");
    }

    #[test]
    fn supports_percent_encoded_item_queries() {
        let mut state = vault::VaultState::empty();
        vault::add_login(
            &mut state,
            "Example Prod".to_owned(),
            "alice".to_owned(),
            "https://example.com".to_owned(),
            None,
            Some("secret".to_owned()),
            None,
        )
        .unwrap();

        let unlocked = unlocked_state(state);
        let rendered = render_template("mlocker://Example%20Prod/password", &unlocked).unwrap();

        assert_eq!(rendered, "secret");
    }

    fn unlocked_state(state: vault::VaultState) -> UnlockedVault {
        let recovery = parse_mnemonic(MNEMONIC).unwrap();
        let root_key = derive_root_key(&recovery, DEFAULT_APP_DOMAIN).unwrap();
        UnlockedVault {
            state,
            root_key,
            mnemonic: Some(MNEMONIC.to_owned()),
        }
    }
}
