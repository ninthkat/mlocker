use std::collections::HashMap;

use anyhow::{anyhow, bail, Result};
use serde_json::Value;

use crate::cli::ImportFormat;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportedLogin {
    pub title: String,
    pub username: String,
    pub url: String,
    pub password: String,
    pub totp: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportedLogin {
    pub title: String,
    pub username: String,
    pub url: String,
    pub password: String,
    pub totp: Option<String>,
}

pub fn parse_login_import(input: &str, format: ImportFormat) -> Result<Vec<ImportedLogin>> {
    match format {
        ImportFormat::Auto => {
            if starts_like_json(input) {
                let value: Value = serde_json::from_str(input)?;
                let one_password = one_password_logins(&value)?;
                if !one_password.is_empty() {
                    return Ok(one_password);
                }
                return generic_json_logins(&value);
            }
            parse_login_csv(input, format)
        }
        ImportFormat::Chrome | ImportFormat::Bitwarden | ImportFormat::GenericCsv => {
            parse_login_csv(input, format)
        }
        ImportFormat::OnePasswordJson => {
            let value: Value = serde_json::from_str(input)?;
            one_password_logins(&value)
        }
        ImportFormat::GenericJson => {
            let value: Value = serde_json::from_str(input)?;
            generic_json_logins(&value)
        }
    }
}

pub fn parse_login_csv(input: &str, format: ImportFormat) -> Result<Vec<ImportedLogin>> {
    let rows = parse_csv(input)?;
    let Some((headers, records)) = rows.split_first() else {
        return Ok(Vec::new());
    };
    let headers = header_map(headers);
    let format = detect_format(format, &headers)?;

    let mut imported = Vec::new();
    for record in records {
        if record.iter().all(|field| field.trim().is_empty()) {
            continue;
        }
        let login = match format {
            ImportFormat::Auto => unreachable!("auto format must be resolved before mapping"),
            ImportFormat::Chrome | ImportFormat::GenericCsv => generic_login(&headers, record)?,
            ImportFormat::Bitwarden => bitwarden_login(&headers, record)?,
            ImportFormat::OnePasswordJson | ImportFormat::GenericJson => {
                bail!("JSON import format cannot parse CSV input")
            }
        };
        if !login.password.is_empty() {
            imported.push(login);
        }
    }

    Ok(imported)
}

pub fn format_login_csv(logins: &[ExportedLogin]) -> String {
    let mut output = String::from("name,url,username,password,totp\n");
    for login in logins {
        write_csv_row(
            &mut output,
            &[
                login.title.as_str(),
                login.url.as_str(),
                login.username.as_str(),
                login.password.as_str(),
                login.totp.as_deref().unwrap_or(""),
            ],
        );
    }
    output
}

fn detect_format(format: ImportFormat, headers: &HashMap<String, usize>) -> Result<ImportFormat> {
    if !matches!(format, ImportFormat::Auto) {
        return Ok(format);
    }
    if headers.contains_key("login_uri") && headers.contains_key("login_password") {
        return Ok(ImportFormat::Bitwarden);
    }
    if headers.contains_key("url") && headers.contains_key("username") {
        return Ok(ImportFormat::GenericCsv);
    }
    bail!(
        "could not detect import format; use --format chrome, bitwarden, generic-csv, 1password-json, or generic-json"
    )
}

fn starts_like_json(input: &str) -> bool {
    matches!(input.trim_start().chars().next(), Some('{') | Some('['))
}

fn generic_json_logins(value: &Value) -> Result<Vec<ImportedLogin>> {
    let mut imported = Vec::new();
    for item in generic_json_items(value) {
        if let Some(login) = generic_json_login(item) {
            imported.push(login);
        }
    }
    Ok(imported)
}

fn generic_json_items(value: &Value) -> Vec<&Value> {
    if let Some(items) = value.as_array() {
        return items.iter().collect();
    }

    let Some(object) = value.as_object() else {
        return Vec::new();
    };

    for key in ["items", "logins", "credentials", "passwords"] {
        if let Some(items) = object.get(key).and_then(Value::as_array) {
            return items.iter().collect();
        }
    }

    vec![value]
}

fn generic_json_login(value: &Value) -> Option<ImportedLogin> {
    let url = string_alias(value, &["url", "uri", "login_uri", "website", "href"])
        .or_else(|| first_url(value))?;
    let username = string_alias(
        value,
        &[
            "username",
            "user",
            "login_username",
            "email",
            "account",
            "login",
        ],
    )?;
    let password = string_alias(value, &["password", "login_password", "secret"])?;
    if password.trim().is_empty() {
        return None;
    }

    let title = string_alias(value, &["title", "name", "label"]).unwrap_or_else(|| url.clone());
    let totp = string_alias(value, &["totp", "login_totp", "otp", "one_time_password"])
        .and_then(|value| normalize_totp_secret(&value));

    Some(ImportedLogin {
        title,
        username,
        url,
        password,
        totp,
    })
}

fn one_password_logins(value: &Value) -> Result<Vec<ImportedLogin>> {
    let mut imported = Vec::new();
    for item in one_password_items(value) {
        if let Some(login) = one_password_login(item) {
            imported.push(login);
        }
    }
    Ok(imported)
}

fn one_password_items(value: &Value) -> Vec<&Value> {
    if let Some(items) = value.as_array() {
        return items.iter().collect();
    }

    let Some(object) = value.as_object() else {
        return Vec::new();
    };

    if let Some(accounts) = object.get("accounts").and_then(Value::as_array) {
        let mut items = Vec::new();
        for account in accounts {
            for vault in account
                .get("vaults")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if let Some(vault_items) = vault.get("items").and_then(Value::as_array) {
                    items.extend(vault_items);
                }
            }
        }
        return items;
    }

    if let Some(vaults) = object.get("vaults").and_then(Value::as_array) {
        let mut items = Vec::new();
        for vault in vaults {
            if let Some(vault_items) = vault.get("items").and_then(Value::as_array) {
                items.extend(vault_items);
            }
        }
        return items;
    }

    if let Some(items) = object.get("items").and_then(Value::as_array) {
        return items.iter().collect();
    }

    vec![value]
}

fn one_password_login(item: &Value) -> Option<ImportedLogin> {
    let fields = one_password_fields(item);
    let url = first_url(item).or_else(|| string_alias(item, &["url", "website", "href"]))?;
    let username = one_password_field_value(&fields, &["username"], &["username", "user", "email"])
        .or_else(|| string_alias(item, &["username", "login_username"]))?;
    let password =
        one_password_field_value(&fields, &["password"], &["password", "passcode", "secret"])
            .or_else(|| string_alias(item, &["password", "login_password"]))?;
    if password.trim().is_empty() {
        return None;
    }

    let title = string_alias(item, &["title", "name"]).unwrap_or_else(|| url.clone());
    let totp =
        one_password_field_value(&fields, &["otp", "totp"], &["otp", "totp", "one_time_password"])
            .and_then(|value| normalize_totp_secret(&value));

    Some(ImportedLogin {
        title,
        username,
        url,
        password,
        totp,
    })
}

fn one_password_fields(item: &Value) -> Vec<&Value> {
    let mut fields = Vec::new();
    if let Some(root_fields) = item.get("fields").and_then(Value::as_array) {
        fields.extend(root_fields);
    }
    if let Some(sections) = item.get("sections").and_then(Value::as_array) {
        for section in sections {
            if let Some(section_fields) = section.get("fields").and_then(Value::as_array) {
                fields.extend(section_fields);
            }
        }
    }
    fields
}

fn one_password_field_value(
    fields: &[&Value],
    purposes: &[&str],
    aliases: &[&str],
) -> Option<String> {
    fields
        .iter()
        .find(|field| {
            let purpose = string_alias(field, &["purpose", "type"]).unwrap_or_default();
            purposes
                .iter()
                .any(|expected| normalized_key(&purpose).contains(&normalized_key(expected)))
        })
        .and_then(field_string_value)
        .or_else(|| {
            fields
                .iter()
                .find(|field| {
                    let name = string_alias(field, &["id", "label", "name", "designation"])
                        .unwrap_or_default();
                    let normalized = normalized_key(&name);
                    aliases
                        .iter()
                        .any(|alias| normalized.contains(&normalized_key(alias)))
                })
                .and_then(field_string_value)
        })
}

fn field_string_value(field: &&Value) -> Option<String> {
    string_alias(field, &["value", "text", "data"])
}

fn string_alias(value: &Value, aliases: &[&str]) -> Option<String> {
    let object = value.as_object()?;
    for (key, entry) in object {
        if aliases
            .iter()
            .any(|alias| normalized_key(key) == normalized_key(alias))
        {
            return value_to_string(entry);
        }
    }
    for nested in ["login", "credential", "passwordDetails"] {
        if let Some(value) = object.get(nested).and_then(|nested| string_alias(nested, aliases)) {
            return Some(value);
        }
    }
    None
}

fn value_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Object(object) => object.get("value").and_then(value_to_string),
        _ => None,
    }
}

fn first_url(value: &Value) -> Option<String> {
    value
        .get("urls")
        .and_then(Value::as_array)
        .and_then(|urls| {
            urls.iter().find_map(|url| {
                string_alias(url, &["href", "url"])
                    .filter(|candidate| !candidate.trim().is_empty())
            })
        })
}

fn normalize_totp_secret(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if !value.to_ascii_lowercase().starts_with("otpauth://") {
        return Some(value.to_owned());
    }
    value
        .split_once('?')
        .and_then(|(_, query)| {
            query.split('&').find_map(|pair| {
                let (key, value) = pair.split_once('=')?;
                (key.eq_ignore_ascii_case("secret")).then(|| percent_decode(value))
            })
        })
        .filter(|secret| !secret.is_empty())
}

fn normalized_key(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut output = String::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&value[index + 1..index + 3], 16) {
                output.push(byte as char);
                index += 3;
                continue;
            }
        }
        output.push(bytes[index] as char);
        index += 1;
    }
    output
}

fn generic_login(headers: &HashMap<String, usize>, record: &[String]) -> Result<ImportedLogin> {
    let url = field(headers, record, &["url", "login_uri", "uri"])?;
    let username = field(headers, record, &["username", "login_username", "user"])?;
    let password = field(headers, record, &["password", "login_password"])?;
    let title = optional_field(headers, record, &["name", "title"])
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(url);
    let totp = optional_field(headers, record, &["totp", "login_totp"])
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned);

    Ok(ImportedLogin {
        title: title.to_owned(),
        username: username.to_owned(),
        url: url.to_owned(),
        password: password.to_owned(),
        totp,
    })
}

fn bitwarden_login(headers: &HashMap<String, usize>, record: &[String]) -> Result<ImportedLogin> {
    let item_type = optional_field(headers, record, &["type"]).unwrap_or("login");
    if item_type != "login" {
        return Ok(ImportedLogin {
            title: String::new(),
            username: String::new(),
            url: String::new(),
            password: String::new(),
            totp: None,
        });
    }

    let url = field(headers, record, &["login_uri"])?;
    let username = field(headers, record, &["login_username"])?;
    let password = field(headers, record, &["login_password"])?;
    let title = optional_field(headers, record, &["name"])
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(url);
    let totp = optional_field(headers, record, &["login_totp"])
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned);

    Ok(ImportedLogin {
        title: title.to_owned(),
        username: username.to_owned(),
        url: url.to_owned(),
        password: password.to_owned(),
        totp,
    })
}

fn field<'a>(
    headers: &HashMap<String, usize>,
    record: &'a [String],
    names: &[&str],
) -> Result<&'a str> {
    optional_field(headers, record, names)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow!("missing CSV field {}", names.join("/")))
}

fn optional_field<'a>(
    headers: &HashMap<String, usize>,
    record: &'a [String],
    names: &[&str],
) -> Option<&'a str> {
    names.iter().find_map(|name| {
        headers
            .get(*name)
            .and_then(|index| record.get(*index))
            .map(String::as_str)
    })
}

fn header_map(headers: &[String]) -> HashMap<String, usize> {
    headers
        .iter()
        .enumerate()
        .map(|(index, header)| (normalize_header(header), index))
        .collect()
}

fn normalize_header(header: &str) -> String {
    header.trim().to_ascii_lowercase().replace(' ', "_")
}

fn parse_csv(input: &str) -> Result<Vec<Vec<String>>> {
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut field = String::new();
    let mut chars = input.chars().peekable();
    let mut in_quotes = false;

    while let Some(ch) = chars.next() {
        match ch {
            '"' if in_quotes && chars.peek() == Some(&'"') => {
                field.push('"');
                chars.next();
            }
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                row.push(std::mem::take(&mut field));
            }
            '\n' if !in_quotes => {
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
            }
            '\r' if !in_quotes => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
            }
            _ => field.push(ch),
        }
    }

    if in_quotes {
        bail!("unterminated quoted CSV field");
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }

    Ok(rows)
}

fn write_csv_row(output: &mut String, fields: &[&str]) {
    for (index, field) in fields.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        write_csv_field(output, field);
    }
    output.push('\n');
}

fn write_csv_field(output: &mut String, field: &str) {
    let must_quote =
        field.contains(',') || field.contains('"') || field.contains('\n') || field.contains('\r');
    if !must_quote {
        output.push_str(field);
        return;
    }

    output.push('"');
    for ch in field.chars() {
        if ch == '"' {
            output.push('"');
        }
        output.push(ch);
    }
    output.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_chrome_export_with_quoted_commas() {
        let csv = "name,url,username,password\n\"Example, Inc\",https://example.com,alice,secret\n";

        let imported = parse_login_csv(csv, ImportFormat::Chrome).unwrap();

        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].title, "Example, Inc");
        assert_eq!(imported[0].password, "secret");
    }

    #[test]
    fn parses_bitwarden_login_rows_only() {
        let csv = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n,,login,Example,,,,https://example.com,alice,secret,JBSWY3DPEHPK3PXP\n,,note,Ignored,,,,https://note.example,bob,secret,\n";

        let imported = parse_login_csv(csv, ImportFormat::Bitwarden).unwrap();

        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].title, "Example");
        assert_eq!(imported[0].totp.as_deref(), Some("JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn parses_generic_json_imports() {
        let json = r#"{
          "items": [
            {
              "name": "Example",
              "url": "https://example.com",
              "username": "alice",
              "password": "secret",
              "totp": "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example"
            }
          ]
        }"#;

        let imported = parse_login_import(json, ImportFormat::GenericJson).unwrap();

        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].title, "Example");
        assert_eq!(imported[0].username, "alice");
        assert_eq!(imported[0].totp.as_deref(), Some("JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn parses_one_password_json_imports() {
        let json = r#"{
          "accounts": [
            {
              "vaults": [
                {
                  "items": [
                    {
                      "title": "Example",
                      "urls": [{"href": "https://example.com/login"}],
                      "fields": [
                        {"id": "username", "purpose": "USERNAME", "value": "alice"},
                        {"id": "password", "purpose": "PASSWORD", "value": "secret"}
                      ],
                      "sections": [
                        {
                          "fields": [
                            {
                              "label": "one-time password",
                              "type": "OTP",
                              "value": "otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP"
                            }
                          ]
                        }
                      ]
                    }
                  ]
                }
              ]
            }
          ]
        }"#;

        let imported = parse_login_import(json, ImportFormat::OnePasswordJson).unwrap();

        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].title, "Example");
        assert_eq!(imported[0].url, "https://example.com/login");
        assert_eq!(imported[0].password, "secret");
        assert_eq!(imported[0].totp.as_deref(), Some("JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn formats_csv_with_quoting() {
        let csv = format_login_csv(&[ExportedLogin {
            title: "Example, Inc".to_owned(),
            username: "alice".to_owned(),
            url: "https://example.com".to_owned(),
            password: "quote\"secret".to_owned(),
            totp: None,
        }]);

        assert_eq!(
            csv,
            "name,url,username,password,totp\n\"Example, Inc\",https://example.com,alice,\"quote\"\"secret\",\n"
        );
    }
}
