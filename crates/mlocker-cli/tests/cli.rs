use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use tempfile::tempdir;

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[test]
fn init_add_get_and_list_login() {
    let dir = tempdir().unwrap();
    let vault = dir.path().join("vault.blob");

    mlocker()
        .args(["init", "--vault"])
        .arg(&vault)
        .args(["--mnemonic", MNEMONIC])
        .assert()
        .success()
        .stdout(predicate::str::contains("Vault initialized"));

    mlocker()
        .env("MLOCKER_MNEMONIC", MNEMONIC)
        .args(["add-login", "--vault"])
        .arg(&vault)
        .args([
            "--title",
            "Example",
            "--username",
            "alice",
            "--url",
            "https://example.com",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"title\": \"Example\""));

    let password_output = mlocker()
        .env("MLOCKER_MNEMONIC", MNEMONIC)
        .args(["get", "--vault"])
        .arg(&vault)
        .args(["Example", "--field", "password"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let password = String::from_utf8(password_output).unwrap();

    assert_eq!(password.trim().len(), 24);

    let list_output = mlocker()
        .env("MLOCKER_MNEMONIC", MNEMONIC)
        .args(["list", "--vault"])
        .arg(&vault)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let list: Value = serde_json::from_slice(&list_output).unwrap();

    assert_eq!(list[0]["title"], "Example");
    assert_eq!(list[0]["username"], "alice");
    assert!(list[0].get("path").is_none());
    assert_eq!(list[0]["password"]["type"], "mnemonic_derived");
    assert_eq!(list[0]["password"]["path"], "m/passwords/0");
}

#[test]
fn derive_password_matches_stored_login_password() {
    let dir = tempdir().unwrap();
    let vault = dir.path().join("vault.blob");

    mlocker()
        .args(["init", "--vault"])
        .arg(&vault)
        .args(["--mnemonic", MNEMONIC])
        .assert()
        .success();

    mlocker()
        .env("MLOCKER_MNEMONIC", MNEMONIC)
        .args(["add-login", "--vault"])
        .arg(&vault)
        .args([
            "--title",
            "Example",
            "--username",
            "alice",
            "--url",
            "https://example.com",
        ])
        .assert()
        .success();

    let from_vault = mlocker()
        .env("MLOCKER_MNEMONIC", MNEMONIC)
        .args(["get", "--vault"])
        .arg(&vault)
        .args(["Example", "--field", "password"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let standalone = mlocker()
        .args([
            "derive-password",
            "--mnemonic",
            MNEMONIC,
            "--site",
            "https://example.com",
            "--username",
            "alice",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    assert_eq!(from_vault, standalone);
}

#[test]
fn user_input_password_does_not_expose_password_path() {
    let dir = tempdir().unwrap();
    let vault = dir.path().join("vault.blob");

    mlocker()
        .args(["init", "--vault"])
        .arg(&vault)
        .args(["--mnemonic", MNEMONIC])
        .assert()
        .success();

    mlocker()
        .env("MLOCKER_MNEMONIC", MNEMONIC)
        .args(["add-login", "--vault"])
        .arg(&vault)
        .args([
            "--title",
            "Manual",
            "--username",
            "alice",
            "--url",
            "https://manual.example",
            "--password",
            "user-entered-secret",
        ])
        .assert()
        .success();

    let get_output = mlocker()
        .env("MLOCKER_MNEMONIC", MNEMONIC)
        .args(["get", "--vault"])
        .arg(&vault)
        .arg("Manual")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let item: Value = serde_json::from_slice(&get_output).unwrap();

    assert!(item.get("path").is_none());
    assert_eq!(item["password"]["type"], "user_input");
    assert!(item["password"].get("path").is_none());
    assert_eq!(item["password"]["value"], "user-entered-secret");

    mlocker()
        .env("MLOCKER_MNEMONIC", MNEMONIC)
        .args(["get", "--vault"])
        .arg(&vault)
        .args(["Manual", "--field", "password"])
        .assert()
        .success()
        .stdout("user-entered-secret\n");
}

#[test]
fn edit_and_delete_login_round_trip() {
    let dir = tempdir().unwrap();
    let vault = dir.path().join("vault.blob");

    mlocker()
        .args(["init", "--vault"])
        .arg(&vault)
        .args(["--mnemonic", MNEMONIC])
        .assert()
        .success();

    mlocker()
        .env("MLOCKER_MNEMONIC", MNEMONIC)
        .args(["add-login", "--vault"])
        .arg(&vault)
        .args([
            "--title",
            "Example",
            "--username",
            "alice",
            "--url",
            "https://example.com",
        ])
        .assert()
        .success();

    mlocker()
        .env("MLOCKER_MNEMONIC", MNEMONIC)
        .args(["edit-login", "--vault"])
        .arg(&vault)
        .args([
            "Example",
            "--title",
            "Example Prod",
            "--username",
            "ops@example.com",
            "--password",
            "rotated-secret",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"title\": \"Example Prod\""))
        .stdout(predicate::str::contains(
            "\"username\": \"ops@example.com\"",
        ));

    mlocker()
        .env("MLOCKER_MNEMONIC", MNEMONIC)
        .args(["get", "--vault"])
        .arg(&vault)
        .args(["Example Prod", "--field", "password"])
        .assert()
        .success()
        .stdout("rotated-secret\n");

    mlocker()
        .env("MLOCKER_MNEMONIC", MNEMONIC)
        .args(["delete-login", "--vault"])
        .arg(&vault)
        .arg("Example Prod")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"title\": \"Example Prod\""));

    mlocker()
        .env("MLOCKER_MNEMONIC", MNEMONIC)
        .args(["list", "--vault"])
        .arg(&vault)
        .assert()
        .success()
        .stdout("[]\n");
}

#[test]
fn import_logins_from_csv_creates_and_updates_items() {
    let dir = tempdir().unwrap();
    let vault = dir.path().join("vault.blob");
    let csv = dir.path().join("chrome.csv");

    mlocker()
        .args(["init", "--vault"])
        .arg(&vault)
        .args(["--mnemonic", MNEMONIC])
        .assert()
        .success();

    std::fs::write(
        &csv,
        "name,url,username,password\nExample,https://example.com,alice,first-secret\n",
    )
    .unwrap();
    mlocker()
        .env("MLOCKER_MNEMONIC", MNEMONIC)
        .args(["import", "--vault"])
        .arg(&vault)
        .args(["--file"])
        .arg(&csv)
        .assert()
        .success()
        .stdout(predicate::str::contains("\"created\": 1"))
        .stdout(predicate::str::contains("\"updated\": 0"));

    std::fs::write(
        &csv,
        "name,url,username,password\nExample,https://example.com,alice,rotated-secret\nSecond,https://second.example,bob,second-secret\n",
    )
    .unwrap();
    mlocker()
        .env("MLOCKER_MNEMONIC", MNEMONIC)
        .args(["import", "--vault"])
        .arg(&vault)
        .args(["--file"])
        .arg(&csv)
        .assert()
        .success()
        .stdout(predicate::str::contains("\"created\": 1"))
        .stdout(predicate::str::contains("\"updated\": 1"));

    mlocker()
        .env("MLOCKER_MNEMONIC", MNEMONIC)
        .args(["get", "--vault"])
        .arg(&vault)
        .args(["Example", "--field", "password"])
        .assert()
        .success()
        .stdout("rotated-secret\n");

    let list_output = mlocker()
        .env("MLOCKER_MNEMONIC", MNEMONIC)
        .args(["list", "--vault"])
        .arg(&vault)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let list: Value = serde_json::from_slice(&list_output).unwrap();

    assert_eq!(list.as_array().unwrap().len(), 2);
}

#[test]
fn import_and_export_provider_csv_formats() {
    let dir = tempdir().unwrap();
    let vault = dir.path().join("vault.blob");
    let keychain_csv = dir.path().join("keychain.csv");
    let one_password_csv = dir.path().join("one-password.csv");
    let exported_keychain_csv = dir.path().join("export-keychain.csv");

    mlocker()
        .args(["init", "--vault"])
        .arg(&vault)
        .args(["--mnemonic", MNEMONIC])
        .assert()
        .success();

    std::fs::write(
        &keychain_csv,
        "Title,URL,Username,Password,Notes,OTPAuth\nKeychain,https://keychain.example,alice,keychain-secret,\"keychain note\",otpauth://totp/Keychain?secret=JBSWY3DPEHPK3PXP\n",
    )
    .unwrap();
    mlocker()
        .env("MLOCKER_MNEMONIC", MNEMONIC)
        .args(["import", "--vault"])
        .arg(&vault)
        .args(["--file"])
        .arg(&keychain_csv)
        .args(["--format", "keychain-csv"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"created\": 1"));

    mlocker()
        .env("MLOCKER_MNEMONIC", MNEMONIC)
        .args(["export", "--vault"])
        .arg(&vault)
        .args(["--file"])
        .arg(&one_password_csv)
        .args(["--format", "1password-csv"])
        .assert()
        .success();

    let one_password_export = std::fs::read_to_string(&one_password_csv).unwrap();
    assert!(one_password_export.starts_with("Title,Website,Username,Password,One-time password"));
    assert!(one_password_export.contains("keychain-secret"));
    assert!(one_password_export.contains("keychain note"));

    mlocker()
        .env("MLOCKER_MNEMONIC", MNEMONIC)
        .args(["export", "--vault"])
        .arg(&vault)
        .args(["--file"])
        .arg(&exported_keychain_csv)
        .args(["--format", "keychain-csv"])
        .assert()
        .success();

    let keychain_export = std::fs::read_to_string(&exported_keychain_csv).unwrap();
    assert!(keychain_export.starts_with("Title,URL,Username,Password,Notes,OTPAuth"));
    assert!(keychain_export.contains("keychain note"));
    assert!(keychain_export.contains("JBSWY3DPEHPK3PXP"));
}

#[test]
fn export_logins_writes_decrypted_csv() {
    let dir = tempdir().unwrap();
    let vault = dir.path().join("vault.blob");
    let csv = dir.path().join("export.csv");

    mlocker()
        .args(["init", "--vault"])
        .arg(&vault)
        .args(["--mnemonic", MNEMONIC])
        .assert()
        .success();

    mlocker()
        .env("MLOCKER_MNEMONIC", MNEMONIC)
        .args(["add-login", "--vault"])
        .arg(&vault)
        .args([
            "--title",
            "Example, Inc",
            "--username",
            "alice",
            "--url",
            "https://example.com",
            "--password",
            "quoted\"secret",
        ])
        .assert()
        .success();

    mlocker()
        .env("MLOCKER_MNEMONIC", MNEMONIC)
        .args(["export", "--vault"])
        .arg(&vault)
        .args(["--file"])
        .arg(&csv)
        .assert()
        .success();

    let exported = std::fs::read_to_string(csv).unwrap();

    assert!(exported.contains("\"Example, Inc\""));
    assert!(exported.contains("\"quoted\"\"secret\""));
}

#[test]
fn password_wrapped_vault_works_without_mnemonic_env() {
    let dir = tempdir().unwrap();
    let vault = dir.path().join("vault.blob");

    mlocker()
        .args(["init", "--vault"])
        .arg(&vault)
        .args(["--mnemonic", MNEMONIC, "--password", "local-password"])
        .assert()
        .success()
        .stdout(predicate::str::contains("MLOCKER_PASSWORD"));

    mlocker()
        .env("MLOCKER_PASSWORD", "local-password")
        .args(["add-login", "--vault"])
        .arg(&vault)
        .args([
            "--title",
            "Example",
            "--username",
            "alice",
            "--url",
            "https://example.com",
        ])
        .assert()
        .success();

    let password_output = mlocker()
        .env("MLOCKER_PASSWORD", "local-password")
        .args(["get", "--vault"])
        .arg(&vault)
        .args(["Example", "--field", "password"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let password = String::from_utf8(password_output).unwrap();

    assert_eq!(password.trim().len(), 24);

    let request = native_message(serde_json::json!({
        "type": "credential_query",
        "origin": "https://example.com",
        "url": "https://example.com/login"
    }));
    let response_output = mlocker()
        .env("MLOCKER_PASSWORD", "local-password")
        .args(["browser-host", "run", "--vault"])
        .arg(&vault)
        .write_stdin(request)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let response = decode_native_message(&response_output);

    assert_eq!(response["type"], "credential_suggestions");
    assert_eq!(response["items"][0]["title"], "Example");
    assert_eq!(response["items"][0]["password"], password.trim());
}

#[test]
fn sync_exports_and_imports_encrypted_blob() {
    let dir = tempdir().unwrap();
    let vault = dir.path().join("vault.blob");
    let imported = dir.path().join("restored.blob");
    let cloud_dir = dir.path().join("cloud");

    mlocker()
        .args(["init", "--vault"])
        .arg(&vault)
        .args(["--mnemonic", MNEMONIC])
        .assert()
        .success();

    mlocker()
        .args(["sync", "export", "--vault"])
        .arg(&vault)
        .args(["--cloud-dir"])
        .arg(&cloud_dir)
        .assert()
        .success()
        .stdout(predicate::str::contains("Exported encrypted vault"));

    std::fs::copy(
        cloud_dir.join("vault.blob"),
        cloud_dir.join("restored.blob"),
    )
    .unwrap();

    mlocker()
        .args(["sync", "import", "--vault"])
        .arg(&imported)
        .args(["--cloud-dir"])
        .arg(&cloud_dir)
        .assert()
        .success()
        .stdout(predicate::str::contains("Imported encrypted vault"));

    mlocker()
        .env("MLOCKER_MNEMONIC", MNEMONIC)
        .args(["list", "--vault"])
        .arg(&imported)
        .assert()
        .success()
        .stdout(predicate::str::contains("[]"));
}

#[test]
fn inject_renders_secret_references_from_stdin() {
    let dir = tempdir().unwrap();
    let vault = dir.path().join("vault.blob");

    mlocker()
        .args(["init", "--vault"])
        .arg(&vault)
        .args(["--mnemonic", MNEMONIC])
        .assert()
        .success();

    mlocker()
        .env("MLOCKER_MNEMONIC", MNEMONIC)
        .args(["add-login", "--vault"])
        .arg(&vault)
        .args([
            "--title",
            "Example Prod",
            "--username",
            "alice",
            "--url",
            "https://example.com",
            "--password",
            "stored-secret",
        ])
        .assert()
        .success();

    mlocker()
        .env("MLOCKER_MNEMONIC", MNEMONIC)
        .args(["inject", "--vault"])
        .arg(&vault)
        .write_stdin(
            "USER=mlocker://Example%20Prod/username\nPASS=mlocker://Example%20Prod/password\n",
        )
        .assert()
        .success()
        .stdout("USER=alice\nPASS=stored-secret\n");
}

#[test]
fn browser_host_manifest_generates_firefox_native_manifest() {
    mlocker()
        .args([
            "browser-host",
            "manifest",
            "--browser",
            "firefox",
            "--extension-id",
            "mlocker@example.local",
            "--host-path",
            "/usr/local/bin/mlocker-browser-host",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"name\": \"com.mlocker.native\""))
        .stdout(predicate::str::contains("\"allowed_extensions\""))
        .stdout(predicate::str::contains("\"mlocker@example.local\""));
}

#[test]
fn browser_host_native_protocol_returns_origin_matched_credentials() {
    let dir = tempdir().unwrap();
    let vault = dir.path().join("vault.blob");

    mlocker()
        .args(["init", "--vault"])
        .arg(&vault)
        .args(["--mnemonic", MNEMONIC])
        .assert()
        .success();

    mlocker()
        .env("MLOCKER_MNEMONIC", MNEMONIC)
        .args(["add-login", "--vault"])
        .arg(&vault)
        .args([
            "--title",
            "Example",
            "--username",
            "alice",
            "--url",
            "https://example.com/login",
            "--password",
            "stored-secret",
        ])
        .assert()
        .success();

    let request = native_message(serde_json::json!({
        "type": "credential_query",
        "origin": "https://accounts.example.com",
        "url": "https://accounts.example.com/login"
    }));
    let output = mlocker()
        .env("MLOCKER_MNEMONIC", MNEMONIC)
        .args(["browser-host", "run", "--vault"])
        .arg(&vault)
        .write_stdin(request)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let response = decode_native_message(&output);

    assert_eq!(response["type"], "credential_suggestions");
    assert_eq!(response["items"][0]["title"], "Example");
    assert_eq!(response["items"][0]["username"], "alice");
    assert_eq!(response["items"][0]["password"], "stored-secret");
}

#[test]
fn browser_host_native_protocol_saves_login_to_vault() {
    let dir = tempdir().unwrap();
    let vault = dir.path().join("vault.blob");

    mlocker()
        .args(["init", "--vault"])
        .arg(&vault)
        .args(["--mnemonic", MNEMONIC])
        .assert()
        .success();

    let save_request = native_message(serde_json::json!({
        "type": "save_login",
        "origin": "https://example.com",
        "url": "https://example.com/login",
        "title": "Example",
        "username": "alice",
        "password": "typed-secret"
    }));
    let save_output = mlocker()
        .env("MLOCKER_MNEMONIC", MNEMONIC)
        .args(["browser-host", "run", "--vault"])
        .arg(&vault)
        .write_stdin(save_request)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let save_response = decode_native_message(&save_output);

    assert_eq!(save_response["type"], "saved_login");
    assert_eq!(save_response["item"]["title"], "Example");
    assert_eq!(save_response["item"]["username"], "alice");

    let update_request = native_message(serde_json::json!({
        "type": "save_login",
        "origin": "https://example.com",
        "url": "https://example.com/settings",
        "title": "Example Updated",
        "username": "alice",
        "password": "rotated-secret"
    }));
    let update_output = mlocker()
        .env("MLOCKER_MNEMONIC", MNEMONIC)
        .args(["browser-host", "run", "--vault"])
        .arg(&vault)
        .write_stdin(update_request)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let update_response = decode_native_message(&update_output);

    assert_eq!(update_response["type"], "saved_login");
    assert_eq!(update_response["item"]["title"], "Example Updated");
    assert_eq!(update_response["item"]["password"], "rotated-secret");

    mlocker()
        .env("MLOCKER_MNEMONIC", MNEMONIC)
        .args(["get", "--vault"])
        .arg(&vault)
        .args(["Example Updated", "--field", "password"])
        .assert()
        .success()
        .stdout("rotated-secret\n");

    let list_output = mlocker()
        .env("MLOCKER_MNEMONIC", MNEMONIC)
        .args(["list", "--vault"])
        .arg(&vault)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let list: Value = serde_json::from_slice(&list_output).unwrap();

    assert_eq!(list.as_array().unwrap().len(), 1);
}

#[test]
fn vault_commands_require_unlock_env() {
    let dir = tempdir().unwrap();
    let vault = dir.path().join("vault.blob");

    mlocker()
        .args(["init", "--vault"])
        .arg(&vault)
        .args(["--mnemonic", MNEMONIC])
        .assert()
        .success();

    mlocker()
        .args(["list", "--vault"])
        .arg(&vault)
        .assert()
        .failure()
        .stderr(predicate::str::contains("MLOCKER_MNEMONIC"));
}

fn mlocker() -> Command {
    Command::cargo_bin("mlocker").unwrap()
}

fn native_message(value: Value) -> Vec<u8> {
    let body = serde_json::to_vec(&value).unwrap();
    let mut framed = Vec::with_capacity(4 + body.len());
    framed.extend_from_slice(&(body.len() as u32).to_le_bytes());
    framed.extend_from_slice(&body);
    framed
}

fn decode_native_message(output: &[u8]) -> Value {
    assert!(output.len() >= 4);
    let len = u32::from_le_bytes(output[..4].try_into().unwrap()) as usize;
    assert_eq!(output.len(), 4 + len);
    serde_json::from_slice(&output[4..]).unwrap()
}
