use std::fs;
use std::io::{Read, Write};
use std::{ffi::OsString, path::PathBuf};

use anyhow::{bail, Context, Result};
use clap::{CommandFactory, Parser};
use mlocker_core::{derive_ssh_key_from_root_key, generate_mnemonic, generate_totp_now};
use serde::Serialize;

use crate::browser_host as browser_host_support;
use crate::cli::{
    AddLoginArgs, BrowserHostArgs, BrowserHostCommand, Cli, Command, DeleteLoginArgs,
    CompletionArgs, DerivePasswordArgs, EditLoginArgs, ExportLoginsArgs, GetArgs, GetField,
    ImportLoginsArgs, InitArgs, InjectArgs, ListArgs, SshAgentArgs, SyncArgs, SyncCommand,
    SyncTransferArgs, WalletArgs,
};
use crate::core_adapter;
use crate::importer;
use crate::inject as inject_support;
use crate::ssh_agent::{self, AgentIdentity};
use crate::vault::{self, LoginItem};

const MNEMONIC_ENV: &str = "MLOCKER_MNEMONIC";
const PASSWORD_ENV: &str = "MLOCKER_PASSWORD";

pub fn run<I, T, W>(args: I, output: &mut W) -> Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
    W: Write,
{
    let cli = Cli::parse_from(args);

    match cli.command {
        Command::Init(args) => init(args, output),
        Command::AddLogin(args) => add_login(args, output),
        Command::EditLogin(args) => edit_login(args, output),
        Command::DeleteLogin(args) => delete_login(args, output),
        Command::ImportLogins(args) => import_logins(args, output),
        Command::ExportLogins(args) => export_logins(args, output),
        Command::Get(args) => get(args, output),
        Command::List(args) => list(args, output),
        Command::Inject(args) => inject(args, output),
        Command::DerivePassword(args) => derive_password(args, output),
        Command::Wallet(args) => wallet(args, output),
        Command::Sync(args) => sync(args, output),
        Command::SshAgent(args) => ssh_agent(args, output),
        Command::BrowserHost(args) => browser_host(args, output),
        Command::Completion(args) => completion(args, output),
    }
}

fn init(args: InitArgs, output: &mut impl Write) -> Result<()> {
    let (mnemonic, generated) = match args.mnemonic {
        Some(mnemonic) => (mnemonic, false),
        None => (generate_mnemonic(12)?.expose_phrase().to_owned(), true),
    };

    if let Some(password) = &args.password {
        vault::create_password_vault(&args.vault, &mnemonic, password)?;
    } else {
        vault::create_vault(&args.vault, &mnemonic)?;
    }
    writeln!(output, "Vault initialized: {}", args.vault.display())?;
    if generated {
        writeln!(output, "Mnemonic: {mnemonic}")?;
        writeln!(
            output,
            "Set {MNEMONIC_ENV} to this phrase before running vault commands."
        )?;
    }
    if args.password.is_some() {
        writeln!(
            output,
            "Set {PASSWORD_ENV} to unlock this password-protected vault."
        )?;
    }
    Ok(())
}

fn add_login(args: AddLoginArgs, output: &mut impl Write) -> Result<()> {
    let mut unlocked = unlock_vault(&args.vault)?;
    let item = vault::add_login(
        &mut unlocked.state,
        args.title,
        args.username,
        args.url,
        args.path,
        args.password,
        args.totp,
    )?;
    vault::save_unlocked_vault(&args.vault, &unlocked)?;

    let password = login_password_value(&unlocked, &item)?;
    let password_output = PasswordOutput::with_value(&item.password, &password);
    let totp = item
        .totp
        .as_ref()
        .and_then(|totp| generate_totp_now(&totp.secret).ok().map(|code| code.code));
    let response = AddedLoginOutput {
        id: item.id,
        title: item.title,
        username: item.username,
        url: item.url,
        password: password_output,
        totp,
    };
    write_json(output, &response)
}

fn edit_login(args: EditLoginArgs, output: &mut impl Write) -> Result<()> {
    let mut unlocked = unlock_vault(&args.vault)?;
    let item = vault::edit_login(
        &mut unlocked.state,
        &args.query,
        vault::EditLoginRequest {
            title: args.title,
            username: args.username,
            url: args.url,
            path: args.path,
            password: args.password,
            totp: args.totp,
            clear_totp: args.clear_totp,
        },
    )?;
    vault::save_unlocked_vault(&args.vault, &unlocked)?;

    let password = login_password_value(&unlocked, &item)?;
    let response = LoginOutput::from_item(&item, password);
    write_json(output, &response)
}

fn delete_login(args: DeleteLoginArgs, output: &mut impl Write) -> Result<()> {
    let mut unlocked = unlock_vault(&args.vault)?;
    let item = vault::delete_login(&mut unlocked.state, &args.query)?;
    vault::save_unlocked_vault(&args.vault, &unlocked)?;

    let response = DeletedLoginOutput {
        id: item.id,
        title: item.title,
        username: item.username,
        url: item.url,
    };
    write_json(output, &response)
}

fn import_logins(args: ImportLoginsArgs, output: &mut impl Write) -> Result<()> {
    let mut unlocked = unlock_vault(&args.vault)?;
    let input = fs::read_to_string(&args.file)
        .with_context(|| format!("read login import file {}", args.file.display()))?;
    let imported = importer::parse_login_import(&input, args.format)?;
    let parsed = imported.len();
    let summary = vault::import_logins(
        &mut unlocked.state,
        imported
            .into_iter()
            .map(|login| vault::ImportLoginRequest {
                title: login.title,
                username: login.username,
                url: login.url,
                password: login.password,
                totp: login.totp,
            })
            .collect(),
    )?;
    vault::save_unlocked_vault(&args.vault, &unlocked)?;

    let response = ImportLoginsOutput {
        parsed,
        created: summary.created,
        updated: summary.updated,
    };
    write_json(output, &response)
}

fn export_logins(args: ExportLoginsArgs, output: &mut impl Write) -> Result<()> {
    let unlocked = unlock_vault(&args.vault)?;
    let mut exported = Vec::with_capacity(unlocked.state.items.len());
    for item in &unlocked.state.items {
        exported.push(importer::ExportedLogin {
            title: item.title.clone(),
            username: item.username.clone(),
            url: item.url.clone(),
            password: login_password_value(&unlocked, item)?,
            totp: item.totp.as_ref().map(|totp| totp.secret.clone()),
        });
    }
    let csv = importer::format_login_csv(&exported);
    match args.file {
        Some(path) => fs::write(&path, csv)
            .with_context(|| format!("write login export file {}", path.display())),
        None => {
            output.write_all(csv.as_bytes())?;
            Ok(())
        }
    }
}

fn get(args: GetArgs, output: &mut impl Write) -> Result<()> {
    let unlocked = unlock_vault(&args.vault)?;
    let item = unlocked.state.find_login(&args.query)?;
    let password = login_password_value(&unlocked, item)?;

    match args.field {
        Some(GetField::Password) => writeln!(output, "{password}")?,
        Some(GetField::Username) => writeln!(output, "{}", item.username)?,
        Some(GetField::Url) => writeln!(output, "{}", item.url)?,
        Some(GetField::Totp) => {
            let Some(totp) = &item.totp else {
                bail!("totp is not stored for this login item");
            };
            let code = generate_totp_now(&totp.secret)?;
            writeln!(output, "{}", code.code)?
        }
        None => {
            let response = LoginOutput::from_item(item, password);
            write_json(output, &response)?;
        }
    }

    Ok(())
}

fn list(args: ListArgs, output: &mut impl Write) -> Result<()> {
    let unlocked = unlock_vault(&args.vault)?;
    let items: Vec<_> = unlocked
        .state
        .items
        .iter()
        .map(ListItemOutput::from_item)
        .collect();
    write_json(output, &items)
}

fn inject(args: InjectArgs, output: &mut impl Write) -> Result<()> {
    let unlocked = unlock_vault(&args.vault)?;
    let input = match args.input {
        Some(path) => fs::read_to_string(&path)
            .with_context(|| format!("read inject template {}", path.display()))?,
        None => {
            let mut input = String::new();
            std::io::stdin()
                .read_to_string(&mut input)
                .context("read inject template from stdin")?;
            input
        }
    };
    let rendered = inject_support::render_template(&input, &unlocked)?;

    match args.output {
        Some(path) => fs::write(&path, rendered)
            .with_context(|| format!("write injected output {}", path.display())),
        None => {
            output.write_all(rendered.as_bytes())?;
            Ok(())
        }
    }
}

fn derive_password(args: DerivePasswordArgs, output: &mut impl Write) -> Result<()> {
    let password = core_adapter::derive_password(
        &args.mnemonic,
        &args.site,
        &args.username,
        args.path.as_deref(),
    )?;
    writeln!(output, "{password}")?;
    Ok(())
}

fn wallet(args: WalletArgs, output: &mut impl Write) -> Result<()> {
    let unlocked = unlock_vault(&args.vault)?;
    let mnemonic = unlocked.mnemonic.as_deref().ok_or_else(|| {
        anyhow::anyhow!("wallet derivation requires MLOCKER_MNEMONIC for this MVP")
    })?;
    let wallet = core_adapter::derive_wallet(mnemonic, args.chain, args.index)?;
    write_json(output, &wallet)
}

fn sync(args: SyncArgs, output: &mut impl Write) -> Result<()> {
    match args.command {
        SyncCommand::Export(args) => sync_export(args, output),
        SyncCommand::Import(args) => sync_import(args, output),
    }
}

fn sync_export(args: SyncTransferArgs, output: &mut impl Write) -> Result<()> {
    let target = vault::copy_export(&args.vault, &args.cloud_dir)?;
    writeln!(output, "Exported encrypted vault: {}", target.display())?;
    Ok(())
}

fn sync_import(args: SyncTransferArgs, output: &mut impl Write) -> Result<()> {
    let source = vault::copy_import(&args.vault, &args.cloud_dir)?;
    writeln!(output, "Imported encrypted vault: {}", source.display())?;
    Ok(())
}

fn ssh_agent(args: SshAgentArgs, output: &mut impl Write) -> Result<()> {
    let unlocked = unlock_vault(&args.vault)?;
    let identities = unlocked
        .state
        .ssh_keys()
        .iter()
        .map(|key| {
            let comment = key.comment.clone().unwrap_or_else(|| key.label.clone());
            let derived =
                derive_ssh_key_from_root_key(&unlocked.root_key, &key.derivation_path, &comment)?;
            Ok(AgentIdentity {
                comment,
                derivation_path: key.derivation_path.clone(),
                key_blob: derived.public_key_blob,
                public_key_openssh: derived.public_key_openssh,
            })
        })
        .collect::<mlocker_core::Result<Vec<_>>>()?;
    if identities.is_empty() {
        bail!("no SSH key items found; add an SSH key item to the vault first");
    }

    let socket = args.socket.unwrap_or_else(default_ssh_agent_socket);
    writeln!(output, "SSH_AUTH_SOCK={}", socket.display())?;
    writeln!(output, "export SSH_AUTH_SOCK")?;
    for identity in &identities {
        writeln!(output, "{}", identity.public_key_openssh)?;
    }
    output.flush()?;

    ssh_agent::serve(&socket, identities, unlocked.root_key)
}

fn browser_host(args: BrowserHostArgs, output: &mut impl Write) -> Result<()> {
    match args.command {
        BrowserHostCommand::Run(args) => {
            browser_host_support::run_native_host(&args.vault, &mut std::io::stdin(), output)
        }
        BrowserHostCommand::Configure(args) => {
            let config_path =
                browser_host_support::write_config(args.config.as_deref(), &args.vault)?;
            writeln!(output, "Configured browser host: {}", config_path.display())
                .map_err(Into::into)
        }
        BrowserHostCommand::Manifest(args) => {
            let host_path = match args.host_path {
                Some(path) => path,
                None => browser_host_support::default_host_executable_path()?,
            };
            let manifest = browser_host_support::render_manifest(
                args.browser,
                &args.extension_id,
                &host_path,
            )?;
            match args.out {
                Some(path) => {
                    if let Some(parent) = path.parent() {
                        fs::create_dir_all(parent).with_context(|| {
                            format!("create manifest output directory {}", parent.display())
                        })?;
                    }
                    fs::write(&path, manifest)
                        .with_context(|| format!("write manifest {}", path.display()))?;
                    writeln!(
                        output,
                        "Wrote native messaging manifest: {}",
                        path.display()
                    )
                    .map_err(Into::into)
                }
                None => {
                    writeln!(output, "{manifest}")?;
                    Ok(())
                }
            }
        }
        BrowserHostCommand::Install(args) => {
            let config_path =
                browser_host_support::write_config(args.config.as_deref(), &args.vault)?;
            let host_path = match args.host_path {
                Some(path) => path,
                None => browser_host_support::default_host_executable_path()?,
            };
            let manifest_path = browser_host_support::install_manifest(
                args.browser,
                &args.extension_id,
                &host_path,
                args.manifest_dir.as_deref(),
            )?;
            writeln!(output, "Configured browser host: {}", config_path.display())?;
            writeln!(
                output,
                "Installed native messaging manifest: {}",
                manifest_path.display()
            )?;
            writeln!(output, "Host executable: {}", host_path.display()).map_err(Into::into)
        }
    }
}

fn completion(args: CompletionArgs, output: &mut impl Write) -> Result<()> {
    let mut command = Cli::command();
    clap_complete::generate(args.shell, &mut command, "mlocker", output);
    Ok(())
}

fn default_ssh_agent_socket() -> PathBuf {
    std::env::temp_dir().join(format!("mlocker-agent-{}.sock", std::process::id()))
}

fn unlock_vault(path: &std::path::Path) -> Result<vault::UnlockedVault> {
    let mnemonic = optional_env(MNEMONIC_ENV)?;
    let password = optional_env(PASSWORD_ENV)?;
    vault::unlock_vault(path, mnemonic.as_deref(), password.as_deref())
}

fn optional_env(name: &str) -> Result<Option<String>> {
    match std::env::var(name) {
        Ok(value) if value.trim().is_empty() => bail!("{name} must not be empty"),
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(err) => Err(err).with_context(|| format!("read {name}")),
    }
}

fn login_password_value(unlocked: &vault::UnlockedVault, item: &LoginItem) -> Result<String> {
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

fn write_json(output: &mut impl Write, value: &impl Serialize) -> Result<()> {
    serde_json::to_writer_pretty(&mut *output, value)?;
    writeln!(output)?;
    Ok(())
}

#[derive(Debug, Serialize)]
struct AddedLoginOutput {
    id: String,
    title: String,
    username: String,
    url: String,
    password: PasswordOutput,
    #[serde(skip_serializing_if = "Option::is_none")]
    totp: Option<String>,
}

#[derive(Debug, Serialize)]
struct LoginOutput<'a> {
    id: &'a str,
    title: &'a str,
    username: &'a str,
    url: &'a str,
    password: PasswordOutput,
    #[serde(skip_serializing_if = "Option::is_none")]
    totp: Option<String>,
}

#[derive(Debug, Serialize)]
struct DeletedLoginOutput {
    id: String,
    title: String,
    username: String,
    url: String,
}

#[derive(Debug, Serialize)]
struct ImportLoginsOutput {
    parsed: usize,
    created: usize,
    updated: usize,
}

impl<'a> LoginOutput<'a> {
    fn from_item(item: &'a LoginItem, password: String) -> Self {
        Self {
            id: &item.id,
            title: &item.title,
            username: &item.username,
            url: &item.url,
            password: PasswordOutput::with_value(&item.password, &password),
            totp: item
                .totp
                .as_ref()
                .and_then(|totp| generate_totp_now(&totp.secret).ok().map(|code| code.code)),
        }
    }
}

#[derive(Debug, Serialize)]
struct ListItemOutput<'a> {
    id: &'a str,
    title: &'a str,
    username: &'a str,
    url: &'a str,
    password: PasswordOutput,
    has_totp: bool,
}

impl<'a> ListItemOutput<'a> {
    fn from_item(item: &'a LoginItem) -> Self {
        Self {
            id: &item.id,
            title: &item.title,
            username: &item.username,
            url: &item.url,
            password: PasswordOutput::metadata(&item.password),
            has_totp: item.totp.is_some(),
        }
    }
}

#[derive(Debug, Serialize)]
struct PasswordOutput {
    #[serde(rename = "type")]
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
}

impl PasswordOutput {
    fn metadata(password: &mlocker_core::LoginPassword) -> Self {
        match password {
            mlocker_core::LoginPassword::MnemonicDerived { path } => Self {
                kind: "mnemonic_derived",
                path: Some(path.clone()),
                value: None,
            },
            mlocker_core::LoginPassword::UserInput { .. } => Self {
                kind: "user_input",
                path: None,
                value: None,
            },
        }
    }

    fn with_value(password: &mlocker_core::LoginPassword, value: &str) -> Self {
        let mut output = Self::metadata(password);
        output.value = Some(value.to_owned());
        output
    }
}
