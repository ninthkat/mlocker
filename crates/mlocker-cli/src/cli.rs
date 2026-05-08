use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;

#[derive(Debug, Parser)]
#[command(name = "mlocker")]
#[command(about = "mlocker password-manager MVP CLI")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Init(InitArgs),
    AddLogin(AddLoginArgs),
    EditLogin(EditLoginArgs),
    DeleteLogin(DeleteLoginArgs),
    #[command(name = "import", alias = "import-logins")]
    Import(ImportArgs),
    #[command(name = "export", alias = "export-logins")]
    Export(ExportArgs),
    Get(GetArgs),
    List(ListArgs),
    Inject(InjectArgs),
    DerivePassword(DerivePasswordArgs),
    Wallet(WalletArgs),
    Sync(SyncArgs),
    SshAgent(SshAgentArgs),
    BrowserHost(BrowserHostArgs),
    Completion(CompletionArgs),
}

#[derive(Debug, Args)]
pub struct InitArgs {
    #[arg(long)]
    pub vault: PathBuf,
    #[arg(long)]
    pub mnemonic: Option<String>,
    #[arg(long)]
    pub password: Option<String>,
}

#[derive(Debug, Args)]
pub struct AddLoginArgs {
    #[arg(long)]
    pub vault: PathBuf,
    #[arg(long)]
    pub title: String,
    #[arg(long)]
    pub username: String,
    #[arg(long)]
    pub url: String,
    #[arg(long)]
    pub path: Option<String>,
    #[arg(long, conflicts_with = "path")]
    pub password: Option<String>,
    #[arg(long)]
    pub totp: Option<String>,
}

#[derive(Debug, Args)]
pub struct EditLoginArgs {
    #[arg(long)]
    pub vault: PathBuf,
    pub query: String,
    #[arg(long)]
    pub title: Option<String>,
    #[arg(long)]
    pub username: Option<String>,
    #[arg(long)]
    pub url: Option<String>,
    #[arg(long, conflicts_with = "password")]
    pub path: Option<String>,
    #[arg(long, conflicts_with = "path")]
    pub password: Option<String>,
    #[arg(long, conflicts_with = "clear_totp")]
    pub totp: Option<String>,
    #[arg(long)]
    pub clear_totp: bool,
}

#[derive(Debug, Args)]
pub struct DeleteLoginArgs {
    #[arg(long)]
    pub vault: PathBuf,
    pub query: String,
}

#[derive(Debug, Args)]
pub struct ImportArgs {
    #[arg(long)]
    pub vault: PathBuf,
    #[arg(long)]
    pub file: PathBuf,
    #[arg(long, value_enum, default_value_t = ImportFormat::Auto)]
    pub format: ImportFormat,
}

#[derive(Debug, Args)]
pub struct ExportArgs {
    #[arg(long)]
    pub vault: PathBuf,
    #[arg(long)]
    pub file: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = ExportFormat::Generic)]
    pub format: ExportFormat,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum ImportFormat {
    Auto,
    Chrome,
    Bitwarden,
    GenericCsv,
    #[value(name = "1password-csv", alias = "one-password-csv")]
    OnePasswordCsv,
    #[value(name = "1password-json", alias = "one-password-json")]
    OnePasswordJson,
    #[value(
        name = "keychain-csv",
        alias = "apple-passwords-csv",
        alias = "safari-csv"
    )]
    KeychainCsv,
    GenericJson,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum ExportFormat {
    #[value(name = "generic-csv")]
    Generic,
    #[value(name = "1password-csv", alias = "one-password-csv")]
    OnePassword,
    #[value(
        name = "keychain-csv",
        alias = "apple-passwords-csv",
        alias = "safari-csv"
    )]
    Keychain,
}

#[derive(Debug, Args)]
pub struct GetArgs {
    #[arg(long)]
    pub vault: PathBuf,
    pub query: String,
    #[arg(long)]
    pub field: Option<GetField>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum GetField {
    Password,
    Username,
    Url,
    Totp,
}

#[derive(Debug, Args)]
pub struct ListArgs {
    #[arg(long)]
    pub vault: PathBuf,
}

#[derive(Debug, Args)]
pub struct InjectArgs {
    #[arg(long)]
    pub vault: PathBuf,
    #[arg(long = "in-file")]
    pub input: Option<PathBuf>,
    #[arg(long = "out-file")]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct DerivePasswordArgs {
    #[arg(long)]
    pub mnemonic: String,
    #[arg(long)]
    pub site: String,
    #[arg(long)]
    pub username: String,
    #[arg(long)]
    pub path: Option<String>,
}

#[derive(Debug, Args)]
pub struct WalletArgs {
    #[arg(long)]
    pub vault: PathBuf,
    #[arg(long)]
    pub chain: Chain,
    #[arg(long, default_value_t = 0)]
    pub index: u32,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Chain {
    Ethereum,
    Solana,
}

#[derive(Debug, Args)]
pub struct SyncArgs {
    #[command(subcommand)]
    pub command: SyncCommand,
}

#[derive(Debug, Subcommand)]
pub enum SyncCommand {
    Export(SyncTransferArgs),
    Import(SyncTransferArgs),
}

#[derive(Debug, Args)]
pub struct SyncTransferArgs {
    #[arg(long)]
    pub vault: PathBuf,
    #[arg(long)]
    pub cloud_dir: PathBuf,
}

#[derive(Debug, Args)]
pub struct SshAgentArgs {
    #[arg(long)]
    pub vault: PathBuf,
    #[arg(long)]
    pub socket: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct BrowserHostArgs {
    #[command(subcommand)]
    pub command: BrowserHostCommand,
}

#[derive(Debug, Args)]
pub struct CompletionArgs {
    #[arg(long, value_enum)]
    pub shell: Shell,
}

#[derive(Debug, Subcommand)]
pub enum BrowserHostCommand {
    Run(BrowserHostRunArgs),
    Configure(BrowserHostConfigureArgs),
    Manifest(BrowserHostManifestArgs),
    Install(BrowserHostInstallArgs),
}

#[derive(Debug, Args)]
pub struct BrowserHostRunArgs {
    #[arg(long)]
    pub vault: PathBuf,
}

#[derive(Debug, Args)]
pub struct BrowserHostConfigureArgs {
    #[arg(long)]
    pub vault: PathBuf,
    #[arg(long)]
    pub config: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct BrowserHostManifestArgs {
    #[arg(long)]
    pub browser: BrowserKind,
    #[arg(long)]
    pub extension_id: String,
    #[arg(long)]
    pub host_path: Option<PathBuf>,
    #[arg(long)]
    pub out: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct BrowserHostInstallArgs {
    #[arg(long)]
    pub vault: PathBuf,
    #[arg(long)]
    pub browser: BrowserKind,
    #[arg(long)]
    pub extension_id: String,
    #[arg(long)]
    pub host_path: Option<PathBuf>,
    #[arg(long)]
    pub config: Option<PathBuf>,
    #[arg(long)]
    pub manifest_dir: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum BrowserKind {
    Chrome,
    Chromium,
    Firefox,
}
