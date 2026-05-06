mod browser_host;
mod cli;
mod commands;
mod core_adapter;
mod importer;
mod inject;
mod ssh_agent;
mod vault;

use anyhow::Result;

pub fn run() -> Result<()> {
    commands::run(std::env::args_os(), &mut std::io::stdout())
}

pub fn run_browser_host_from_config() -> Result<()> {
    browser_host::run_from_default_config(&mut std::io::stdin(), &mut std::io::stdout())
}
