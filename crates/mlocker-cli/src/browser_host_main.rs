use std::process::ExitCode;

fn main() -> ExitCode {
    match mlocker_cli::run_browser_host_from_config() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}
