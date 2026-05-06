use std::process::ExitCode;

fn main() -> ExitCode {
    match mlocker_cli::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}
