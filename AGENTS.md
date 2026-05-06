# mlocker Agent Guide

mlocker is a Rust workspace for a cross-platform password manager MVP inspired by 1Password and Bitwarden. It is not Microsoft BitLocker.

## Build and Test

- `cargo fmt --all` formats all crates.
- `cargo test --workspace` runs core, CLI, and desktop tests.
- `cargo check --workspace` checks all workspace members.
- `cargo clippy --workspace --all-targets -- -D warnings` is the quality gate.
- `cargo run -p mlocker-cli -- --help` starts the CLI.
- `cargo run -p mlocker-desktop` starts the native egui desktop app.

The workspace targets Rust `1.83` and edition `2021`. Keep GUI transitive dependency pins compatible with this toolchain.

## Architecture Map

- `crates/mlocker-core`: BIP39 recovery phrases, key derivation, XChaCha20Poly1305 vault encryption, deterministic passwords, wallet derivation, SSH key derivation, sync import/export, and shared domain types.
- `crates/mlocker-cli`: op-inspired command-line interface for scripting, `inject`, import/export, browser/Bitwarden CSV import/export, item create/list/get/edit/delete, wallet address derivation, SSH agent/native browser host, and diagnostics.
- `crates/mlocker-desktop`: lightweight `eframe`/`egui` GUI for open/restore, item browsing, derived/user-entered login creation, and wallet address previews.
- `browser-extension`: Manifest V3 browser integration that calls the `com.mlocker.native` native messaging host for origin-bound login filling.
- `dist`: OS integration templates and installable packaging assets.
- `docs`: product plans, security notes, packaging notes, and release checklists.

Expected data flow:

1. Desktop and CLI collect user intent and validate input.
2. Core owns vault format, cryptography, derivation, sync conflict logic, and wallet/SSH key material.
3. Desktop and CLI never reimplement production crypto. Temporary UI previews must be clearly marked and kept out of vault persistence until replaced by core APIs.

## Repo Conventions

- Keep crate boundaries strict. UI code belongs in `crates/mlocker-desktop`; domain logic belongs in `crates/mlocker-core`; shell UX belongs in `crates/mlocker-cli`.
- Prefer small, typed interfaces over passing raw JSON between crates.
- Do not persist secrets in logs, screenshots, fixtures, panic messages, or docs.
- Use deterministic tests for derivation behavior and temporary directories for vault file tests.
- Add dependencies through workspace dependencies when they are shared by multiple crates.
- Keep docs current when user-facing commands or architecture boundaries change.

## Security Rules

- Core is the only production owner of encryption, KDF parameters, wallet derivation, SSH key derivation, vault serialization, and sync integrity checks.
- Treat passphrases, recovery phrases, private keys, derived passwords, session keys, and decrypted vault items as secrets.
- Zeroize secret buffers where practical and keep decrypted state scoped to the active session.
- Never add telemetry that includes item names, URLs, usernames, vault paths, addresses, recovery phrases, or derived secrets without an explicit privacy review.
- Clipboard writes must be user initiated and should gain timeout clearing before production release.
- SSH-agent functionality must require explicit unlock, origin checks, confirmation policies, and constrained signing rules.
- Wallet signing must display chain, address, derivation path, destination, amount, contract/function metadata, and network before approval.

## Subagent Ownership

- Core agent owns `crates/mlocker-core/**` and must expose stable APIs for vault, password, wallet, SSH, and sync operations.
- CLI agent owns `crates/mlocker-cli/**` and should mirror high-value `op` command shapes where feasible.
- Desktop/docs agent owns `crates/mlocker-desktop/**`, `README.md`, `AGENTS.md`, and `docs/**`.
- Packaging agent may add release assets under `dist/`, platform metadata, and CI jobs after coordinating with crate owners.
- Do not revert or overwrite another agent's files. If a cross-boundary change is required, leave a narrow TODO or coordinate before editing.
