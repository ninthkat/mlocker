# mlocker

mlocker is a Rust workspace for a cross-platform 1Password-like password manager MVP. It is Bitwarden-style vault software, not Microsoft BitLocker disk encryption.

## Quickstart

```sh
cargo test --workspace
cargo run -p mlocker-cli -- --help
cargo run -p mlocker-desktop
```

## CLI MVP

Create a vault, add a login, read it back, and export the encrypted blob to a cloud-drive folder:

```sh
cargo run -p mlocker-cli -- init --vault ./personal.vault
export MLOCKER_MNEMONIC="paste the generated phrase here"
cargo run -p mlocker-cli -- add-login --vault ./personal.vault \
  --title GitHub --username name@example.com --url https://github.com
cargo run -p mlocker-cli -- get --vault ./personal.vault GitHub --field password
cargo run -p mlocker-cli -- edit-login --vault ./personal.vault GitHub --title GitHub.com
cargo run -p mlocker-cli -- import --vault ./personal.vault --file ./chrome-passwords.csv
cargo run -p mlocker-cli -- import --vault ./personal.vault \
  --file ./1password.csv --format 1password-csv
cargo run -p mlocker-cli -- import --vault ./personal.vault \
  --file ./Passwords.csv --format keychain-csv
cargo run -p mlocker-cli -- export --vault ./personal.vault \
  --file ./mlocker-export.csv --format keychain-csv
cargo run -p mlocker-cli -- inject --vault ./personal.vault < .env.template
cargo run -p mlocker-cli -- wallet --vault ./personal.vault --chain ethereum --index 0
cargo run -p mlocker-cli -- sync export --vault ./personal.vault --cloud-dir "$HOME/Library/Mobile Documents/mlocker"
```

Login passwords can be mnemonic-derived or user-entered with `add-login --password`. Mnemonic-derived password metadata stores its path under the nested `password` object; user-entered passwords do not have a path. The CLI stores only encrypted vault blobs.
Use `delete-login --vault ./personal.vault <query>` to remove a login item.
`import` accepts Chrome/generic CSV, Bitwarden CSV, 1Password CSV/JSON, and Apple Passwords/iCloud Keychain CSV exports; existing rows with the same URL and username are updated instead of duplicated.
`export` writes decrypted login CSV for `generic-csv`, `1password-csv`, or `keychain-csv` and must be treated as a user-initiated secret export.

For local OS/browser integration, the CLI can also create a password-wrapped vault:

```sh
cargo run -p mlocker-cli -- init --vault ./personal.vault \
  --mnemonic "paste recovery phrase here" \
  --password "local unlock password"
export MLOCKER_PASSWORD="local unlock password"
```

`MLOCKER_PASSWORD` unlocks password-wrapped vaults for CLI and browser native-host flows. Keep `MLOCKER_MNEMONIC` available for wallet derivation in this MVP.

To use a vault SSH key with OpenSSH, add an SSH key item in the desktop app, then start the local agent:

```sh
export MLOCKER_MNEMONIC="paste the vault recovery phrase here"
cargo run -p mlocker-cli -- ssh-agent --vault "$HOME/.mlocker/personal.vault" --socket /tmp/mlocker-agent.sock
```

In another shell, use the printed socket before running `ssh`:

```sh
export SSH_AUTH_SOCK=/tmp/mlocker-agent.sock
ssh git@github.com
```

Each SSH signature request requires approval. On macOS the agent shows a system dialog with the key, derivation path, and payload hash before signing.

The desktop app also supports Passkey items under `Add Item -> Passkey`. The current MVP stores encrypted WebAuthn credential metadata and derives stable EdDSA credential material from the unlocked vault; CTAP/WebAuthn mediation is not wired yet.

## Browser and OS Integration

The `browser-extension/` folder contains a Manifest V3 extension for Chrome, Chromium, and Firefox. It detects login forms, requests origin-matched credentials from the local native messaging host, fills the selected username/password, and can save a new login back to the encrypted vault from the current page origin.

Build the native host binary and install a browser manifest:

```sh
cargo build -p mlocker-cli --bins
cargo run -p mlocker-cli -- browser-host install \
  --browser firefox \
  --extension-id mlocker@example.local \
  --vault "$HOME/.mlocker/personal.vault" \
  --host-path "$(pwd)/target/debug/mlocker-browser-host"
```

`mlocker inject` supports op-style local automation templates using references such as `mlocker://GitHub/password` and `mlocker://GitHub/username`. See `docs/OS_INTEGRATION.md` for browser native messaging, `inject`, launchd, and systemd user-service details.

## Workspace

- `crates/mlocker-core`: BIP39 recovery phrases, HKDF keys, XChaCha20Poly1305 vault format, deterministic password derivation, Ethereum/Solana derivation, SSH ed25519 derivation, and folder-backed sync.
- `crates/mlocker-cli`: command-line interface, `inject`, SSH agent, and browser native messaging host.
- `crates/mlocker-desktop`: native `eframe`/`egui` GUI shell with core-backed restore/password/wallet flows and local preview open flow.
- `browser-extension`: Manifest V3 browser autofill extension backed by `com.mlocker.native`.
- `dist`: OS integration templates for native messaging and SSH-agent startup on macOS, Linux, and Windows.
- `docs/PLAN.md`: staged product roadmap.
- `AGENTS.md`: build commands, conventions, security rules, and ownership guidance for parallel agents.

## Development Notes

Use `cargo fmt --all`, `cargo test --workspace`, `cargo check --workspace`, and `cargo clippy --workspace --all-targets -- -D warnings` before handing off changes. The workspace targets Rust `1.83`, so several GUI transitive dependencies are pinned in `Cargo.lock` to MSRV-compatible patch versions.
