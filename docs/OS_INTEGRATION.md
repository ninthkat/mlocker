# OS Integration

mlocker currently exposes two installable OS touch points: browser native messaging for autofill/save, and SSH agent socket startup templates. Both keep vault secrets encrypted on disk and require an explicit unlock path before secrets are released.

## Browser Native Messaging

The browser extension lives in `browser-extension/`. The native host executable is `mlocker-browser-host`, built from the CLI crate.

```sh
cargo build -p mlocker-cli --bins
cargo run -p mlocker-cli -- browser-host configure --vault "$HOME/.mlocker/personal.vault"
```

Firefox uses the stable extension id in `browser-extension/manifest.json`:

```sh
cargo run -p mlocker-cli -- browser-host install \
  --browser firefox \
  --extension-id mlocker@example.local \
  --vault "$HOME/.mlocker/personal.vault" \
  --host-path "$(pwd)/target/debug/mlocker-browser-host"
```

Chrome and Chromium assign an id after loading `browser-extension/` as an unpacked extension:

```sh
cargo run -p mlocker-cli -- browser-host install \
  --browser chrome \
  --extension-id "<chrome-extension-id>" \
  --vault "$HOME/.mlocker/personal.vault" \
  --host-path "$(pwd)/target/debug/mlocker-browser-host"
```

Use `browser-host manifest` when packaging needs to write the native messaging JSON manually:

```sh
cargo run -p mlocker-cli -- browser-host manifest \
  --browser firefox \
  --extension-id mlocker@example.local \
  --host-path "$(pwd)/target/debug/mlocker-browser-host"
```

The MVP native host reads `MLOCKER_PASSWORD` for password-wrapped vaults or `MLOCKER_MNEMONIC` for mnemonic-only vaults from its process environment. This is acceptable for local development only; production should replace it with a desktop unlock service backed by Keychain, Windows Hello, Secret Service, or KWallet.

## CLI Inject

`mlocker inject` renders templates by replacing `mlocker://<item>/<field>` references. Supported fields are `id`, `title`, `username`, `url`, `password`, and `totp`.

```sh
export MLOCKER_MNEMONIC="paste the vault recovery phrase here"
printf 'DATABASE_PASSWORD=mlocker://Example/password\n' |
  cargo run -p mlocker-cli -- inject --vault "$HOME/.mlocker/personal.vault"
```

Item names with spaces can be percent encoded:

```txt
mlocker://Example%20Prod/password
```

## SSH Agent Startup

The SSH agent command is:

```sh
cargo run -p mlocker-cli -- ssh-agent \
  --vault "$HOME/.mlocker/personal.vault" \
  --socket /tmp/mlocker-agent.sock
```

Templates for launchd and systemd user services are in `dist/macos/` and `dist/linux/`. They intentionally do not embed `MLOCKER_MNEMONIC`; production startup should acquire unlock material through an OS-bound unlock broker.

## Windows

Windows native messaging hosts are installed through per-user registry keys. The helper script writes the browser host config, writes the native messaging manifest, and registers the manifest path under `HKCU`.

```powershell
cargo build -p mlocker-cli --bins
powershell -ExecutionPolicy Bypass -File .\dist\windows\install-native-host.ps1 `
  -Browser firefox `
  -ExtensionId mlocker@example.local `
  -Vault "$env:USERPROFILE\.mlocker\personal.vault" `
  -HostPath "$PWD\target\debug\mlocker-browser-host.exe" `
  -MlockerExe "$PWD\target\debug\mlocker.exe"
```

The SSH-agent template in `dist/windows/mlocker-ssh-agent.ps1` documents the intended Windows named-pipe entrypoint. The current Rust agent still supports Unix domain sockets only, so Windows OpenSSH Agent compatibility remains a product gap.
