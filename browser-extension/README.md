# mlocker Browser Extension

This is a Manifest V3 extension for Chrome, Chromium, and Firefox. It detects login fields, asks the local `com.mlocker.native` native messaging host for origin-matched vault items, fills the selected username/password, and can save a typed username/password back to the encrypted vault for the current page origin.

## Native Host

Build both CLI binaries:

```sh
cargo build -p mlocker-cli --bins
```

Configure the native host for the vault:

```sh
cargo run -p mlocker-cli -- browser-host configure --vault "$HOME/.mlocker/personal.vault"
```

For Firefox, the extension id is fixed in `manifest.json`:

```sh
cargo run -p mlocker-cli -- browser-host install \
  --browser firefox \
  --extension-id mlocker@example.local \
  --vault "$HOME/.mlocker/personal.vault" \
  --host-path "$(pwd)/target/debug/mlocker-browser-host"
```

For Chrome or Chromium, load this folder as an unpacked extension first, copy the generated extension id, then install the native host with that id:

```sh
cargo run -p mlocker-cli -- browser-host install \
  --browser chrome \
  --extension-id "<chrome-extension-id>" \
  --vault "$HOME/.mlocker/personal.vault" \
  --host-path "$(pwd)/target/debug/mlocker-browser-host"
```

The native host can unlock either with `MLOCKER_PASSWORD` for password-wrapped vaults or `MLOCKER_MNEMONIC` for legacy mnemonic-only vaults. Production unlock should move to an OS-bound unlock broker rather than storing unlock material in browser or native host configuration.
