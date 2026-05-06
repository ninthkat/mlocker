# mlocker Product Plan

mlocker is a cross-platform password manager MVP with a path toward a 1Password-class product. The desktop shell can demonstrate the flows now; production security must come from the core crate.

## Stage 0: Workspace Foundation

- Establish Rust workspace, shared dependency policy, formatting, linting, and CI gates.
- Define core domain types for vaults, items, accounts, devices, sync metadata, wallet accounts, and SSH identities.
- Keep CLI, desktop, and core crate ownership separate so agents can work in parallel.
- Add threat model notes covering local attackers, sync-provider compromise, clipboard leaks, malicious websites, and malicious wallet transactions.

## Stage 1: MVP Vault

- Implement encrypted local vault create/open/lock/unlock using audited primitives.
- Support login items with title, URL, username, mnemonic-derived or user-entered password data, notes, tags, and favorite state.
- Add recovery phrase generation and restore flow.
- Provide desktop screens for open/restore, item list/detail, add login, and wallet address preview.
- Provide CLI commands for init, unlock, list, get, create login, derive password, export, and import.
- Add deterministic tests for vault round trips, wrong-passphrase failures, and item derivation.

## Stage 2: Sync and Multi-Device

- Add sync envelope with device identity, monotonic revision, item tombstones, conflict records, and authenticated metadata.
- Support provider adapters:
  - Local folder for development and self-hosting.
  - iCloud Drive for macOS/iOS ecosystem users.
  - Google Drive and Dropbox for broad consumer support.
  - OneDrive for Windows and Microsoft 365 users.
  - WebDAV/S3-compatible storage for self-hosted and enterprise deployments.
- Encrypt all synced data client-side before provider upload.
- Detect replayed or rolled-back sync snapshots.
- Add merge UX for conflicting item updates.

## Stage 3: CLI Parity and Automation

- Close high-value `op` CLI gaps: signin/session semantics, `item list/get/create/edit/delete`, templates, document/file attachments, vault selection, JSON output, and shell completion.
- Provide `inject` template rendering for local automation references such as `mlocker://Item/password`.
- Add machine-readable errors and stable exit codes.
- Add importers for 1Password and generic JSON; Bitwarden and browser CSV exports are now covered by `import-logins`.
- Add service-account mode with scoped vault access and short-lived tokens.
- Keep compatibility pragmatic: mirror `op` shapes where useful, but do not copy cloud-specific semantics that conflict with mlocker security.

## Stage 4: SSH Agent

- Implement SSH identity derivation and import with encrypted storage of private material.
- Harden the agent:
  - Require explicit vault unlock before agent activation.
  - Bind approval prompts to process origin, requested public key, destination host, and signing payload class.
  - Support per-key confirmation policies, host allowlists, lifetime limits, and touch/biometric gates.
  - Refuse silent signing for unknown origins.
  - Log non-secret audit events locally.
- Add platform integration for `SSH_AUTH_SOCK` on macOS, Windows named pipes/OpenSSH Agent, and Linux sockets/systemd user services.

## Stage 5: Wallet Security

- Move all wallet derivation and signing into core with explicit chain adapters.
- Support read-only address derivation before transaction signing.
- Require transaction review screens showing chain, account, derivation path, destination, amount, fees, nonce, contract call, token metadata, and simulation warnings where available.
- Add phishing defenses: chain mismatch warnings, address-book labels, suspicious approval detection, and clear hardware-wallet handoff support.
- Separate password-vault unlock from high-risk signing approval with stronger re-authentication options.

## Stage 6: Desktop Product Depth

- Add search, tags, favorites, item history, password reveal controls, clipboard timeout clearing, and duplicate/reused password warnings.
- Harden the browser-extension handoff protocol with persistent unlock state, item selection policies, passkey mediation, and phishing-resistant origin review.
- Add secure settings for auto-lock, biometrics, recovery phrase rotation, sync provider selection, and device management.
- Add accessibility review for keyboard navigation, screen readers, contrast, and reduced motion.
- Add migration assistant and guided first-run setup.

## Stage 7: Packaging and Release

- macOS:
  - Build universal binaries.
  - Sign, notarize, staple, and package as `.dmg` and Homebrew cask.
  - Integrate Keychain for device-bound unlock helpers where appropriate.
- Windows:
  - Build MSIX and MSI installers.
  - Sign binaries and installers.
  - Integrate Windows Hello and Windows OpenSSH Agent support.
- Linux:
  - Build AppImage, Flatpak, and `.deb`/`.rpm` packages.
  - Integrate Secret Service/KWallet carefully without storing vault secrets in plaintext.
  - Provide systemd user units for optional SSH-agent socket management.
- Add release CI with reproducible build notes, SBOM generation, dependency audit, and smoke tests on all target platforms.

## Stage 8: 1Password-Class Reliability

- Add account recovery policies, emergency kit export, device revocation, item sharing, collections, admin controls, and audit reporting.
- Add encrypted attachments and secure document storage.
- Add passkeys/WebAuthn storage and browser-mediated sign-in flows.
- Add enterprise sync backends, SSO unlock options, SCIM provisioning, and policy enforcement.
- Complete external security review before claiming production readiness.
