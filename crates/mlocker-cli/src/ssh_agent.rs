use std::{
    io::{ErrorKind, Read, Write},
    path::Path,
    process::Command,
};

use anyhow::{bail, Context, Result};
use mlocker_core::{sign_ssh_data_from_root_key, RootKey};
use sha2::{Digest, Sha256};

const MAX_AGENT_MESSAGE_LEN: usize = 1024 * 1024;
const SSH_AGENT_FAILURE: u8 = 5;
const SSH2_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH2_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH2_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH2_AGENT_SIGN_RESPONSE: u8 = 14;
const SSH_ED25519: &str = "ssh-ed25519";

#[derive(Clone, Debug)]
pub struct AgentIdentity {
    pub comment: String,
    pub derivation_path: String,
    pub key_blob: Vec<u8>,
    pub public_key_openssh: String,
}

#[derive(Clone, Debug)]
pub struct SignApprovalRequest {
    pub key_comment: String,
    pub derivation_path: String,
    pub key_fingerprint: String,
    pub payload_len: usize,
    pub payload_sha256: String,
}

pub trait ApprovalPrompt {
    fn approve(&self, request: &SignApprovalRequest) -> Result<bool>;
}

pub struct SystemApprovalPrompt;

#[cfg(unix)]
pub fn serve(socket_path: &Path, identities: Vec<AgentIdentity>, root_key: RootKey) -> Result<()> {
    use std::{
        fs,
        os::unix::{
            fs::{FileTypeExt, PermissionsExt},
            net::UnixListener,
        },
    };

    if identities.is_empty() {
        bail!("no SSH key items found in the vault");
    }
    if socket_path.exists() {
        let file_type = fs::symlink_metadata(socket_path)
            .with_context(|| format!("inspect socket path {}", socket_path.display()))?
            .file_type();
        if !file_type.is_socket() {
            bail!(
                "refusing to replace non-socket path {}",
                socket_path.display()
            );
        }
        fs::remove_file(socket_path)
            .with_context(|| format!("remove stale socket {}", socket_path.display()))?;
    }
    if let Some(parent) = socket_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create socket directory {}", parent.display()))?;
    }

    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("bind SSH agent socket {}", socket_path.display()))?;
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("secure SSH agent socket {}", socket_path.display()))?;

    let approval = SystemApprovalPrompt;
    for stream in listener.incoming() {
        let mut stream = stream.with_context(|| "accept SSH agent client")?;
        handle_client(&mut stream, &identities, &root_key, &approval)?;
    }

    Ok(())
}

#[cfg(not(unix))]
pub fn serve(
    _socket_path: &Path,
    _identities: Vec<AgentIdentity>,
    _root_key: RootKey,
) -> Result<()> {
    bail!("mlocker ssh-agent currently supports Unix domain sockets only")
}

fn handle_client(
    stream: &mut impl ReadWrite,
    identities: &[AgentIdentity],
    root_key: &RootKey,
    approval: &impl ApprovalPrompt,
) -> Result<()> {
    loop {
        let mut len_buf = [0_u8; 4];
        match stream.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(err) if err.kind() == ErrorKind::UnexpectedEof => return Ok(()),
            Err(err) => return Err(err).context("read SSH agent frame length"),
        }

        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_AGENT_MESSAGE_LEN {
            bail!("SSH agent message is too large");
        }

        let mut message = vec![0_u8; len];
        stream
            .read_exact(&mut message)
            .context("read SSH agent frame")?;
        let response = handle_message(&message, identities, root_key, approval)
            .unwrap_or_else(|_| failure_message());
        stream
            .write_all(&(response.len() as u32).to_be_bytes())
            .context("write SSH agent response length")?;
        stream
            .write_all(&response)
            .context("write SSH agent response")?;
        stream.flush().context("flush SSH agent response")?;
    }
}

pub fn handle_message(
    message: &[u8],
    identities: &[AgentIdentity],
    root_key: &RootKey,
    approval: &impl ApprovalPrompt,
) -> Result<Vec<u8>> {
    let Some((&message_type, payload)) = message.split_first() else {
        return Ok(failure_message());
    };

    match message_type {
        SSH2_AGENTC_REQUEST_IDENTITIES => Ok(identities_answer(identities)),
        SSH2_AGENTC_SIGN_REQUEST => sign_response(payload, identities, root_key, approval),
        _ => Ok(failure_message()),
    }
}

fn identities_answer(identities: &[AgentIdentity]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(SSH2_AGENT_IDENTITIES_ANSWER);
    write_u32(&mut out, identities.len() as u32);
    for identity in identities {
        write_string(&mut out, &identity.key_blob);
        write_string(&mut out, identity.comment.as_bytes());
    }
    out
}

fn sign_response(
    payload: &[u8],
    identities: &[AgentIdentity],
    root_key: &RootKey,
    approval: &impl ApprovalPrompt,
) -> Result<Vec<u8>> {
    let mut reader = AgentReader::new(payload);
    let key_blob = reader.read_string()?;
    let data = reader.read_string()?;
    let _flags = reader.read_u32()?;

    let Some(identity) = identities
        .iter()
        .find(|identity| identity.key_blob.as_slice() == key_blob.as_slice())
    else {
        return Ok(failure_message());
    };

    let request = SignApprovalRequest::new(identity, &data);
    if !approval.approve(&request)? {
        return Ok(failure_message());
    }

    let signature = sign_ssh_data_from_root_key(root_key, &identity.derivation_path, &data)?;
    let mut signature_blob = Vec::new();
    write_string(&mut signature_blob, SSH_ED25519.as_bytes());
    write_string(&mut signature_blob, &signature);

    let mut out = Vec::new();
    out.push(SSH2_AGENT_SIGN_RESPONSE);
    write_string(&mut out, &signature_blob);
    Ok(out)
}

impl SignApprovalRequest {
    fn new(identity: &AgentIdentity, payload: &[u8]) -> Self {
        Self {
            key_comment: identity.comment.clone(),
            derivation_path: identity.derivation_path.clone(),
            key_fingerprint: short_sha256(&identity.key_blob),
            payload_len: payload.len(),
            payload_sha256: hex::encode(Sha256::digest(payload)),
        }
    }
}

impl ApprovalPrompt for SystemApprovalPrompt {
    fn approve(&self, request: &SignApprovalRequest) -> Result<bool> {
        system_approval(request)
    }
}

#[cfg(target_os = "macos")]
fn system_approval(request: &SignApprovalRequest) -> Result<bool> {
    let message = format!(
        "mlocker SSH agent signing request\n\nKey: {}\nPath: {}\nKey fingerprint: {}\nPayload: {} bytes\nPayload SHA256: {}\n\nAllow this SSH signature?",
        request.key_comment,
        request.derivation_path,
        request.key_fingerprint,
        request.payload_len,
        request.payload_sha256
    );
    let script = format!(
        "button returned of (display dialog \"{}\" buttons {{\"Deny\", \"Allow\"}} default button \"Deny\" cancel button \"Deny\" with title \"mlocker\" with icon caution)",
        escape_applescript(&message)
    );
    let output = Command::new("osascript")
        .arg("-e")
        .arg(script)
        .output()
        .context("show SSH signing approval dialog")?;
    if !output.status.success() {
        return Ok(false);
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim() == "Allow")
}

#[cfg(not(target_os = "macos"))]
fn system_approval(request: &SignApprovalRequest) -> Result<bool> {
    eprintln!(
        "mlocker SSH signing request: key={}, path={}, fingerprint={}, payload={} bytes, sha256={}",
        request.key_comment,
        request.derivation_path,
        request.key_fingerprint,
        request.payload_len,
        request.payload_sha256
    );
    eprint!("Allow signature? [y/N] ");
    std::io::stderr().flush().ok();
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .context("read SSH signing approval")?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "YES"))
}

fn escape_applescript(input: &str) -> String {
    input.replace('\\', "\\\\").replace('"', "\\\"")
}

fn short_sha256(input: &[u8]) -> String {
    let digest = Sha256::digest(input);
    hex::encode(&digest[..12])
}

fn failure_message() -> Vec<u8> {
    vec![SSH_AGENT_FAILURE]
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_string(out: &mut Vec<u8>, value: &[u8]) {
    write_u32(out, value.len() as u32);
    out.extend_from_slice(value);
}

struct AgentReader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> AgentReader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn read_u32(&mut self) -> Result<u32> {
        let bytes = self.read_exact(4)?;
        Ok(u32::from_be_bytes(bytes.try_into().expect("fixed length")))
    }

    fn read_string(&mut self) -> Result<Vec<u8>> {
        let len = self.read_u32()? as usize;
        Ok(self.read_exact(len)?.to_vec())
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self.offset.checked_add(len).context("SSH agent overflow")?;
        if end > self.input.len() {
            bail!("truncated SSH agent message");
        }
        let bytes = &self.input[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }
}

trait ReadWrite: Read + Write {}

impl<T: Read + Write> ReadWrite for T {}

#[cfg(test)]
mod tests {
    use super::*;
    use mlocker_core::{
        derive_root_key, derive_ssh_key_from_root_key, parse_mnemonic, DEFAULT_APP_DOMAIN,
        DEFAULT_SSH_DERIVATION_PATH,
    };

    const MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn request_identities_returns_configured_key() {
        let (root_key, identity) = test_identity();
        let approval = AllowApproval;

        let response = handle_message(
            &[SSH2_AGENTC_REQUEST_IDENTITIES],
            &[identity],
            &root_key,
            &approval,
        )
        .unwrap();

        assert_eq!(response[0], SSH2_AGENT_IDENTITIES_ANSWER);
        assert_eq!(u32::from_be_bytes(response[1..5].try_into().unwrap()), 1);
    }

    #[test]
    fn sign_request_returns_ed25519_signature() {
        let (root_key, identity) = test_identity();
        let approval = AllowApproval;
        let mut request = Vec::new();
        request.push(SSH2_AGENTC_SIGN_REQUEST);
        write_string(&mut request, &identity.key_blob);
        write_string(&mut request, b"session-id-and-userauth-data");
        write_u32(&mut request, 0);

        let response = handle_message(&request, &[identity], &root_key, &approval).unwrap();

        assert_eq!(response[0], SSH2_AGENT_SIGN_RESPONSE);
        assert!(response.len() > 80);
    }

    #[test]
    fn denied_sign_request_fails() {
        let (root_key, identity) = test_identity();
        let mut request = Vec::new();
        request.push(SSH2_AGENTC_SIGN_REQUEST);
        write_string(&mut request, &identity.key_blob);
        write_string(&mut request, b"session-id-and-userauth-data");
        write_u32(&mut request, 0);

        let response = handle_message(&request, &[identity], &root_key, &DenyApproval).unwrap();

        assert_eq!(response, failure_message());
    }

    #[test]
    fn unknown_key_sign_request_fails() {
        let (root_key, identity) = test_identity();
        let approval = AllowApproval;
        let mut request = Vec::new();
        request.push(SSH2_AGENTC_SIGN_REQUEST);
        write_string(&mut request, b"not-the-agent-key");
        write_string(&mut request, b"data");
        write_u32(&mut request, 0);

        let response = handle_message(&request, &[identity], &root_key, &approval).unwrap();

        assert_eq!(response, failure_message());
    }

    fn test_identity() -> (RootKey, AgentIdentity) {
        let mnemonic = parse_mnemonic(MNEMONIC).unwrap();
        let root_key = derive_root_key(&mnemonic, DEFAULT_APP_DOMAIN).unwrap();
        let key =
            derive_ssh_key_from_root_key(&root_key, DEFAULT_SSH_DERIVATION_PATH, "mlocker-test")
                .unwrap();
        let identity = AgentIdentity {
            comment: String::from("mlocker-test"),
            derivation_path: key.derivation_path,
            key_blob: key.public_key_blob,
            public_key_openssh: key.public_key_openssh,
        };
        (root_key, identity)
    }

    struct AllowApproval;

    impl ApprovalPrompt for AllowApproval {
        fn approve(&self, _request: &SignApprovalRequest) -> Result<bool> {
            Ok(true)
        }
    }

    struct DenyApproval;

    impl ApprovalPrompt for DenyApproval {
        fn approve(&self, _request: &SignApprovalRequest) -> Result<bool> {
            Ok(false)
        }
    }
}
