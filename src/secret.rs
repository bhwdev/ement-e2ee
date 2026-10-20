//! The admin token, and files only their owner may read.
//!
//! Every `/_ement` route but the version route needs the admin token: the
//! configured `admin_token`, or else one drawn at random for each run. The
//! proxy writes it, either way, to `.admin-token` in its store directory
//! (which only its owner may enter), where `ctl` and Emacs read it. The
//! version route proves with it that the proxy answering is the one that
//! can read the file: anything else on the port cannot.

use std::io::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use hmac::{KeyInit as _, Mac as _};

/// In the store directory: the admin token of the proxy using it.
pub const TOKEN_FILE: &str = ".admin-token";

/// The token file for a store directory.
pub fn token_file(store_dir: &Path) -> PathBuf {
    store_dir.join(TOKEN_FILE)
}

/// A new admin token: 256 random bits, in hex.
pub fn generate_token() -> anyhow::Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| anyhow::anyhow!("no random numbers: {e}"))?;
    Ok(hex(&bytes))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Write the token where `ctl` and Emacs look for it.
pub fn write_token_file(store_dir: &Path, token: &str) -> anyhow::Result<()> {
    write_private(&token_file(store_dir), format!("{token}\n").as_bytes())
}

/// The token a proxy using `store_dir` wrote, if any.
pub fn read_token_file(store_dir: &Path) -> anyhow::Result<Option<String>> {
    let path = token_file(store_dir);
    match std::fs::read_to_string(&path) {
        Ok(text) => Ok(Some(text.trim().to_owned()).filter(|token| !token.is_empty())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("failed to read {}", path.display())),
    }
}

/// Compare a presented secret with the expected one in time independent of
/// where they differ.
pub fn same_secret(given: &[u8], expected: &[u8]) -> bool {
    given.len() == expected.len()
        && given
            .iter()
            .zip(expected)
            .fold(0u8, |difference, (a, b)| difference | (a ^ b))
            == 0
}

/// Is this a nonce the version route answers with a proof? Hex, long
/// enough not to repeat, short enough not to matter.
pub fn valid_nonce(nonce: &str) -> bool {
    (16..=128).contains(&nonce.len()) && nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// What the version route answers a `nonce` with: HMAC-SHA256, keyed with
/// the admin token, over the address the proxy is reached at and the
/// nonce. Only a proxy that can read the token file can compute it, and
/// only for its own address: one relayed from another port does not pass.
pub fn version_proof(token: &str, reached_at: SocketAddr, nonce: &str) -> String {
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(token.as_bytes())
        .expect("HMAC takes keys of any length");
    mac.update(format!("ement-e2ee version {reached_at} {nonce}").as_bytes());
    hex(&mac.finalize().into_bytes())
}

/// Create or replace `path` with `contents`, readable and writable by its
/// owner only, whatever the file's mode was.
pub fn write_private(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to write {}", path.display()))?;
    // The mode above applies to a new file only.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to restrict {}", path.display()))?;
    }
    file.write_all(contents)
        .with_context(|| format!("failed to write {}", path.display()))
}

/// From now on, create files and directories accessible to their owner
/// only: the crypto stores hold private keys, and the SDK creates them with
/// the default mode.
pub fn restrict_new_files() {
    #[cfg(unix)]
    // SAFETY: umask only replaces the process's file mode creation mask.
    unsafe {
        libc::umask(0o077);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_random_and_hex() {
        let first = generate_token().unwrap();
        assert_eq!(first.len(), 64);
        assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(first, generate_token().unwrap());
    }

    #[test]
    fn secrets_compare_exactly() {
        assert!(same_secret(b"s3cret", b"s3cret"));
        assert!(!same_secret(b"s3cret", b"s3creT"));
        assert!(!same_secret(b"s3cre", b"s3cret"));
        assert!(!same_secret(b"", b"s3cret"));
        assert!(same_secret(b"", b""));
    }

    #[test]
    fn nonces_are_bounded_hex() {
        assert!(valid_nonce("0123456789abcdef"));
        assert!(valid_nonce(&"a".repeat(128)));
        for bad in ["", "0123456789abcde", "0123456789abcdeg", &"a".repeat(129)] {
            assert!(!valid_nonce(bad), "{bad}");
        }
    }

    #[test]
    fn proof_is_hmac_sha256_over_address_and_nonce() {
        let at: SocketAddr = "127.0.0.1:8009".parse().unwrap();
        let proof = version_proof("s3cret", at, "00112233445566778899aabbccddeeff");
        // The value ement-e2ee.el computes too (see its tests).
        assert_eq!(
            proof,
            "6db7c1973eaa390c029abe4a50f928415e37e6f1c1ac5f01576b651923aabc5e"
        );
        // Another token, address or nonce: another proof.
        assert_ne!(
            proof,
            version_proof("s3creT", at, "00112233445566778899aabbccddeeff")
        );
        assert_ne!(
            proof,
            version_proof(
                "s3cret",
                "127.0.0.1:8010".parse().unwrap(),
                "00112233445566778899aabbccddeeff"
            )
        );
        assert_ne!(
            proof,
            version_proof("s3cret", at, "00112233445566778899aabbccddeef0")
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_files_are_private_even_if_they_were_not() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file");
        std::fs::write(&path, "old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_private(&path, b"new").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn token_file_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_token_file(dir.path()).unwrap(), None);
        write_token_file(dir.path(), "abc123").unwrap();
        assert_eq!(
            read_token_file(dir.path()).unwrap().as_deref(),
            Some("abc123")
        );
    }
}
