//! One proxy per store directory, and never an older one after a newer.
//!
//! matrix-sdk-sqlite locks nothing in the crypto store: two proxies on one
//! store would both advance the same olm and megolm state. And it opens a
//! store whose schema a newer version has migrated without complaint. So
//! `serve` claims the store directory before it opens any store: an
//! exclusive lock for the life of the process, and a marker naming the
//! newest version that has used the directory. Stores older than the marker
//! (or written by another program) are checked one by one: none may have a
//! schema newer than this build's matrix-sdk-sqlite knows.

use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::Path;

use anyhow::Context as _;
use rusqlite::OptionalExtension as _;

use crate::crypto::device::STORE_FILE;

/// The newest crypto store schema this build's matrix-sdk-sqlite knows: the
/// version a store it creates gets. (Not its `DATABASE_VERSION`, which it
/// does not export and which 0.18 left at 15 while migrating to 17.) Raise
/// it with the matrix-sdk crates; `pinned_schema_is_matrix_sdk_sqlites`
/// tells.
pub const CRYPTO_STORE_SCHEMA: u8 = 17;

const LOCK_FILE: &str = ".lock";
const VERSION_FILE: &str = ".version";

/// The claim on a store directory; it lasts as long as this value.
#[derive(Debug)]
pub struct StoreGuard {
    _lock: File,
}

/// Claim `store_dir` for this process and this binary's version.
pub fn claim(store_dir: &Path) -> anyhow::Result<StoreGuard> {
    claim_as(store_dir, env!("CARGO_PKG_VERSION"))
}

fn claim_as(store_dir: &Path, version: &str) -> anyhow::Result<StoreGuard> {
    create_private_dir(store_dir)?;
    // Lock first: the marker is only read and raised under the lock.
    let lock = lock(store_dir)?;
    raise_marker(store_dir, version)?;
    // The stores are laid out as USER/DEVICE/.
    for user_dir in subdirs(store_dir) {
        for device_dir in subdirs(&user_dir) {
            check_crypto_store_schema(&device_dir)?;
        }
    }
    Ok(StoreGuard { _lock: lock })
}

fn subdirs(dir: &Path) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(|entry| Some(entry.ok()?.path()))
                .filter(|path| path.is_dir())
                .collect()
        })
        .unwrap_or_default()
}

/// Refuse the crypto store in `dir` if its schema is newer than this
/// build's matrix-sdk-sqlite knows: it would open the store all the same,
/// and work on tables a newer version has changed or dropped.
pub fn check_crypto_store_schema(dir: &Path) -> anyhow::Result<()> {
    let path = dir.join(STORE_FILE);
    let schema = crypto_store_schema(&path)
        .with_context(|| format!("failed to read the schema version of {}", path.display()))?;
    match schema {
        Some(schema) if schema > CRYPTO_STORE_SCHEMA => anyhow::bail!(
            "the crypto store {} has schema version {schema}, newer than the {CRYPTO_STORE_SCHEMA} \
             this ement-e2ee {} can use: a newer ement-e2ee has used it. Install that one again \
             (or newer), or move {} away to start over as a new device",
            path.display(),
            env!("CARGO_PKG_VERSION"),
            dir.display()
        ),
        _ => Ok(()),
    }
}

/// The schema version matrix-sdk-sqlite keeps in a crypto store: one byte,
/// stored in the clear even in an encrypted store. None if there is no
/// store, or no version to read (matrix-sdk-sqlite judges those itself).
fn crypto_store_schema(path: &Path) -> anyhow::Result<Option<u8>> {
    if !path.is_file() {
        return Ok(None);
    }
    let connection = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    let has_kv: bool = connection.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'kv')",
        [],
        |row| row.get(0),
    )?;
    if !has_kv {
        return Ok(None);
    }
    let version: Option<Vec<u8>> = connection
        .query_row("SELECT value FROM kv WHERE key = 'version'", [], |row| {
            row.get(0)
        })
        .optional()?;
    Ok(match version.as_deref() {
        Some([version]) => Some(*version),
        _ => None,
    })
}

fn create_private_dir(dir: &Path) -> anyhow::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder
        .create(dir)
        .with_context(|| format!("failed to create {}", dir.display()))
}

/// Take the directory's lock, or say who holds it. The lock is released
/// when the returned file is closed, which the kernel does for a process
/// however it ends.
fn lock(store_dir: &Path) -> anyhow::Result<File> {
    let path = store_dir.join(LOCK_FILE);
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    match file.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => {
            let mut holder = String::new();
            let _ = file.read_to_string(&mut holder);
            let holder = match holder.trim() {
                "" => "another process".to_owned(),
                pid => format!("another ement-e2ee (pid {pid})"),
            };
            anyhow::bail!(
                "the store directory {} is in use by {holder}; only one proxy may use it at a time",
                store_dir.display()
            );
        }
        Err(std::fs::TryLockError::Error(e)) => {
            return Err(e).with_context(|| format!("failed to lock {}", path.display()));
        }
    }
    // For the message above, in whoever comes next.
    file.set_len(0)?;
    writeln!(file, "{}", std::process::id())?;
    Ok(file)
}

/// Refuse a directory a newer version has used; otherwise record that
/// `running` has used it.
fn raise_marker(store_dir: &Path, running: &str) -> anyhow::Result<()> {
    let path = store_dir.join(VERSION_FILE);
    let running_version = parse_version(running)
        .with_context(|| format!("this binary's version {running:?} is not major.minor.patch"))?;
    match std::fs::read_to_string(&path) {
        Ok(text) => {
            let recorded = text.trim();
            let Some(recorded_version) = parse_version(recorded) else {
                anyhow::bail!(
                    "{} does not hold a version ({recorded:?}); delete it if no ement-e2ee newer \
                     than {running} has used this store",
                    path.display()
                );
            };
            if recorded_version > running_version {
                anyhow::bail!(
                    "store was last used by ement-e2ee {recorded}, newer than this {running}; \
                     install ≥ {recorded} (if you are certain, delete {})",
                    path.display()
                );
            }
            if recorded_version == running_version {
                return Ok(());
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("failed to read {}", path.display())),
    }
    // Never leave a half-written marker: it would refuse every later start.
    let temporary = store_dir.join(format!("{VERSION_FILE}.tmp"));
    std::fs::write(&temporary, format!("{running}\n"))
        .with_context(|| format!("failed to write {}", temporary.display()))?;
    std::fs::rename(&temporary, &path)
        .with_context(|| format!("failed to replace {}", path.display()))
}

/// `major.minor.patch`, numerically; a pre-release or build suffix is
/// ignored.
fn parse_version(text: &str) -> Option<(u64, u64, u64)> {
    let core = text.split(['-', '+']).next()?;
    let mut parts = core.split('.').map(|part| part.parse::<u64>().ok());
    let version = (parts.next()??, parts.next()??, parts.next()??);
    parts.next().is_none().then_some(version)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn marker(dir: &Path) -> String {
        std::fs::read_to_string(dir.join(VERSION_FILE)).unwrap()
    }

    #[test]
    fn versions_compare_numerically() {
        assert_eq!(parse_version("0.18.0"), Some((0, 18, 0)));
        assert_eq!(parse_version("1.2.3-rc.1"), Some((1, 2, 3)));
        assert_eq!(parse_version("1.2.3+build.5"), Some((1, 2, 3)));
        assert!(parse_version("0.18.10") > parse_version("0.18.9"));
        for bad in ["", "1", "1.2", "1.2.3.4", "1.x.3", "v1.2.3", "garbage"] {
            assert_eq!(parse_version(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_second_claim_is_refused_while_the_first_holds() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("store");
        let guard = claim(&store).unwrap();
        // flock belongs to the open file description, so a second open in
        // the same process conflicts like another process would.
        let second = OpenOptions::new()
            .write(true)
            .open(store.join(LOCK_FILE))
            .unwrap();
        assert!(matches!(
            second.try_lock(),
            Err(std::fs::TryLockError::WouldBlock)
        ));
        let error = format!("{:#}", claim(&store).unwrap_err());
        assert!(
            error.contains(&format!("pid {}", std::process::id())),
            "{error}"
        );
        assert!(error.contains("only one proxy"), "{error}");

        drop(guard);
        claim(&store).unwrap();
    }

    #[test]
    fn the_marker_is_written_and_raised() {
        let dir = tempfile::tempdir().unwrap();
        drop(claim_as(dir.path(), "0.18.0").unwrap());
        assert_eq!(marker(dir.path()), "0.18.0\n");
        // The same version leaves it alone; a newer one raises it.
        drop(claim_as(dir.path(), "0.18.0-rc.1").unwrap());
        assert_eq!(marker(dir.path()), "0.18.0\n");
        drop(claim_as(dir.path(), "0.19.2").unwrap());
        assert_eq!(marker(dir.path()), "0.19.2\n");
        assert!(!dir.path().join(".version.tmp").exists());
    }

    #[test]
    fn an_older_binary_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        drop(claim_as(dir.path(), "0.19.0").unwrap());
        let error = format!("{:#}", claim_as(dir.path(), "0.18.0").unwrap_err());
        assert!(
            error.contains("store was last used by ement-e2ee 0.19.0, newer than this 0.18.0"),
            "{error}"
        );
        assert!(error.contains("install ≥ 0.19.0"), "{error}");
        assert!(error.contains(".version"), "{error}");
        // Refusing leaves the marker as it was.
        assert_eq!(marker(dir.path()), "0.19.0\n");
    }

    #[test]
    fn a_garbled_marker_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(VERSION_FILE), "not a version\n").unwrap();
        let error = format!("{:#}", claim_as(dir.path(), "0.18.0").unwrap_err());
        assert!(error.contains("does not hold a version"), "{error}");
        assert_eq!(marker(dir.path()), "not a version\n");
    }

    /// A real crypto store, as this build's matrix-sdk-sqlite makes it, in
    /// `dir`; its schema version set to `schema` if given.
    async fn crypto_store(dir: &Path, schema: Option<u8>) {
        drop(
            matrix_sdk_sqlite::SqliteCryptoStore::open(dir, Some("passphrase"))
                .await
                .unwrap(),
        );
        if let Some(schema) = schema {
            let connection = rusqlite::Connection::open(dir.join(STORE_FILE)).unwrap();
            connection
                .execute("UPDATE kv SET value = ?1 WHERE key = 'version'", [[schema]])
                .unwrap();
        }
    }

    #[tokio::test]
    async fn pinned_schema_is_matrix_sdk_sqlites() {
        let dir = tempfile::tempdir().unwrap();
        crypto_store(dir.path(), None).await;
        assert_eq!(
            crypto_store_schema(&dir.path().join(STORE_FILE)).unwrap(),
            Some(CRYPTO_STORE_SCHEMA),
            "set CRYPTO_STORE_SCHEMA to the version of a new store"
        );
        check_crypto_store_schema(dir.path()).unwrap();
    }

    #[tokio::test]
    async fn a_store_with_a_newer_schema_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let device_dir = dir.path().join("@me:example.org/DEVICE");
        crypto_store(&device_dir, Some(CRYPTO_STORE_SCHEMA + 4)).await;
        let error = format!("{:#}", check_crypto_store_schema(&device_dir).unwrap_err());
        assert!(
            error.contains(&format!(
                "has schema version {}, newer than the {CRYPTO_STORE_SCHEMA}",
                CRYPTO_STORE_SCHEMA + 4
            )),
            "{error}"
        );
        assert!(error.contains("start over as a new device"), "{error}");
        // The whole directory is refused at start-up, marker or not.
        let error = format!("{:#}", claim(dir.path()).unwrap_err());
        assert!(error.contains("newer than the"), "{error}");

        // An older schema is matrix-sdk-sqlite's to migrate.
        crypto_store(&device_dir, Some(CRYPTO_STORE_SCHEMA - 1)).await;
        drop(claim(dir.path()).unwrap());
    }

    #[test]
    fn no_store_no_schema() {
        let dir = tempfile::tempdir().unwrap();
        check_crypto_store_schema(dir.path()).unwrap();
        // Not ours to judge: matrix-sdk-sqlite reports these.
        std::fs::write(dir.path().join(STORE_FILE), b"").unwrap();
        check_crypto_store_schema(dir.path()).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_new_store_directory_is_private() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("a/b");
        drop(claim(&store).unwrap());
        let mode = std::fs::metadata(&store).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
    }
}
