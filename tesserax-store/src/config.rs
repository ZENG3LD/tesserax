//! [`DbConfig`] — where a store lives and how it is keyed.
//!
//! - `Path(path)` — file-backed, WAL mode (the production case).
//! - `InMemory` — ephemeral, one connection, no WAL (tests, throwaway
//!   state). Every new connection to `:memory:` is a separate database, so
//!   pools and read pools refuse it.
//! - `EncryptedNative { path, key_source }` (feature `cipher-native`) —
//!   whole-file SQLCipher, keyed by a
//!   [`KeySource`](tesserax_secrets::keysource::KeySource) on every
//!   connection this crate opens.

use std::path::{Path, PathBuf};
#[cfg(feature = "cipher-native")]
use std::sync::Arc;

use rusqlite::Connection;

#[cfg(feature = "cipher-native")]
use tesserax_secrets::keysource::KeySource;

use crate::db::DbError;

/// Opening parameters for [`crate::Db`], [`crate::ReadPool`],
/// [`crate::Checkpointer`] and (feature `pool`) `DbPool`.
#[derive(Clone)]
#[non_exhaustive]
pub enum DbConfig {
    /// File-backed store at this path. Parent directories are created.
    Path(PathBuf),
    /// Private in-memory database.
    InMemory,
    /// File-backed SQLCipher store keyed via a runtime key source.
    ///
    /// On every connection open the source's 32-byte master key is
    /// hex-encoded and applied as `PRAGMA key = "x'<hex>'"` BEFORE any other
    /// statement (SQLCipher requires key-first). Opening fails with
    /// [`DbError::NotADatabase`] when the key does not match the file.
    #[cfg(feature = "cipher-native")]
    EncryptedNative {
        /// Database file.
        path: PathBuf,
        /// Where the master key comes from.
        key_source: Arc<dyn KeySource>,
    },
}

impl std::fmt::Debug for DbConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DbConfig::Path(p) => write!(f, "DbConfig::Path({p:?})"),
            DbConfig::InMemory => write!(f, "DbConfig::InMemory"),
            #[cfg(feature = "cipher-native")]
            DbConfig::EncryptedNative { path, .. } => {
                write!(
                    f,
                    "DbConfig::EncryptedNative {{ path: {path:?}, key_source: <redacted> }}"
                )
            }
        }
    }
}

impl DbConfig {
    /// File-backed store at `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self::Path(path.into())
    }

    /// Private in-memory database.
    pub fn in_memory() -> Self {
        Self::InMemory
    }

    /// SQLCipher store at `path`, keyed by `key_source`.
    #[cfg(feature = "cipher-native")]
    pub fn encrypted_native(path: impl Into<PathBuf>, key_source: Arc<dyn KeySource>) -> Self {
        Self::EncryptedNative {
            path: path.into(),
            key_source,
        }
    }

    /// True for [`DbConfig::InMemory`].
    pub fn is_in_memory(&self) -> bool {
        matches!(self, DbConfig::InMemory)
    }

    /// True when the file is encrypted at rest.
    pub fn is_encrypted(&self) -> bool {
        #[cfg(feature = "cipher-native")]
        {
            matches!(self, DbConfig::EncryptedNative { .. })
        }
        #[cfg(not(feature = "cipher-native"))]
        {
            false
        }
    }

    /// File path if file-backed, `None` if in-memory.
    pub fn path(&self) -> Option<&Path> {
        match self {
            DbConfig::Path(p) => Some(p.as_path()),
            DbConfig::InMemory => None,
            #[cfg(feature = "cipher-native")]
            DbConfig::EncryptedNative { path, .. } => Some(path.as_path()),
        }
    }

    /// Human-readable label used in logs and thread names.
    pub fn label(&self) -> String {
        match self {
            DbConfig::Path(p) => p.display().to_string(),
            DbConfig::InMemory => ":memory:".to_owned(),
            #[cfg(feature = "cipher-native")]
            DbConfig::EncryptedNative { path, .. } => format!("{} (encrypted)", path.display()),
        }
    }

    /// Opens one raw connection and applies the key (if any) as the very
    /// first statement. The writer (`create_parent = true`) creates a
    /// missing parent directory; readers and the checkpointer do not, so a
    /// wrong path fails at their open. No other pragma is applied here —
    /// each caller applies its own set.
    pub(crate) fn open_connection(&self, create_parent: bool) -> Result<Connection, DbError> {
        let conn = match self {
            DbConfig::InMemory => Connection::open_in_memory().map_err(|source| DbError::Open {
                path: ":memory:".into(),
                source,
            })?,
            DbConfig::Path(path) => open_file(path, create_parent)?,
            #[cfg(feature = "cipher-native")]
            DbConfig::EncryptedNative { path, key_source } => {
                let conn = open_file(path, create_parent)?;
                apply_key(&conn, key_source.as_ref())?;
                conn
            }
        };
        Ok(conn)
    }
}

impl From<PathBuf> for DbConfig {
    fn from(path: PathBuf) -> Self {
        Self::Path(path)
    }
}

impl From<&Path> for DbConfig {
    fn from(path: &Path) -> Self {
        Self::Path(path.to_path_buf())
    }
}

impl From<&PathBuf> for DbConfig {
    fn from(path: &PathBuf) -> Self {
        Self::Path(path.clone())
    }
}

impl From<&str> for DbConfig {
    fn from(path: &str) -> Self {
        Self::Path(PathBuf::from(path))
    }
}

fn open_file(path: &Path, create_parent: bool) -> Result<Connection, DbError> {
    if create_parent
        && let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        let _ = std::fs::create_dir_all(parent);
    }
    Connection::open(path).map_err(|source| DbError::Open {
        path: path.display().to_string(),
        source,
    })
}

/// Applies a SQLCipher raw key and proves it by reading the schema: a
/// wrong key surfaces here as [`DbError::NotADatabase`], not on the first
/// query deep inside a caller.
#[cfg(feature = "cipher-native")]
fn apply_key(conn: &Connection, source: &dyn KeySource) -> Result<(), DbError> {
    use zeroize::Zeroizing;

    const HEX: &[u8; 16] = b"0123456789abcdef";
    let key = source.master_key()?;
    let mut literal = Zeroizing::new(String::with_capacity(3 + 64 + 1));
    literal.push_str("x'");
    for &b in key.iter() {
        literal.push(HEX[(b >> 4) as usize] as char);
        literal.push(HEX[(b & 0x0f) as usize] as char);
    }
    literal.push('\'');
    conn.pragma_update(None, "key", literal.as_str())
        .map_err(DbError::Pragma)?;
    match conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
        r.get::<_, i64>(0)
    }) {
        Ok(_) => Ok(()),
        Err(rusqlite::Error::SqliteFailure(e, _))
            if e.code == rusqlite::ErrorCode::NotADatabase =>
        {
            Err(DbError::NotADatabase)
        }
        Err(e) => Err(DbError::Pragma(e)),
    }
}
