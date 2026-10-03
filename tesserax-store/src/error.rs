//! [`StoreError`] — one error type over every part of the crate, for
//! callers that mix the SQLite layer, files and (by feature) the cipher and
//! the time-series store.

use crate::db::DbError;
use crate::files::FilesError;

/// Any error this crate returns, for callers that want one type.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// SQLite layer.
    #[error(transparent)]
    Db(#[from] DbError),
    /// Atomic file writes and the JSON-lines audit file.
    #[error(transparent)]
    Files(#[from] FilesError),
    /// Field cipher.
    #[cfg(feature = "cipher-applite")]
    #[error(transparent)]
    Cipher(#[from] crate::field_cipher::CipherError),
    /// Time-series store.
    #[cfg(feature = "tsdb")]
    #[error(transparent)]
    Tsdb(#[from] crate::tsdb::TsdbError),
}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        StoreError::Db(DbError::Query(e))
    }
}
