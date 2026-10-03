//! Whole-file SQLCipher (`cipher-native`): the file is unreadable without
//! the key, a wrong key fails at open, and every connection kind this crate
//! opens (writer, read pool, checkpointer, pool) is keyed.
#![cfg(feature = "cipher-native")]

mod common;

use std::sync::Arc;

use tesserax_store::keysource::StaticKeySource;
use tesserax_store::{
    Checkpointer, Db, DbConfig, DbError, Migration, MigrationRunner, ReadPoolConfig,
};

fn cfg(path: &std::path::Path, key: u8) -> DbConfig {
    DbConfig::encrypted_native(path, Arc::new(StaticKeySource([key; 32])))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn encrypted_store_is_opaque_without_its_key() {
    let path = common::temp_path("sqlcipher");
    {
        let db = Db::open(&cfg(&path, 7)).unwrap();
        assert!(db.label().ends_with("(encrypted)"));
        db.run_migrations(MigrationRunner::new(vec![Migration::new(
            1,
            "t",
            "CREATE TABLE secret (v TEXT);",
        )]))
        .await
        .unwrap();
        db.write(|c| {
            c.execute("INSERT INTO secret VALUES ('needle-in-haystack')", [])
                .map(|_| ())
        })
        .await
        .unwrap();
        db.write(|c| c.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(())))
            .await
            .unwrap();
    }

    let raw = std::fs::read(&path).unwrap();
    assert!(
        !raw.starts_with(b"SQLite format 3"),
        "header must be encrypted"
    );
    assert!(
        !raw.windows(b"needle-in-haystack".len())
            .any(|w| w == b"needle-in-haystack"),
        "plaintext must not appear on disk"
    );

    match Db::open(&cfg(&path, 8)) {
        Err(DbError::NotADatabase) => {}
        other => panic!("wrong key must fail at open, got {other:?}"),
    }
    let plain = Db::open(&DbConfig::new(&path));
    assert!(plain.is_err(), "opening without a key must fail");

    let db = Db::open(&cfg(&path, 7)).unwrap();
    let v: String = db
        .read(|c| c.query_row("SELECT v FROM secret", [], |r| r.get(0)))
        .await
        .unwrap();
    assert_eq!(v, "needle-in-haystack");

    let pool = ReadPoolConfig::from_config(cfg(&path, 7))
        .pool_size(2)
        .open()
        .unwrap();
    let n: i64 = pool
        .read(|c| c.query_row("SELECT count(*) FROM secret", [], |r| r.get(0)))
        .await
        .unwrap();
    assert_eq!(n, 1);
    assert!(ReadPoolConfig::from_config(cfg(&path, 9)).open().is_err());

    let checkpointer = Checkpointer::open_config(&cfg(&path, 7), -8192).unwrap();
    let (busy, _, _) = checkpointer.checkpoint_passive().await.unwrap();
    assert_eq!(busy, 0);

    #[cfg(feature = "pool")]
    {
        let dbpool = tesserax_store::DbPool::open_with_size(&cfg(&path, 7), 2).unwrap();
        let n: i64 = dbpool
            .read(|c| c.query_row("SELECT count(*) FROM secret", [], |r| r.get(0)))
            .await
            .unwrap();
        assert_eq!(n, 1);
    }

    drop((db, pool, checkpointer));
    common::cleanup(&path);
}
