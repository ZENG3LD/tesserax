//! Golden files: the audit chain verifies and extends, a field-cipher blob
//! sealed under `tesserax-field-cipher-v1|` decrypts, and a time-series
//! file queries. Fixtures live in `tests/golden/`.

mod common;

use tesserax_store::{AuditEntry, AuditLog, Db, DbConfig};

#[tokio::test]
async fn audit_chain_written_by_the_old_code_verifies_and_extends() {
    let path = common::fixture_copy("audit_v1.sqlite");
    let db = Db::open(&DbConfig::new(&path)).unwrap();
    let log = AuditLog::new(db.clone());

    let report = log.verify().await.unwrap();
    assert!(report.is_valid, "{report:?}");
    assert_eq!(report.rows_checked, 3);
    let rows = log.list(None).await.unwrap();
    assert_eq!(rows[0].actor, "alice");
    assert_eq!(rows[1].payload["n"][2], 3);

    // The new code continues the old chain.
    log.append(AuditEntry::new(
        "carol",
        "export",
        serde_json::json!({"rows": 7}),
    ))
    .await
    .unwrap();
    let report = log.verify().await.unwrap();
    assert!(report.is_valid, "{report:?}");
    assert_eq!(report.rows_checked, 4);

    // And still detects a tampered old row.
    db.write(|c| {
        c.execute("UPDATE audit_log SET actor = 'mallory' WHERE id = 1", [])
            .map(|_| ())
    })
    .await
    .unwrap();
    let report = log.verify().await.unwrap();
    assert!(!report.is_valid);
    assert_eq!(report.first_break, Some(1));

    drop(log);
    drop(db);
    common::cleanup(&path);
}

#[cfg(feature = "cipher-applite")]
#[test]
fn field_cipher_blob_written_by_the_old_code_decrypts() {
    use tesserax_store::FieldCipher;
    use tesserax_store::keysource::StaticKeySource;

    let hex = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/field_cipher_v1.hex"),
    )
    .unwrap();
    let blob: Vec<u8> = (0..hex.trim().len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    let cipher = FieldCipher::from_source(&StaticKeySource([0x42; 32])).unwrap();
    assert_eq!(
        cipher.decrypt_str(&blob, b"users.email").unwrap(),
        "golden plaintext"
    );
    assert!(
        cipher.decrypt_str(&blob, b"users.name").is_err(),
        "context binding kept"
    );
}

#[cfg(feature = "tsdb")]
#[test]
fn tsdb_file_written_by_the_old_code_queries() {
    use tesserax_store::tsdb::{Agg, LabelSet, SeriesKey, Tsdb};

    let path = common::fixture_copy("tsdb_v1.sqlite");
    let key = SeriesKey::new("cpu_pct", LabelSet::new(vec![("host".into(), "a".into())]));
    assert_eq!(
        format!("{:032x}", key.id().0),
        "ba3d21ca47559664db7947703d50a766"
    );
    {
        let db = Tsdb::open(&path).unwrap();
        assert_eq!(db.series_count().unwrap(), 1);
        let samples = db.range(&key, 0, i64::MAX).unwrap();
        assert_eq!(samples.len(), 25);
        for (i, s) in samples.iter().enumerate() {
            assert_eq!(s.ts_ms, 1_000 + i as i64 * 30_000);
            assert_eq!(s.value, i as f64 * 1.5);
        }
        assert_eq!(
            db.aggregate(&key, 0, i64::MAX, Agg::Max).unwrap(),
            Some(36.0)
        );
        assert_eq!(db.select("cpu_pct", &[]).unwrap(), vec![key.clone()]);
    }
    common::cleanup(&path);
}
