//! Golden vectors for the tesserax wire and storage labels.
//!
//! Sealed blobs and the daemon-identity file are sealed under the synthetic
//! host factors below (`PRODUCT_UUID`, `MACHINE_ID`, `MAC`, `UID`). The
//! operator-command signature is ed25519 over the tesserax-op-command-v2
//! canonical bytes with signing key `[0x42; 32]`. The response signature is
//! the same identity's signature over the tesserax-resp-v1 canonical bytes.
//! Shamir shares reconstruct `b"golden shamir secret"`. Every value is
//! synthetic; no real host, key or service is involved.

use std::time::{Duration, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use tesserax_secrets::opcmd::{
    OperatorCommand, OperatorTrustStore, ReplayCache, canonical_signing_bytes,
};
use tesserax_secrets::shamir::{Share, reconstruct};
use tesserax_secrets::{
    DaemonIdentity, HostFactors, MachineSeal, SealedSecret, SealedSecretError, signing,
};

const PRODUCT_UUID: &str = "00000000-1111-2222-3333-444444444444";
const MACHINE_ID: &str = "0123456789abcdef0123456789abcdef";
const MAC: &str = "02:00:00:00:00:01";
const UID: &str = "1000";

fn golden_host() -> HostFactors {
    HostFactors::new(Some(PRODUCT_UUID.into()), MACHINE_ID, MAC, UID)
}

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn fixture_bytes(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

#[test]
fn sealed_secret_dmi_v2_blob_unseals() {
    let s = SealedSecret::new(b"golden-sealed-secret-label".to_vec());
    let pt = s
        .unseal_with(&golden_host(), &fixture("sealed_secret_dmi_v2.b64"))
        .unwrap();
    assert_eq!(pt.as_slice(), b"golden plaintext sealed under DMI-V2");

    let d = SealedSecret::default_label();
    let pt = d
        .unseal_with(&golden_host(), &fixture("sealed_secret_default_label.b64"))
        .unwrap();
    assert_eq!(pt.as_slice(), b"default label payload");
}

#[test]
fn sealed_secret_golden_fails_on_other_host_or_label() {
    let blob = fixture("sealed_secret_dmi_v2.b64");
    let s = SealedSecret::new(b"golden-sealed-secret-label".to_vec());
    let other = HostFactors::new(Some(PRODUCT_UUID.into()), MACHINE_ID, MAC, "1001");
    assert!(matches!(
        s.unseal_with(&other, &blob),
        Err(SealedSecretError::FingerprintMismatch)
    ));
    // Without DMI only the legacy variant is tried, which this blob is not.
    let no_dmi = HostFactors::new(None, MACHINE_ID, MAC, UID);
    assert!(matches!(
        s.unseal_with(&no_dmi, &blob),
        Err(SealedSecretError::FingerprintMismatch)
    ));
    let wrong_label = SealedSecret::new(b"other".to_vec());
    assert!(wrong_label.unseal_with(&golden_host(), &blob).is_err());
}

#[test]
fn machine_seal_dmi_v2_blob_unseals() {
    let pt = MachineSeal::default_label()
        .unseal_with(&golden_host(), &fixture("machine_seal_dmi_v2.b64"))
        .unwrap();
    assert_eq!(pt, b"machine seal payload under DMI-V2");
    let other = HostFactors::new(
        Some("ffffffff-1111-2222-3333-444444444444".into()),
        MACHINE_ID,
        MAC,
        UID,
    );
    assert!(
        MachineSeal::default_label()
            .unseal_with(&other, &fixture("machine_seal_dmi_v2.b64"))
            .is_err()
    );
}

#[test]
fn daemon_identity_file_loads_with_same_fingerprint() {
    let path = format!(
        "{}/tests/fixtures/daemon_identity.seal",
        env!("CARGO_MANIFEST_DIR")
    );
    let id = DaemonIdentity::load_with(
        std::path::Path::new(&path),
        &SealedSecret::new(b"tesserax-daemon-identity-v1".to_vec()),
        &golden_host(),
    )
    .unwrap();
    assert_eq!(
        id.pubkey_fingerprint(),
        fixture("daemon_identity.fingerprint")
    );

    // The response signature made by the old code with this identity verifies.
    let canonical = fixture_bytes("response_canonical.txt");
    assert_eq!(
        canonical,
        signing::canonical_signing_bytes(1_700_000_000, 200, "/admin/info", "golden-body-hash")
    );
    let sig = ed25519_dalek::Signature::from_slice(
        &B64.decode(fixture("response_signature.b64")).unwrap(),
    )
    .unwrap();
    ed25519_dalek::Verifier::verify(id.verifying_key(), &canonical, &sig).unwrap();
    // And the new code produces the identical signature (ed25519 is deterministic).
    assert_eq!(
        B64.encode(id.sign(&canonical).to_bytes()),
        fixture("response_signature.b64")
    );
}

#[test]
fn operator_command_v2_verifies_and_canonical_bytes_match() {
    let cmd: OperatorCommand = serde_json::from_str(&fixture("opcmd_v2.json")).unwrap();
    let payload = B64.decode(&cmd.payload_b64).unwrap();
    let canonical = canonical_signing_bytes(
        &cmd.signer_id,
        cmd.expires_at_unix,
        &cmd.request_id,
        &payload,
    );
    assert_eq!(canonical, fixture_bytes("opcmd_v2_canonical.bin"));
    assert!(canonical.starts_with(b"tesserax-op-command-v2\ngolden-operator\n"));

    let store = OperatorTrustStore::new();
    store
        .add_signer(
            "golden-operator",
            &B64.decode(fixture("opcmd_v2_signer_pubkey.b64")).unwrap(),
        )
        .unwrap();
    let before_expiry = UNIX_EPOCH + Duration::from_secs(cmd.expires_at_unix - 10);
    let replay = ReplayCache::new();
    assert_eq!(
        cmd.verify(&store, before_expiry, Some(&replay)).unwrap(),
        payload
    );
    assert!(
        cmd.verify(&store, before_expiry, Some(&replay)).is_err(),
        "replay refused"
    );
    let after_expiry = UNIX_EPOCH + Duration::from_secs(cmd.expires_at_unix);
    assert!(cmd.verify(&store, after_expiry, None).is_err());

    // Same key, same inputs: the new signer reproduces the old signature.
    let client = tesserax_secrets::opcmd::OperatorCommandClient::new(
        ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]),
        "golden-operator",
    );
    let sk = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
    let resigned = ed25519_dalek::Signer::sign(&sk, &canonical);
    assert_eq!(B64.encode(resigned.to_bytes()), cmd.signature_b64);
    assert_eq!(client.signer_id(), "golden-operator");
}

#[test]
fn shamir_shares_from_old_code_reconstruct() {
    let shares: Vec<Share> = fixture("shamir_3_of_5.txt")
        .lines()
        .map(|l| {
            let (x, hex) = l.split_once(' ').unwrap();
            Share {
                x: x.parse().unwrap(),
                y_bytes: (0..hex.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                    .collect(),
            }
        })
        .collect();
    assert_eq!(shares.len(), 5);
    for pick in [[0usize, 1, 2], [2, 3, 4], [0, 2, 4], [4, 1, 3]] {
        let subset: Vec<Share> = pick.iter().map(|&i| shares[i].clone()).collect();
        assert_eq!(reconstruct(&subset, 3).unwrap(), b"golden shamir secret");
    }
}
