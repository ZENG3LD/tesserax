# tesserax-secrets

Contract header. The crate docs mirror this block.

```text
Role:      engine (crypto-at-rest logic); features `opctl`, `peer-trust` add client shells
Owns:      nothing stateful except files it is told to seal (identity, sealed blobs, tripwire pin)
Exports:   MachineSeal, SealedSecret, SealedPlaintext, HostFactors, BindingStrength, DaemonIdentity, wipe_identity,
           shamir::{split, reconstruct, Share}, tripwire::{check_or_pin, TripwirePolicy},
           keysource::{KeySource, DmiKeySource, RemoteKeySource, StaticKeySource},
           platform::{machine_id, product_uuid, primary_mac, uid},
           opcmd::{OperatorCommand, OperatorTrustStore, ReplayCache, OperatorCommandClient},
           signing::{ResponseSigningState, SignedResponseConfig, SigningScope, canonical_signing_bytes},
           hardening::harden_process (feature), opctl (feature), peer_trust (feature), SecretsError.
Imports:   tesserax (no default features), sha2, blake3, chacha20poly1305, aes-gcm, hkdf, ed25519-dalek,
           zeroize, getrandom, base64, serde, serde_json, thiserror, tracing;
           feature hardening: libc; feature opctl: reqwest, tokio, clap.
Forbidden: axum, rusqlite, tesserax-auth/-http/-store/-framework; `unsafe` outside module `hardening`;
           a constant-time compare of its own; any product, host or consumer name.
```
