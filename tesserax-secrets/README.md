# tesserax-secrets

Secrets at rest and signing for services built with `tesserax`. `SealedSecret` and `MachineSeal` bind encrypted data to the host, `DaemonIdentity` gives a service instance an ed25519 key that is sealed at rest, and the `opcmd` module covers ed25519-signed operator commands with a trust store and a replay cache. The crate also provides k-of-n Shamir sharing, a host-move tripwire, key sources and canonical bytes for signed responses. Three features are off by default: `hardening` (process lockdown, the crate's only `unsafe` code), `opctl` (operator HTTP tooling and the `tesserax-opctl` binary) and `peer-trust` (signed trust gossip between services). Storage and wire formats use the tesserax domain labels and are checked against golden vectors.

Licensed under either of MIT or Apache-2.0, at your option.
