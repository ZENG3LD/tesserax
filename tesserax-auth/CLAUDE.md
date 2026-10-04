# tesserax-auth

Contract header. The crate docs mirror this block.

```text
Role:      shell (axum middleware over the Tier / Principal / RouteTable types of the root)
Owns:      key rings (hashes only), failure ledger (AuthBan). No persistent state
           except a DerivedTokens secret file it is told to create.
Exports:   ct_eq, ct_eq_str, hmac_sha256, generate_key, KeyHash, KeyRecord, KeyRing, Grant, Door, Policy,
           PathTemplate, AuthGate, Denial, AuthLayer, AuthOutcome, AuthChain, AuthChainMode, AuthExt,
           DerivedTokens, AuthBan, AuthBanConfig, AuthError.
Imports:   tesserax (incl. tesserax::ct, the single constant-time compare), axum types, zeroize, getrandom,
           thiserror, tracing;
           feature toml: serde, toml.
Forbidden: any domain crate; tesserax-http / -transport / -mcp / -framework; `==` / `!=` on secret
           material outside ct.rs; open-by-default behaviour; any product, host or consumer name.
```
