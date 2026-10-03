# tesserax-auth

Authentication for servers built with `tesserax`. Requests are admitted through named doors, each with a path policy that is closed by default. Keys are stored only as SHA-256 hashes in a key ring that can be swapped atomically, and every presented key is compared against every record in constant time. The crate also provides HMAC-SHA256, derived per-subject tokens, and a ban ledger for repeated authentication failures. `AuthExt::with_auth` installs the gate at the builder's `TierGate` stage and the ban check at `PeerGuard`. An empty key ring denies everything.

Licensed under either of MIT or Apache-2.0, at your option.
