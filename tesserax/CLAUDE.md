# tesserax

Contract header. The crate docs mirror this block.

```text
Role:      types + handle (modules swc, tier, principal, audit, net, publish, cache, ct, route_table, error;
           always compiled)
           shell (feature `server`: modules builder, server, lifecycle, listener, config)
Owns:      no domain state. The port edge owns only the published snapshot, event-log ring and subscriber
           list of one port. `server`: the layer-slot table of one builder, listener tasks, shutdown
           broadcast, drain flag.
Exports:   swc::{CommandEnvelope, EffectEnvelope, ObservationEnvelope, EventEnvelope, CoreEvent, Snapshot,
           Handle, Port, KernelPort, bounded_port, ResyncReply, SnapshotCache}; Tier, TierSet, Scope, ScopeSet,
           Principal, KeyId, DoorName, AuditSink, AuditEvent; Cidr, CidrList, honest_client_ip; Published<T>,
           Flags, LruCache; RouteTable, RouteEntry, HttpMethod; ct::{ct_eq, ct_eq_str, ct_eq_array, hmac_sha256};
           feature server: ServerBuilder, Server, RunningServer, ServerPlugin, BuildCx, LayerStage, Transport,
           BuildError, RunError, lifecycle::*, listener::{ListenerDriver, DriverListener, ListenerAddr,
           ShutdownSignal} (the accept-loop hook transport crates use for Tls / Ipc).
Imports:   arc-swap, thiserror, sha2, subtle; feature serde: serde; feature server: tokio, axum, tracing, serde_json.
Forbidden: any other tesserax-* crate; database, crypto beyond sha2 (+ subtle for ct), outbound network clients; in the always-compiled
           modules: tokio, axum, tower, std::fs, sockets; reading any configuration file implicitly;
           any product, host or consumer name.
```
