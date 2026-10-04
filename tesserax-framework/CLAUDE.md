# tesserax-framework

Contract header. The crate docs mirror this block.

```text
Role:      kernel (module kernel); shell (modules runtime, shell, and, behind their features, ncp, agent, plugins)
Owns:      the kernel of one Domain (single writer: domain, counters, step bookkeeping); per runtime: the
           kernel side of one port, one bounded observation inbox, one executor.
Exports:   Domain, Tick, Core, CoreResume, CoreStats, CoreError, ObservationDrops, Step, Counter, Exhausted;
           Runtime, DomainHandle, RuntimeConfig, RuntimeHandle, RuntimeStats, RuntimeError, TickReport,
           Executor, Refusal, ThreadExecutor, ThreadExecutorConfig, ObservationSink, EffectTicket, SinkError,
           SinkRejected, SinkStats; feature tokio: TokioExecutor, TokioExecutorConfig; feature store: PersistExecutor,
           PersistConfig, PersistOutcome; FrameworkError, ShellError; feature shell: shell::{http_shell,
           ShellOpts, local_shell, LocalShellOpts}; feature client: shell::{RemoteHandle, HttpRemote,
           LocalRemote}; shell or client: shell::{wire, LinkKeys, LinkContext};
           tier features (node / c2 / hq, node-os): ncp::{TierKind, EntryId, Reach, CredentialSource,
           LinkSpec, DialEntry, Roster, DownLink, AttachListener, Oracle, FleetCache, spawn_poller,
           reconcile, PassthroughPolicy (c2), the tier builders, NcpError};
           feature agent: agent::{Verb, VerbCx, VerbCode, VerbError, AgentDoor, AgentSurface,
           VERBS_PATH_PREFIX};
           feature plugins: plugins::{PluginHost, PluginManifest, RestartPolicy, PluginError}.
Imports:   tesserax (default-features = false), thiserror; feature tokio: tokio (rt, time);
           feature store: tesserax-store; feature shell: tesserax-auth, tesserax-http,
           tesserax-transport, axum, tokio, serde, tracing; feature client: tesserax-transport, hyper,
           tokio, serde; feature agent: tesserax-auth, tesserax-http, tesserax-mcp, axum, serde;
           feature plugins: zeroize.
Forbidden: in `kernel`: tokio, locks, channels, atomics, threads, fs, network (SWC law 3 — checked by
           tests/kernel_purity.rs); a second door into the kernel beside the port and the observation
           sink; product vocabulary.
```
