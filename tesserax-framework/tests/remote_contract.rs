//! The B1a port contract, run over `RemoteHandle`: once through
//! `http_shell` (HTTP + SSE), once through `local_shell` (NDJSON over an
//! owner-only socket). Same tests as the in-process `Handle` runs in the
//! root crate (`tesserax/tests/swc_contract.rs`).

#![cfg(all(feature = "shell", feature = "client", unix))]

mod common_shell;
#[macro_use]
#[path = "../../tesserax/tests/swc_suite/mod.rs"]
mod swc_suite;

use std::time::Duration;

use swc_suite::{Cmd, Ev, Fixture, State};
use tesserax::swc::{KernelPort, PortConfig, bounded_port};
use tesserax_framework::shell::RemoteHandle;

/// 10 000 refused dispatches over a wire are 10 000 round trips (tens of
/// microseconds each on loopback): at most 1 ms each on a loaded box.
const REMOTE_REFUSALS_BUDGET: Duration = Duration::from_secs(10);

mod over_http {
    use super::*;

    struct OverHttp;

    impl Fixture for OverHttp {
        type Port = RemoteHandle<Cmd, Ev, State>;
        type Guard = common_shell::Served;
        const IN_PROCESS: bool = false;
        const REFUSALS_BUDGET: Duration = REMOTE_REFUSALS_BUDGET;

        fn open(cfg: PortConfig) -> (Self::Port, KernelPort<Cmd, Ev, State>, Self::Guard) {
            let (handle, kernel) = bounded_port::<Cmd, Ev, State>(cfg);
            let served = common_shell::serve_http(handle);
            let remote = common_shell::http_remote(&served, common_shell::FULL_KEY);
            (remote, kernel, served)
        }
    }

    contract_suite!(OverHttp);
}

mod over_local {
    use super::*;

    struct OverLocal;

    impl Fixture for OverLocal {
        type Port = RemoteHandle<Cmd, Ev, State>;
        type Guard = common_shell::Served;
        const IN_PROCESS: bool = false;
        const REFUSALS_BUDGET: Duration = REMOTE_REFUSALS_BUDGET;

        fn open(cfg: PortConfig) -> (Self::Port, KernelPort<Cmd, Ev, State>, Self::Guard) {
            let (handle, kernel) = bounded_port::<Cmd, Ev, State>(cfg);
            let served = common_shell::serve_local(handle);
            let remote = common_shell::local_remote(&served, common_shell::server_keys());
            (remote, kernel, served)
        }
    }

    contract_suite!(OverLocal);
}
