//! Contract tests of the in-process SWC port.
//!
//! The rules live in `swc_suite` (generic over `Port`) so that remote ports
//! run the very same tests; here they run over the in-process `Handle`.

#[macro_use]
mod swc_suite;

use swc_suite::{Cmd, Ev, Fixture, State};
use tesserax::swc::{Handle, KernelPort, PortConfig, bounded_port};

struct InProcess;

impl Fixture for InProcess {
    type Port = Handle<Cmd, Ev, State>;
    type Guard = ();
    const IN_PROCESS: bool = true;

    fn open(cfg: PortConfig) -> (Self::Port, KernelPort<Cmd, Ev, State>, ()) {
        let (handle, kernel) = bounded_port(cfg);
        (handle, kernel, ())
    }
}

contract_suite!(InProcess);
