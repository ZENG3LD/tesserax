//! The kernel: one [`Domain`], one writer, one synchronous [`Core::step`].
//!
//! Role: kernel. This module performs no IO and holds no synchronisation
//! primitive; it never waits on anything. Everything it needs arrives as
//! arguments of [`Core::step`] and everything it produces leaves in the
//! returned [`Step`]. The [`runtime`](crate::runtime) is the shell that feeds
//! it and publishes its output.
//!
//! # Phase order (fixed)
//!
//! Every call of [`Core::step`] runs these phases, in this order, once:
//!
//! 1. **advance** — the logical tick rises by one and
//!    [`Domain::advance`] runs (the kernel's only clock; no wall time).
//! 2. **commands** — each command, in arrival order, goes to
//!    [`Domain::apply_command`] and gets exactly one outcome and one
//!    `Accepted` / `Rejected` event. A rejected command's effects and events
//!    are discarded, the operation ids it drew are handed back and its
//!    `mark_changed` is forgotten.
//! 3. **observations** — each observation is checked (issued operation id,
//!    known subject, current generation) and only then handed to
//!    [`Domain::apply_observation`]; anything else is dropped and counted.
//! 4. **project** — iff the tick changed anything, [`Domain::project`] runs
//!    once and the snapshot revision rises by one.
//! 5. **stamp** — pending events get their sequences (strictly +1), the
//!    snapshot's `through_sequence` is the last of them.
//!
//! # Counters
//!
//! Operation ids, event sequences, snapshot revisions and the logical tick
//! are `u64` counters that never wrap. When one runs out it saturates into
//! a [`CoreHealth`](tesserax::swc::CoreHealth) flag; from then on every
//! command is rejected with
//! [`RejectCode::Exhausted`](tesserax::swc::RejectCode::Exhausted). When the
//! revision or the logical tick is spent, the kernel can no longer publish
//! and every later step is *blocked*: commands are rejected, observations
//! dropped and counted, nothing is projected.

mod core;
mod domain;
mod tick;

pub use self::core::{Core, CoreError, CoreResume, CoreStats, ObservationDrops, Step};
pub use self::domain::Domain;
pub use self::tick::{Counter, Exhausted, Tick};
