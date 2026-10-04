//! The oracle: what this tier knows about the health and facts of the
//! tier below, pulled in parallel over the links it already holds and
//! published through a single-writer cache.
//!
//! The two defects of the moved code close here by construction: the poll
//! is parallel with a per-entry timeout (one dark entry no longer delays
//! the fleet), and the cache is a [`Published`] written by the poller
//! task alone — no shared `Mutex<Vec>` between a writer thread and
//! request handlers (SWC laws 2/3).

use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tesserax::publish::Published;
use thiserror::Error;

use super::link::DownLink;
use super::roster::{EntryId, EnvLookup, LinkTarget, Roster};

/// The shortest poll interval the poller accepts (the moved fleet loop
/// ran at 8 s timeouts; below this the links become the load).
pub const MIN_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// What one pull of one entry costs when it fails.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum OracleError {
    /// The link underneath failed.
    #[error("link: {0}")]
    Link(#[from] super::link::LinkError),
    /// The entry answered, but the report did not parse.
    #[error("report: {0}")]
    Report(String),
}

/// What an oracle knows how to do: pull a typed report from one entry,
/// over the down link this tier already holds. An oracle **enriches** the
/// roster's view; it never extends the roster (see [`reconcile`]).
pub trait Oracle: Send + Sync + 'static {
    /// The report type one pull returns.
    type Report: Serialize + Send + Sync + 'static;
    /// Pulls the report of the entry behind `link`.
    fn pull<'a>(
        &'a self,
        link: &'a DownLink,
    ) -> futures_util::future::BoxFuture<'a, Result<Self::Report, OracleError>>;
}

/// The fleet's view of one entry after one poll round.
#[derive(Clone, Debug, Serialize)]
pub struct OracleView<R> {
    /// The roster id this view is about.
    pub entry: EntryId,
    /// Whether the pull got an answer at all.
    pub reachable: bool,
    /// Why not, or why the report is absent.
    pub error: Option<String>,
    /// The pulled report, when there is one.
    pub report: Option<R>,
    /// When the pull finished, milliseconds since the Unix epoch.
    pub polled_at_ms: u64,
}

/// The published fleet view. Single writer: the poller task. Readers get
/// an `Arc` snapshot; they never wait on the poll.
pub struct FleetCache<R> {
    views: Arc<Published<Vec<OracleView<R>>>>,
    poller: tokio::task::JoinHandle<()>,
}

impl<R> std::fmt::Debug for FleetCache<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FleetCache").finish_non_exhaustive()
    }
}

impl<R> FleetCache<R> {
    /// The latest completed poll round (empty before the first finishes).
    pub fn snapshot(&self) -> Arc<Vec<OracleView<R>>> {
        self.views.load()
    }
}

impl<R> Drop for FleetCache<R> {
    fn drop(&mut self) {
        self.poller.abort();
    }
}

/// How the poller runs.
#[derive(Clone, Copy, Debug)]
pub struct PollConfig {
    /// Time between the starts of two rounds; clamped to
    /// [`MIN_POLL_INTERVAL`].
    pub interval: Duration,
    /// The most one entry's pull may take; the round does not wait for
    /// slower entries.
    pub per_entry_timeout: Duration,
}

impl Default for PollConfig {
    fn default() -> Self {
        Self {
            interval: MIN_POLL_INTERVAL,
            per_entry_timeout: Duration::from_secs(8),
        }
    }
}

/// Starts the fleet poller: every round pulls every entry **in
/// parallel**, each under its own timeout, and publishes the merged view
/// once per round. Links are built once at startup from the roster; an
/// entry whose link does not build is reported unreachable every round
/// with the build error.
///
/// Must be called inside a tokio runtime. The poll interval doubles as
/// the reconnect cadence — a dead entry is retried next round, never in a
/// hot loop (the capped-backoff rule of the moved node link).
pub fn spawn_poller<E, O>(roster: Roster<E>, oracle: O, cfg: PollConfig) -> FleetCache<O::Report>
where
    E: LinkTarget + Send + Sync + 'static,
    O: Oracle,
{
    spawn_poller_with(
        roster,
        oracle,
        cfg,
        Arc::new(|name| std::env::var(name).ok()),
    )
}

/// [`spawn_poller`] with the environment injected — the pure form, so
/// tests never touch the process environment.
pub fn spawn_poller_with<E, O>(
    roster: Roster<E>,
    oracle: O,
    cfg: PollConfig,
    env: EnvLookup,
) -> FleetCache<O::Report>
where
    E: LinkTarget + Send + Sync + 'static,
    O: Oracle,
{
    let interval = cfg.interval.max(MIN_POLL_INTERVAL);
    let links: Vec<(EntryId, Result<DownLink, String>)> = roster
        .iter()
        .map(|e| {
            (
                e.id().clone(),
                DownLink::resolve(e, env.as_ref()).map_err(|err| err.to_string()),
            )
        })
        .collect();
    let views = Arc::new(Published::new(Vec::new()));
    let writer = Arc::clone(&views);
    let poller = tokio::spawn(async move {
        let oracle = oracle;
        loop {
            let round = poll_round(&links, &oracle, cfg.per_entry_timeout).await;
            writer.store(round);
            tokio::time::sleep(interval).await;
        }
    });
    FleetCache { views, poller }
}

/// One parallel round over pre-built links. Entries are polled with
/// `FuturesUnordered`; the merged view keeps roster order.
async fn poll_round<O: Oracle>(
    links: &[(EntryId, Result<DownLink, String>)],
    oracle: &O,
    timeout: Duration,
) -> Vec<OracleView<O::Report>> {
    use futures_util::StreamExt;
    let mut pulls = links
        .iter()
        .map(|(id, link)| async move {
            let pulled_at = now_ms();
            match link {
                Err(build) => OracleView {
                    entry: id.clone(),
                    reachable: false,
                    error: Some(build.clone()),
                    report: None,
                    polled_at_ms: pulled_at,
                },
                Ok(link) => match tokio::time::timeout(timeout, oracle.pull(link)).await {
                    Err(_) => OracleView {
                        entry: id.clone(),
                        reachable: false,
                        error: Some(format!("pull timed out after {timeout:?}")),
                        report: None,
                        polled_at_ms: pulled_at,
                    },
                    Ok(Err(e)) => OracleView {
                        entry: id.clone(),
                        reachable: false,
                        error: Some(e.to_string()),
                        report: None,
                        polled_at_ms: pulled_at,
                    },
                    Ok(Ok(report)) => OracleView {
                        entry: id.clone(),
                        reachable: true,
                        error: None,
                        report: Some(report),
                        polled_at_ms: pulled_at,
                    },
                },
            }
        })
        .collect::<futures_util::stream::FuturesUnordered<_>>();
    let mut out = Vec::with_capacity(links.len());
    while let Some(view) = pulls.next().await {
        out.push(view);
    }
    out.sort_by(|a, b| a.entry.cmp(&b.entry));
    out
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A report that names the members it knows about (for [`reconcile`]).
pub trait Identified {
    /// The ids the report claims.
    fn member_ids(&self) -> Vec<EntryId>;
}

/// The roster, reconciled against one report.
pub struct Reconciled<'r, E> {
    /// Roster entries the report also names — the agreed membership.
    pub known: Vec<&'r E>,
    /// Ids the report names that are **not** on the roster: suspicious
    /// facts, never new members (NCP §5; membership changes by operator
    /// edit + restart, not by what a link claims).
    pub unresolved: Vec<EntryId>,
}

/// Splits a report's claimed membership into rostered (`known`) and
/// everything else (`unresolved`). An id a link reports cannot add
/// itself to the fleet.
pub fn reconcile<'r, E: super::roster::RosterEntry>(
    roster: &'r Roster<E>,
    report: &impl Identified,
) -> Reconciled<'r, E> {
    let mut known = Vec::new();
    let mut unresolved = Vec::new();
    for id in report.member_ids() {
        match roster.get(&id) {
            Some(entry) => known.push(entry),
            None => unresolved.push(id),
        }
    }
    Reconciled { known, unresolved }
}
