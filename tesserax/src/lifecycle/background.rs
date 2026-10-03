//! [`BackgroundTask`] — interval task that stops on the shutdown broadcast.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;
use tracing::{debug, error, info};

use super::hooks::BoxError;
use super::shutdown::ShutdownBroadcast;

/// Handle to a spawned periodic task.
pub struct BackgroundTask {
    name: Arc<str>,
    handle: JoinHandle<()>,
}

impl BackgroundTask {
    /// Spawns `work` every `period`, first run immediately. When `shutdown`
    /// fires, the loop exits after the iteration in flight. Errors are
    /// logged and do not stop the loop. Must be called inside a tokio
    /// runtime.
    pub fn spawn<F, Fut>(
        name: impl Into<Arc<str>>,
        period: Duration,
        shutdown: &ShutdownBroadcast,
        work: F,
    ) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), BoxError>> + Send + 'static,
    {
        let name: Arc<str> = name.into();
        let label = Arc::clone(&name);
        let mut rx = shutdown.subscribe();
        let period = period.max(Duration::from_millis(1));
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(period);
            info!(task = %label, period_ms = period.as_millis() as u64, "background task started");
            loop {
                tokio::select! {
                    _ = rx.recv() => break,
                    _ = interval.tick() => match work().await {
                        Ok(()) => debug!(task = %label, "tick ok"),
                        Err(e) => error!(task = %label, "tick error: {e}"),
                    },
                }
            }
            info!(task = %label, "background task exited");
        });
        Self { name, handle }
    }

    /// Task name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// True once the task has finished.
    pub fn is_finished(&self) -> bool {
        self.handle.is_finished()
    }

    /// Cancels the task without letting the iteration in flight finish.
    pub fn abort(self) {
        self.handle.abort();
    }

    /// Detaches, returning the join handle.
    pub fn detach(self) -> JoinHandle<()> {
        self.handle
    }
}

impl std::fmt::Debug for BackgroundTask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackgroundTask")
            .field("name", &self.name)
            .field("finished", &self.is_finished())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn task_ticks_and_drains_on_shutdown() {
        let bx = ShutdownBroadcast::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&counter);
        let task = BackgroundTask::spawn("counter", Duration::from_millis(30), &bx, move || {
            let c = Arc::clone(&c);
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        });
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(counter.load(Ordering::SeqCst) >= 2);
        bx.fire();
        tokio::time::timeout(Duration::from_secs(1), task.detach())
            .await
            .expect("task exits after shutdown")
            .expect("task did not panic");
    }
}
