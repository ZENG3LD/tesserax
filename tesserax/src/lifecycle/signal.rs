//! [`graceful_shutdown_signal`] — resolves when the OS asks the process to stop.

/// Resolves on SIGTERM or SIGINT.
#[cfg(unix)]
pub async fn graceful_shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let (mut term, mut int) = match (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
    ) {
        (Ok(t), Ok(i)) => (t, i),
        (Err(e), _) | (_, Err(e)) => {
            tracing::warn!(
                "installing SIGTERM/SIGINT handlers failed ({e}); waiting for Ctrl-C only"
            );
            let _ = tokio::signal::ctrl_c().await;
            return;
        }
    };
    tokio::select! {
        _ = term.recv() => tracing::info!("shutdown signal: SIGTERM"),
        _ = int.recv() => tracing::info!("shutdown signal: SIGINT"),
    }
}

/// Resolves on Ctrl-C.
#[cfg(not(unix))]
pub async fn graceful_shutdown_signal() {
    match tokio::signal::ctrl_c().await {
        Ok(()) => tracing::info!("shutdown signal: Ctrl-C"),
        Err(e) => tracing::warn!("installing the Ctrl-C handler failed: {e}"),
    }
}
