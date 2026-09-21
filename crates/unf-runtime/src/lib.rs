//! Process lifecycle support for the controller and agent, not the dataplane.

use std::io;

/// Register both Unix termination signals before spawning service tasks.
///
/// Holding the streams also retains a signal arriving before [`Self::wait`].
/// This is a shutdown request, not permission to delete durable dataplane state.
/// Callers remain responsible for cancelling and joining their existing tasks.
pub struct ShutdownSignals {
    #[cfg(unix)]
    interrupt: tokio::signal::unix::Signal,
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
}

impl ShutdownSignals {
    /// Register service shutdown listeners on the current Tokio runtime.
    ///
    /// # Errors
    /// Returns the operating system's signal-registration error.
    pub fn register() -> io::Result<Self> {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            Ok(Self {
                interrupt: signal(SignalKind::interrupt())?,
                terminate: signal(SignalKind::terminate())?,
            })
        }
        #[cfg(not(unix))]
        Ok(Self {})
    }

    /// Await SIGINT or SIGTERM (Ctrl-C on non-Unix platforms).
    ///
    /// # Errors
    /// Fails if the signal driver closes unexpectedly or Ctrl-C registration fails.
    pub async fn wait(&mut self) -> io::Result<()> {
        #[cfg(unix)]
        {
            let received = tokio::select! {
                received = self.interrupt.recv() => received,
                received = self.terminate.recv() => received,
            };
            received.ok_or_else(|| io::Error::other("service shutdown signal stream closed"))
        }
        #[cfg(not(unix))]
        tokio::signal::ctrl_c().await
    }
}
