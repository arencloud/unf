//! One job slot retained through actual nested namespace-worker completion.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::{Semaphore, oneshot};
use tokio::task::JoinHandle;
use unf_cni_state::AttachmentRecord;
use unf_encryption::{EncryptionLocalityContext, VerifiedEncryptionLocality};
use unf_route::NativeRoutingProvider;

use crate::kernel::build::{self, PreparationControl};
use crate::{
    KernelLocalityBank, LeasedLocalityBank, LocalityBankError, LocalityRuntimeMaps,
    ObservedLocalityBank,
};

const MAX_INPUT_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
const OBSERVATION_DEADLINE: Duration = Duration::from_secs(60);

/// Keep one worker for the publisher's lifetime. Retiring a candidate must not
/// replace its worker/slot while an earlier namespace job is still draining.
pub struct LocalityObservationWorker {
    slot: Arc<Semaphore>,
}

/// Dropping a pending job cooperatively cancels its private async observation.
/// Started namespace workers drain before its slot is released.
pub struct LocalityObservationTask {
    task: JoinHandle<Result<ObservedLocalityBank, LocalityBankError>>,
    cancellation: Option<oneshot::Sender<()>>,
}

/// The same worker slot also covers kernel allocation, actual namespace seeding,
/// sealing and final route/link rechecks. Dropping the waiter never releases a
/// started job's slot before its namespace thread and runtime have drained.
pub struct LocalityPreparationTask {
    task: JoinHandle<anyhow::Result<KernelLocalityBank>>,
    cancelled: Arc<AtomicBool>,
    cancellation: Option<oneshot::Sender<()>>,
}

impl Drop for LocalityPreparationTask {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        if let Some(cancellation) = self.cancellation.take() {
            let _ = cancellation.send(());
        }
        self.task.abort();
    }
}

impl LocalityPreparationTask {
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }

    /// Consume a sealed, still unpublished bank. Publication separately checks
    /// the original journal cut, current applied context and exact runtime.
    ///
    /// # Errors
    /// Reports cancellation, budget/kernel/observation errors or worker panic.
    pub async fn finish(mut self) -> anyhow::Result<KernelLocalityBank> {
        (&mut self.task).await?
    }
}

impl Drop for LocalityObservationTask {
    fn drop(&mut self) {
        if let Some(cancellation) = self.cancellation.take() {
            let _ = cancellation.send(());
        }
        // Abort cancels a still-queued blocking job. A started one receives the
        // cooperative signal and retains its permit while its runtime drains.
        self.task.abort();
    }
}

impl LocalityObservationTask {
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }

    /// Consume a preparation, still subject to current context/journal fencing.
    ///
    /// # Errors
    /// Reports observation failure, cancellation or worker panic. Cancelling
    /// this await drops the task and signals its private observation runtime.
    pub async fn finish(mut self) -> Result<ObservedLocalityBank, LocalityBankError> {
        (&mut self.task).await.map_err(LocalityBankError::Task)?
    }
}

impl Default for LocalityObservationWorker {
    fn default() -> Self {
        Self {
            slot: Arc::new(Semaphore::new(1)),
        }
    }
}

impl LocalityObservationWorker {
    /// Non-queuing bank preparation using this worker's EXISTING observation
    /// slot. Retain one worker for the publisher lifetime; never replace it when
    /// retiring a candidate. ELF must be the authenticated packaged consumer,
    /// not network/CNI-provided bytes. `pin_root` is a private runtime bpffs root.
    /// Namespace changes occur only on a dedicated, joined OS thread.
    ///
    /// # Errors
    /// Rejects empty/oversized ELF or retired/empty endpoint input before work.
    /// Returns `None` while earlier real work is still queued/running/draining.
    pub fn try_prepare(
        &self,
        leased: LeasedLocalityBank,
        runtime: &LocalityRuntimeMaps,
        elf: Vec<u8>,
        pin_root: PathBuf,
    ) -> anyhow::Result<Option<LocalityPreparationTask>> {
        anyhow::ensure!(
            !elf.is_empty() && elf.len() <= 4 * 1024 * 1024,
            "locality ELF byte budget"
        );
        anyhow::ensure!(
            leased
                .observed()
                .endpoints()
                .is_some_and(|rows| !rows.is_empty() && rows.len() <= 65_536),
            "invalid kernel bank input"
        );
        let maps = Arc::clone(&runtime.maps);
        let cancelled = Arc::new(AtomicBool::new(false));
        let control = PreparationControl {
            cancelled: Arc::clone(&cancelled),
            deadline: Instant::now() + OBSERVATION_DEADLINE,
        };
        let (cancellation, cancellation_received) = oneshot::channel();
        let task = self.try_spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().max_blocking_threads(2).build()?;
            let result = runtime.block_on(async {
                let preparation = tokio::time::timeout(OBSERVATION_DEADLINE, build::prepare(leased, maps, &elf, &pin_root, &control));
                tokio::select! {
                    biased;
                    _ = cancellation_received => Err(anyhow::anyhow!("locality preparation cancelled")),
                    result = preparation => result.map_err(|_| anyhow::anyhow!("locality preparation deadline exceeded"))?,
                }
            });
            control.cancelled.store(true, Ordering::Release);
            drop(runtime);
            result
        });
        Ok(task.map(|task| LocalityPreparationTask {
            task,
            cancelled,
            cancellation: Some(cancellation),
        }))
    }

    /// Non-queuing background kernel observation. The single permit belongs to
    /// the blocking closure, not its async waiter. Aborting/dropping a started
    /// handle cannot release capacity while its namespace workers still run.
    /// A private runtime drains those workers before the permit is dropped,
    /// including early errors and the sixty-second observation deadline.
    ///
    /// Returns `None` while the previous real job is queued/running/draining.
    /// No journal lock is held, no lease issued and no packet program published.
    /// The caller must revalidate applied context and the real journal cut when
    /// consuming a finished preparation. Namespace leaf read workers have their
    /// own ten-second deadlines; this is not an instantaneous cancellation claim.
    ///
    /// # Errors
    /// Rejects foreign context, over-budget count/payload and arithmetic overflow
    /// before any namespace observation. The payload budget is logical, not RSS.
    pub fn try_observe(
        &self,
        provider: NativeRoutingProvider,
        records: Vec<AttachmentRecord>,
        evidence: VerifiedEncryptionLocality,
        expected: EncryptionLocalityContext,
    ) -> Result<Option<LocalityObservationTask>, LocalityBankError> {
        validate_input(&records, &evidence, &expected)?;
        let (cancellation, cancelled) = oneshot::channel();
        let task = self.try_spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .max_blocking_threads(2)
                .build()
                .map_err(LocalityBankError::Runtime)?;
            let result = runtime.block_on(async {
                let observe = tokio::time::timeout(OBSERVATION_DEADLINE, async {
                    let observations = provider.observe_bound_attachments(&records).await?;
                    ObservedLocalityBank::join(&evidence, &expected, observations)
                });
                tokio::select! {
                    biased;
                    _ = cancelled => Err(LocalityBankError::Worker("observation cancelled")),
                    result = observe => result.map_err(|_| LocalityBankError::Worker("observation deadline exceeded"))?,
                }
            });
            // Tokio runtime Drop waits for its started spawn_blocking workers,
            // whose namespace threads are joined by the link/route providers.
            // Never replace this with shutdown_background/shutdown_timeout.
            drop(runtime);
            result
        });
        Ok(task.map(|task| LocalityObservationTask {
            task,
            cancellation: Some(cancellation),
        }))
    }

    fn try_spawn<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> Option<JoinHandle<T>> {
        let permit = Arc::clone(&self.slot).try_acquire_owned().ok()?;
        Some(tokio::task::spawn_blocking(move || {
            let _permit = permit;
            work()
        }))
    }
}

fn validate_input(
    records: &[AttachmentRecord],
    evidence: &VerifiedEncryptionLocality,
    expected: &EncryptionLocalityContext,
) -> Result<(), LocalityBankError> {
    if records.len() > 65_536 || evidence.certificate().context() != expected {
        return Err(LocalityBankError::Invalid(
            "observation worker context or count",
        ));
    }
    let mut retained = 0_usize;
    for record in records {
        for length in [
            std::mem::size_of::<AttachmentRecord>(),
            record.spec.key.network.len(),
            record.spec.key.container_id.len(),
            record.spec.key.ifname.len(),
            record.spec.netns.len(),
            record.spec.workload_uid.as_deref().map_or(0, str::len),
            record.host_interface.len(),
        ] {
            retained = retained
                .checked_add(length)
                .ok_or(LocalityBankError::Invalid(
                    "observation worker input overflow",
                ))?;
            if retained > MAX_INPUT_PAYLOAD_BYTES {
                return Err(LocalityBankError::Invalid(
                    "observation worker input payload budget",
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn worker_rejects_foreign_context_and_oversized_payload_without_namespace_work() {
        let worker = LocalityObservationWorker::default();
        let (evidence, context) = crate::observed::tests::evidence(true);
        let mut foreign = context.clone();
        foreign.identity_epoch += 1;
        let provider = NativeRoutingProvider::new(1400);
        assert!(
            worker
                .try_observe(provider, vec![], evidence.clone(), foreign)
                .is_err()
        );
        let mut record = crate::observed::tests::record();
        record.spec.netns = "x".repeat(MAX_INPUT_PAYLOAD_BYTES);
        assert!(
            worker
                .try_observe(provider, vec![record], evidence.clone(), context.clone())
                .is_err()
        );
        let empty = worker
            .try_observe(provider, vec![], evidence, context)
            .unwrap()
            .unwrap()
            .finish()
            .await
            .unwrap();
        assert!(empty.endpoints().unwrap().is_empty());
        assert!(empty.addresses().unwrap().is_empty());
    }

    #[tokio::test]
    async fn aborting_a_started_job_does_not_release_its_capacity() {
        let worker = LocalityObservationWorker::default();
        let (started, ready) = tokio::sync::oneshot::channel();
        let (release, wait) = std::sync::mpsc::channel();
        let task = worker
            .try_spawn(move || {
                started.send(()).unwrap();
                wait.recv().unwrap();
            })
            .unwrap();
        ready.await.unwrap();
        task.abort();
        assert!(worker.try_spawn(|| ()).is_none());
        release.send(()).unwrap();
        task.await.unwrap();
        worker.try_spawn(|| ()).unwrap().await.unwrap();
    }

    #[tokio::test]
    async fn early_async_failure_retains_slot_until_nested_workers_really_exit() {
        let worker = LocalityObservationWorker::default();
        let (started, ready) = tokio::sync::oneshot::channel();
        let (release, wait) = std::sync::mpsc::channel();
        let task = worker
            .try_spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                let result = runtime.block_on(async {
                    let _nested = tokio::task::spawn_blocking(move || {
                        wait.recv().unwrap();
                    });
                    started.send(()).unwrap();
                    Err::<(), _>("injected early observation failure")
                });
                drop(runtime);
                result
            })
            .unwrap();
        ready.await.unwrap();
        task.abort();
        assert!(worker.try_spawn(|| ()).is_none());
        release.send(()).unwrap();
        assert!(task.await.unwrap().is_err());
        worker.try_spawn(|| ()).unwrap().await.unwrap();
    }

    #[tokio::test]
    async fn dropping_the_public_task_signals_cancellation_without_releasing_nested_work() {
        let worker = LocalityObservationWorker::default();
        let (cancellation, cancelled) = oneshot::channel();
        let (started, ready) = oneshot::channel();
        let (noticed, notice) = oneshot::channel();
        let (finished, finish) = oneshot::channel();
        let (release, wait) = std::sync::mpsc::channel();
        let task = worker
            .try_spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async {
                    let _nested = tokio::task::spawn_blocking(move || {
                        wait.recv().unwrap();
                    });
                    started.send(()).unwrap();
                    cancelled.await.unwrap();
                    noticed.send(()).unwrap();
                });
                drop(runtime);
                finished.send(()).unwrap();
                Err(LocalityBankError::Worker("cancelled model"))
            })
            .unwrap();
        let task = LocalityObservationTask {
            task,
            cancellation: Some(cancellation),
        };
        ready.await.unwrap();
        drop(task);
        notice.await.unwrap();
        assert!(worker.try_spawn(|| ()).is_none());
        release.send(()).unwrap();
        finish.await.unwrap();
        // The completion notification precedes closure return/permit Drop.
        // Acquire the actual semaphore rather than racing that final unwind.
        let permit = Arc::clone(&worker.slot).acquire_owned().await.unwrap();
        drop(permit);
        worker.try_spawn(|| ()).unwrap().await.unwrap();
    }
}
