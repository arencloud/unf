//! Serialized publication across independent asynchronous identity/route writers.
//! A successful writer never rearms admission; all writers must be durably settled.
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

use anyhow::{Result, ensure};
use unf_cni_state::AttachmentJournal;
use unf_common::Revision;
use unf_encryption::EncryptionLocalityContext;

use crate::{
    IncarnationGate, KernelLocalityBank, LeasedLocalityBank, LocalityObservationWorker,
    LocalityPreparationTask, LocalityRuntimeMaps,
};

/// Independently applied inputs used by the packet-time placement fence.
#[derive(Clone, Copy, Debug)]
pub enum LocalityApplyComponent {
    Identity,
    Routing,
}

impl LocalityApplyComponent {
    const fn index(self) -> usize {
        match self {
            Self::Identity => 0,
            Self::Routing => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Applied {
    Unknown,
    Updating(u64),
    Failed,
    Current { epoch: u64, revision: u64 },
}

trait FenceRuntime {
    fn withdraw(&mut self) -> Result<()>;
    fn arm(&mut self, context: &EncryptionLocalityContext) -> Result<()>;
}

impl FenceRuntime for LocalityRuntimeMaps {
    fn withdraw(&mut self) -> Result<()> {
        Self::withdraw(self)
    }
    fn arm(&mut self, context: &EncryptionLocalityContext) -> Result<()> {
        self.set_applied(context)
    }
}

struct State<R: FenceRuntime> {
    runtime: R,
    applied: [Applied; 2],
    serial: u64,
    poisoned: bool,
}

impl<R: FenceRuntime> State<R> {
    fn health(&self) -> Result<()> {
        ensure!(
            !self.poisoned,
            "locality admission has an uncertain kernel fence; stop runtime"
        );
        Ok(())
    }

    fn is_applied(
        &self,
        component: LocalityApplyComponent,
        epoch: u64,
        revision: Revision,
    ) -> Result<bool> {
        self.health()?;
        Ok(epoch != 0
            && revision.get() != 0
            && self.applied[component.index()]
                == Applied::Current {
                    epoch,
                    revision: revision.get(),
                })
    }

    fn new(mut runtime: R) -> Result<Self> {
        runtime.withdraw()?;
        Ok(Self {
            runtime,
            applied: [Applied::Unknown; 2],
            serial: 0,
            poisoned: false,
        })
    }

    fn withdraw(&mut self) -> Result<()> {
        ensure!(
            !self.poisoned,
            "locality admission has an uncertain kernel fence"
        );
        if let Err(error) = self.runtime.withdraw() {
            self.poisoned = true;
            self.applied = [Applied::Failed; 2];
            return Err(error.context("locality admission withdrawal failed; stop this runtime"));
        }
        Ok(())
    }

    fn begin(&mut self, component: LocalityApplyComponent) -> Result<u64> {
        ensure!(
            !matches!(self.applied[component.index()], Applied::Updating(_)),
            "overlapping writers for one locality component"
        );
        // This completes before returning the writer guard, hence before the
        // caller may mutate identity maps, routes or their durable checkpoint.
        self.withdraw()?;
        let Some(serial) = self.serial.checked_add(1) else {
            self.poisoned = true;
            anyhow::bail!("locality apply serial exhausted");
        };
        self.serial = serial;
        self.applied[component.index()] = Applied::Updating(serial);
        Ok(serial)
    }

    fn check(&self, context: &EncryptionLocalityContext) -> Result<()> {
        ensure!(!self.poisoned, "poisoned locality admission");
        ensure!(
            context.identity_epoch != 0
                && context.identity_revision.get() != 0
                && context.routing_revision.get() != 0,
            "zero locality applied coordinate"
        );
        ensure!(
            self.applied
                == [
                    Applied::Current {
                        epoch: context.identity_epoch,
                        revision: context.identity_revision.get()
                    },
                    Applied::Current {
                        epoch: context.identity_epoch,
                        revision: context.routing_revision.get()
                    },
                ],
            "locality inputs are unsettled, failed or changed"
        );
        Ok(())
    }

    fn admit<T>(
        &mut self,
        context: &EncryptionLocalityContext,
        publish: impl FnOnce(&mut R) -> Result<T>,
    ) -> Result<T> {
        self.withdraw()?;
        self.check(context)?;
        let result = (|| {
            let value = publish(&mut self.runtime)?;
            self.runtime.arm(context)?;
            Ok(value)
        })();
        if let Err(error) = result {
            self.applied = [Applied::Failed; 2];
            let withdrawal = self.withdraw();
            anyhow::bail!("locality admission failed: {error:#}; withdrawal={withdrawal:?}");
        }
        result
    }
}

fn lock<R: FenceRuntime>(state: &Mutex<State<R>>) -> Result<MutexGuard<'_, State<R>>> {
    state
        .lock()
        .map_err(|_| anyhow::anyhow!("locality admission mutex poisoned"))
}

struct Update<R: FenceRuntime> {
    state: Arc<Mutex<State<R>>>,
    component: LocalityApplyComponent,
    serial: u64,
}

impl<R: FenceRuntime> Update<R> {
    fn begin(state: &Arc<Mutex<State<R>>>, component: LocalityApplyComponent) -> Result<Self> {
        let serial = lock(state)?.begin(component)?;
        Ok(Self {
            state: Arc::clone(state),
            component,
            serial,
        })
    }

    fn complete(self, epoch: u64, revision: Revision) -> Result<()> {
        ensure!(
            epoch != 0 && revision.get() != 0,
            "zero locality apply completion"
        );
        let mut state = lock(&self.state)?;
        ensure!(
            !state.poisoned
                && state.applied[self.component.index()] == Applied::Updating(self.serial),
            "stale locality apply completion"
        );
        state.applied[self.component.index()] = Applied::Current {
            epoch,
            revision: revision.get(),
        };
        // No kernel writes here. In particular, another component's active or
        // failed update cannot be overridden by this success callback.
        Ok(())
    }
}

impl<R: FenceRuntime> Drop for Update<R> {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock()
            && state.applied[self.component.index()] == Applied::Updating(self.serial)
        {
            // Cancellation/panic/early error leaves the component failed. Its
            // fence was withdrawn before any mutation; Drop need not do I/O.
            state.applied[self.component.index()] = Applied::Failed;
        }
    }
}

/// Owns the actual runtime maps and one publication lock. Clone only this
/// handle, never replace the coordinator to clear failed/in-flight state.
#[derive(Clone)]
pub struct LocalityAdmission {
    state: Arc<Mutex<State<LocalityRuntimeMaps>>>,
}

/// Non-cloneable update token. Hold across apply, durable persistence and any
/// rollback. Dropping without successful completion leaves admission withdrawn.
pub struct LocalityApplyGuard(Update<LocalityRuntimeMaps>);

impl LocalityApplyGuard {
    /// Record the actual successfully applied AND durable coordinates. A
    /// recovered component needs fresh validation, not a previous cached value.
    /// This never publishes or rearms a bank.
    ///
    /// # Errors
    /// Rejects zero coordinates, poisoned runtime or a stale update token.
    pub fn complete(self, epoch: u64, revision: Revision) -> Result<()> {
        self.0.complete(epoch, revision)
    }
}

impl LocalityAdmission {
    /// Observe actual dispatch/fence identity after confirming settled inputs.
    /// A writer can withdraw then reapply identical coordinates; cached context
    /// equality alone does not prove this bank is still selected.
    ///
    /// # Errors
    /// Reports a fatal fence, foreign bank or failed kernel readback. This does
    /// not validate a journal cut or claim packet delivery; caller does those.
    pub fn is_published(
        &self,
        bank: &KernelLocalityBank,
        context: &EncryptionLocalityContext,
    ) -> Result<bool> {
        let state = lock(&self.state)?;
        state.health()?;
        if state.check(context).is_err() {
            return Ok(false);
        }
        bank.is_selected(&state.runtime, context)
    }

    /// Read-only fatal health check for runtime supervision. Unknown, failed or
    /// pending inputs with a successfully withdrawn fence are not fatal.
    ///
    /// # Errors
    /// Reports poisoned synchronization or an uncertain kernel fence.
    pub fn health(&self) -> Result<()> {
        lock(&self.state)?.health()
    }

    /// O(1) observation of this coordinator's completed writer, not a fresh
    /// kernel observation and never packet permission. An unchanged writer may
    /// avoid withdrawal; false requires guarded readback/apply before completion.
    ///
    /// # Errors
    /// Reports poisoned synchronization or an uncertain kernel fence.
    pub fn is_applied(
        &self,
        component: LocalityApplyComponent,
        epoch: u64,
        revision: Revision,
    ) -> Result<bool> {
        lock(&self.state)?.is_applied(component, epoch, revision)
    }

    /// Bind the real loader while retaining exclusive startup ownership.
    ///
    /// # Errors
    /// Reports missing owned pins or poisoned synchronization.
    pub fn configure_loader(&self, loader: &mut aya::EbpfLoader<'_>) -> Result<()> {
        lock(&self.state)?.runtime.configure_loader(loader)
    }

    /// Check the newly loaded runtime's actual shared map identities before
    /// any TC attachment. Names or compatible shapes alone are insufficient.
    ///
    /// # Errors
    /// Reports missing/substituted maps or poisoned synchronization.
    pub fn verify_loaded(&self, object: &aya::Ebpf) -> Result<()> {
        lock(&self.state)?.runtime.verify_loaded(object)
    }

    /// Take exclusive map ownership and withdraw before any CNI-serving startup
    /// or input mutation. Both components start unknown, including on restart.
    ///
    /// # Errors
    /// Failure to withdraw is fatal to this runtime's admission.
    pub fn new(runtime: LocalityRuntimeMaps) -> Result<Self> {
        Ok(Self {
            state: Arc::new(Mutex::new(State::new(runtime)?)),
        })
    }

    /// Withdraw synchronously BEFORE the caller changes this input. Distinct
    /// component writers may then execute concurrently outside the lock.
    ///
    /// # Errors
    /// Rejects overlapping same-component writers, exhausted serials or a
    /// failed fence. Do not perform the input mutation when this returns error.
    pub fn begin(&self, component: LocalityApplyComponent) -> Result<LocalityApplyGuard> {
        Ok(LocalityApplyGuard(Update::begin(&self.state, component)?))
    }

    /// Explicit retirement; never restores inputs or arms a previous bank.
    ///
    /// # Errors
    /// Reports poisoned synchronization or kernel withdrawal failure.
    pub fn withdraw(&self) -> Result<()> {
        lock(&self.state)?.withdraw()
    }

    /// Submit preparation on the caller's existing bounded worker. No slow
    /// observation/seeding runs under this short publication lock.
    ///
    /// # Errors
    /// Rejects unsettled coordinates and propagates bounded-worker errors.
    pub fn try_prepare(
        &self,
        worker: &LocalityObservationWorker,
        leased: LeasedLocalityBank,
        elf: Vec<u8>,
        pin_root: PathBuf,
    ) -> Result<Option<LocalityPreparationTask>> {
        let state = lock(&self.state)?;
        state.check(leased.observed().context())?;
        worker.try_prepare(leased, &state.runtime, elf, pin_root)
    }

    /// Publish and arm under one lock only after BOTH applied writers settle.
    /// Caller must ALSO hold the actual CNI journal transaction lock and supply
    /// freshly authenticated full context. Never infer that context from the
    /// prepared bank. No lock is held across an await.
    ///
    /// # Errors
    /// Rejects failed/in-flight/stale inputs, original journal-cut or runtime
    /// mismatch, and uncertain kernel writes. Publication failure invalidates
    /// both component observations; withdrawal failure poisons the runtime.
    pub fn publish(
        &self,
        bank: &KernelLocalityBank,
        journal: &AttachmentJournal,
        gate: &IncarnationGate,
        current: &EncryptionLocalityContext,
    ) -> Result<u32> {
        lock(&self.state)?.admit(current, |runtime| {
            bank.publish(runtime, journal, gate, current)
        })
    }
}

#[cfg(test)]
mod tests;
