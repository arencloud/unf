//! Fresh, endpoint-linear kernel banks. A successful preparation is not packet
//! delivery and cannot be restored from serialized metadata or old pins.

pub(crate) mod build;
mod pins;
pub(crate) mod runtime;
mod sys;

use std::sync::Arc;

use anyhow::{Context as _, Result, ensure};
use aya::{Ebpf, programs::SchedClassifier};
use unf_cni_state::AttachmentJournal;
use unf_encryption::EncryptionLocalityContext;

use crate::{IncarnationGate, LeasedLocalityBank};
pub use runtime::LocalityRuntimeMaps;

/// Owns a freshly sealed bank and the original journal cut. No pointer values,
/// seed handles, mutable map descriptors or restore constructor are exposed.
pub struct KernelLocalityBank {
    object: Ebpf,
    leased: LeasedLocalityBank,
    runtime: Arc<runtime::RuntimeMaps>,
}

impl KernelLocalityBank {
    /// Kernel program identity, not application-delivery evidence.
    ///
    /// # Errors
    /// Reports a missing classifier or unavailable kernel metadata.
    pub fn program_id(&self) -> Result<u32> {
        Ok(self.classifier()?.info()?.id())
    }

    #[must_use]
    pub fn endpoint_count(&self) -> usize {
        self.leased.leases().len()
    }

    /// Atomically replace the one locality dispatch entry. The caller MUST hold
    /// its real journal transaction lock and applied-state publication lock
    /// through this call, supplying freshly read applied context. Startup must
    /// fence previous dispatch before allowing any CNI transaction.
    ///
    /// Only the exact runtime used for preparation may publish this bank. The
    /// placement fence is separately controlled by the runtime; publication
    /// never rearms it. An uncertain write withdraws both fence and dispatch.
    ///
    /// # Errors
    /// Rejects stale/foreign state or kernel failure. Both withdrawal operations
    /// are attempted after uncertain publication; any failure is surfaced and
    /// requires the caller to stop admission rather than restoring old state.
    pub fn publish(
        &self,
        runtime: &mut LocalityRuntimeMaps,
        journal: &AttachmentJournal,
        gate: &IncarnationGate,
        current: &EncryptionLocalityContext,
    ) -> Result<u32> {
        ensure!(
            Arc::ptr_eq(&self.runtime, &runtime.maps),
            "foreign locality runtime"
        );
        self.leased.validate_current(journal, gate, current)?;
        runtime.publish(self.classifier()?)
    }

    fn classifier(&self) -> Result<&SchedClassifier> {
        self.object
            .program("unf_locality_bank")
            .context("missing locality consumer")?
            .try_into()
            .map_err(Into::into)
    }
}
