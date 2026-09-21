//! Real journal-to-kernel producer. Publication alone is not packet integration.
use anyhow::{Context as _, Result, ensure};
use unf_cni_state::{AttachmentJournal, AttachmentJournalCut};
use unf_encryption::{
    AdmittedNodeLocalPlan, EncryptionLocalityContext, EncryptionLocalityDigest,
    VerifiedEncryptionLocality,
};
use unf_locality::{
    KernelLocalityBank, LocalityAdmission, LocalityObservationTask, LocalityObservationWorker,
    LocalityPreparationTask,
};

use super::{AgentState, cni_inventory::InventorySelection, encryption_locality::applied_context};

#[derive(Default)]
pub(super) struct BankPublisher {
    // Never replace this worker when retiring a candidate: cancelled namespace
    // work retains its one slot until the actual joined worker drains.
    worker: LocalityObservationWorker,
    pending: Option<(OriginalCut, Preparation)>,
    active: Option<(OriginalCut, KernelLocalityBank)>,
    admission: Option<LocalityAdmission>,
}

struct OriginalCut {
    journal: AttachmentJournalCut,
    context: EncryptionLocalityContext,
    digest: EncryptionLocalityDigest,
}

enum Preparation {
    Observing(LocalityObservationTask),
    Sealing(LocalityPreparationTask),
}

impl Preparation {
    fn is_finished(&self) -> bool {
        match self {
            Self::Observing(task) => task.is_finished(),
            Self::Sealing(task) => task.is_finished(),
        }
    }
}

impl OriginalCut {
    fn current(
        &self,
        journal: &AttachmentJournal,
        selection: &InventorySelection,
        fresh: &EncryptionLocalityContext,
    ) -> bool {
        self.context == *fresh
            && selection.context == *fresh
            && self.digest == selection.locality_digest
            && journal.is_current(&self.journal)
            && journal.is_current(&selection.cut)
    }
}

impl BankPublisher {
    #[cfg(test)]
    pub(super) fn selected_for_test(&self, context: &EncryptionLocalityContext) -> Result<bool> {
        match (&self.active, &self.admission) {
            (Some((_, bank)), Some(admission)) => admission.is_published(bank, context),
            _ => Ok(false),
        }
    }

    pub(super) fn clear(&mut self) -> Result<()> {
        // Retain active ownership if withdrawal fails; the runtime health
        // supervisor treats that uncertain kernel fence as fatal.
        if self.active.is_some() {
            self.admission
                .as_ref()
                .context("active bank has no admission owner")?
                .withdraw()?;
        }
        self.active = None;
        self.pending = None;
        Ok(())
    }

    /// Poll only completed jobs. The original journal cut travels through every
    /// stage and is checked under the real CNI transaction lock at publication.
    #[allow(clippy::too_many_lines)] // Keep journal-lock/fresh-context handoffs in one auditable order.
    pub(super) async fn synchronize(
        &mut self,
        state: &AgentState,
        plan: &AdmittedNodeLocalPlan,
        evidence: &VerifiedEncryptionLocality,
        selection: &InventorySelection,
    ) -> Result<()> {
        let Some(runtime) = state.locality_runtime.get() else {
            self.clear()?;
            return Ok(());
        };
        let resources = runtime.resources()?;
        let inventory = state
            .cni_inventory
            .get()
            .context("bank publisher has no real CNI inventory")?;
        self.admission
            .get_or_insert_with(|| runtime.admission.clone());
        let fresh = || {
            applied_context(plan, &selection.context.cluster_id, state)
                .context("applied placement cut changed during bank production")
        };
        {
            let journal = inventory.journal.lock().await;
            let context = fresh()?;
            ensure!(
                selection.context == context
                    && journal.is_current(&selection.cut)
                    && evidence.certificate().context() == &context
                    && evidence.certificate().certificate_digest() == selection.locality_digest,
                "bank selection no longer matches actual journal/placement"
            );
            if let Some((cut, bank)) = &self.active {
                if cut.current(&journal, selection, &context)
                    && runtime.admission.is_published(bank, &context)?
                {
                    return Ok(());
                }
                self.clear()?;
            }
            if self
                .pending
                .as_ref()
                .is_some_and(|(cut, _)| !cut.current(&journal, selection, &context))
            {
                self.clear()?;
            }
        }
        if selection.records.is_empty() {
            self.clear()?;
            return Ok(());
        }
        if let Some((_, task)) = &self.pending
            && !task.is_finished()
        {
            return Ok(());
        }
        if let Some((cut, task)) = self.pending.take() {
            match task {
                Preparation::Observing(task) => {
                    let observed = task.finish().await?;
                    let leased = {
                        let journal = inventory.journal.lock().await;
                        let context = fresh()?;
                        ensure!(
                            cut.current(&journal, selection, &context),
                            "journal changed before locality binding"
                        );
                        observed.bind(&journal, &cut.journal, runtime.gate()?, &context)?
                    };
                    if let Some(task) = runtime.admission.try_prepare(
                        &self.worker,
                        leased,
                        resources.elf.clone(),
                        resources.pin_root.clone(),
                    )? {
                        self.pending = Some((cut, Preparation::Sealing(task)));
                    }
                }
                Preparation::Sealing(task) => {
                    let bank = task.finish().await?;
                    let journal = inventory.journal.lock().await;
                    let context = fresh()?;
                    ensure!(
                        cut.current(&journal, selection, &context),
                        "journal changed before locality publication"
                    );
                    let id =
                        runtime
                            .admission
                            .publish(&bank, &journal, runtime.gate()?, &context)?;
                    // No fallible operation or await between publication and
                    // retaining the owner that will synchronously withdraw it.
                    self.active = Some((cut, bank));
                    tracing::info!(
                        program_id = id,
                        endpoints = selection.records.len(),
                        "published sealed locality bank; packet integration and delivery remain separate"
                    );
                }
            }
            return Ok(());
        }
        let journal = inventory.journal.lock().await;
        let context = fresh()?;
        ensure!(
            journal.is_current(&selection.cut) && context == selection.context,
            "journal changed before locality observation"
        );
        let cut = OriginalCut {
            journal: selection.cut.clone(),
            context: context.clone(),
            digest: selection.locality_digest,
        };
        let records = selection
            .records
            .iter()
            .map(|(record, _)| record.clone())
            .collect();
        // Submission validates bounded input; namespace work runs outside this
        // transaction lock on the retained single-slot worker.
        if let Some(task) = self
            .worker
            .try_observe_journal(records, evidence.clone(), context)?
        {
            self.pending = Some((cut, Preparation::Observing(task)));
        }
        Ok(())
    }
}

impl Drop for BankPublisher {
    fn drop(&mut self) {
        if let Err(error) = self.clear() {
            tracing::error!(%error, "locality publisher teardown could not withdraw kernel selection");
        }
    }
}

#[cfg(test)]
mod tests;
