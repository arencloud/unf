//! Real CNI-journal/placement candidate joining. No packet or kernel authority.
use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{Context, Result, ensure};
use tokio::sync::Mutex;
use unf_cni_state::{AttachmentJournal, AttachmentJournalCut, AttachmentPhase, AttachmentRecord};
use unf_common::IdentityId;
use unf_encryption::{
    EncryptionLocalityContext, EncryptionLocalityDigest, VerifiedEncryptionLocality,
};

// Logical retained payload budget, not an allocator/RSS or throughput claim.
const MAX_RETAINED_BYTES: usize = 16 * 1024 * 1024;
type SelectedAttachment = (AttachmentRecord, [Option<IdentityId>; 2]);

pub(super) struct CniAttachmentInventory {
    pub(super) journal: Arc<Mutex<AttachmentJournal>>,
}

pub(super) struct InventorySelection {
    pub(super) cut: AttachmentJournalCut,
    pub(super) context: EncryptionLocalityContext,
    pub(super) locality_digest: EncryptionLocalityDigest,
    pub(super) records: Vec<SelectedAttachment>,
    addresses: usize,
    retained_bytes: usize,
}

impl InventorySelection {
    pub(super) fn counts(&self) -> (usize, usize, usize) {
        (self.records.len(), self.addresses, self.retained_bytes)
    }
}

impl CniAttachmentInventory {
    pub(super) fn new(journal: Arc<Mutex<AttachmentJournal>>) -> Self {
        Self { journal }
    }

    /// Only metadata work occurs under the CNI transaction lock. Kernel
    /// observation/publication must recheck this cut under the same lock later.
    /// This method deliberately does neither and cannot grant packet authority.
    pub(super) async fn refresh(
        &self,
        slot: &mut Option<InventorySelection>,
        evidence: &VerifiedEncryptionLocality,
        expected: &EncryptionLocalityContext,
    ) -> Result<()> {
        // Cancellation or failure cannot leave a previous selected inventory
        // looking current. An unchanged, checked cut is restored without clones.
        let previous = slot.take();
        ensure!(
            evidence.certificate().context() == expected,
            "foreign inventory placement cut"
        );
        let journal = self.journal.lock().await;
        let digest = evidence.certificate().certificate_digest();
        if let Some(previous) = previous
            && previous.context == *expected
            && previous.locality_digest == digest
            && journal.is_current(&previous.cut)
        {
            *slot = Some(previous);
            return Ok(());
        }
        let cut = journal
            .cut()
            .context("CNI journal durability is uncertain")?;
        let mut records = Vec::new();
        let mut addresses = 0;
        let mut retained_bytes = 0;
        for record in journal.iter() {
            let Some(identities) = matching_owners(record, evidence)? else {
                continue;
            };
            let cost = retained_cost(record)?;
            retained_bytes = charge_payload(retained_bytes, cost)?;
            addresses += identities.iter().flatten().count();
            records.push((record.clone(), identities));
        }
        *slot = Some(InventorySelection {
            cut,
            context: expected.clone(),
            locality_digest: digest,
            records,
            addresses,
            retained_bytes,
        });
        Ok(())
    }
}

fn matching_owners(
    record: &AttachmentRecord,
    evidence: &VerifiedEncryptionLocality,
) -> Result<Option<[Option<IdentityId>; 2]>> {
    if record.phase != AttachmentPhase::Ready
        || record.creation_token.is_none_or(|token| token == [0; 32])
    {
        return Ok(None);
    }
    let Some(uid) = record.spec.workload_uid.as_deref() else {
        return Ok(None);
    };
    let facts = evidence.certificate().addresses();
    let mut identities = [None, None];
    for (index, address) in [
        IpAddr::V4(record.lease.ipv4.address),
        IpAddr::V6(record.lease.ipv6.address),
    ]
    .into_iter()
    .enumerate()
    {
        if let Ok(found) = facts.binary_search_by_key(&address, |fact| fact.address) {
            let fact = &facts[found];
            ensure!(
                fact.workload_uid == uid,
                "CNI workload UID differs from exact-address placement"
            );
            identities[index] = Some(fact.identity);
        }
    }
    Ok(identities.iter().any(Option::is_some).then_some(identities))
}

fn retained_cost(record: &AttachmentRecord) -> Result<usize> {
    // Charge object storage and its owned strings before cloning. Vec spare
    // capacity and allocator metadata are not included in this logical budget.
    [
        record.spec.key.network.len(),
        record.spec.key.container_id.len(),
        record.spec.key.ifname.len(),
        record.spec.netns.len(),
        record.host_interface.len(),
        record.spec.workload_uid.as_deref().map_or(0, str::len),
    ]
    .into_iter()
    .try_fold(std::mem::size_of::<SelectedAttachment>(), |cost, length| {
        cost.checked_add(length)
            .context("CNI inventory payload size overflow")
    })
}

fn charge_payload(retained: usize, additional: usize) -> Result<usize> {
    let total = retained
        .checked_add(additional)
        .context("CNI inventory payload size overflow")?;
    ensure!(
        total <= MAX_RETAINED_BYTES,
        "selected CNI inventory exceeds payload budget"
    );
    Ok(total)
}

#[cfg(test)]
pub(super) mod tests;
