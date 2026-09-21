use super::*;
use crate::cni_inventory::tests::{placement, ready_inventory};
use unf_cni_state::{CNI_TRANSACTION_SCHEMA_VERSION, TransactionOperation, TransactionRequest};

#[tokio::test]
async fn original_cut_rejects_journal_aba_foreign_instance_and_full_context_drift() {
    let (_directory, inventory) = ready_inventory("pod-a").await;
    let (evidence, context) = placement("pod-a", 17, true);
    let mut selection = None;
    inventory
        .refresh(&mut selection, &evidence, &context)
        .await
        .unwrap();
    let selected = selection.as_ref().unwrap();
    let original = OriginalCut {
        journal: selected.cut.clone(),
        context: context.clone(),
        digest: selected.locality_digest,
    };
    {
        let journal = inventory.journal.lock().await;
        assert!(original.current(&journal, selected, &context));
        for change in 0..7 {
            let mut foreign = context.clone();
            match change {
                0 => foreign.cluster_id.push('x'),
                1 => foreign.recipient.node_name.push('x'),
                2 => foreign.recipient.node_uid.push('x'),
                3 => foreign.membership_revision = unf_common::Revision::new(123),
                4 => foreign.identity_epoch += 1,
                5 => foreign.identity_revision = unf_common::Revision::new(123),
                _ => foreign.routing_revision = unf_common::Revision::new(123),
            }
            assert!(!original.current(&journal, selected, &foreign));
        }
    }
    let (_foreign_directory, foreign) = ready_inventory("pod-a").await;
    assert!(!original.current(&*foreign.journal.lock().await, selected, &context));
    let (changed, _) = placement("pod-a", 18, true);
    inventory
        .refresh(&mut selection, &changed, &context)
        .await
        .unwrap();
    assert!(!original.current(
        &*inventory.journal.lock().await,
        selection.as_ref().unwrap(),
        &context
    ));
    let mut journal = inventory.journal.lock().await;
    let record = journal.records()[0].clone();
    for operation in [
        TransactionOperation::BeginDelete {
            key: record.spec.key.clone(),
        },
        TransactionOperation::CompleteDelete {
            key: record.spec.key.clone(),
        },
        TransactionOperation::Prepare {
            attachment: record.spec.clone(),
        },
        TransactionOperation::Commit {
            key: record.spec.key,
        },
    ] {
        journal
            .apply(TransactionRequest::new(
                CNI_TRANSACTION_SCHEMA_VERSION,
                operation,
            ))
            .unwrap();
    }
    drop(journal);
    inventory
        .refresh(&mut selection, &evidence, &context)
        .await
        .unwrap();
    // Exact same placement and addresses, but never replace the original cut
    // with this newer journal snapshot to salvage an in-flight preparation.
    assert!(!original.current(
        &*inventory.journal.lock().await,
        selection.as_ref().unwrap(),
        &context
    ));
}

#[test]
fn clearing_empty_publisher_needs_no_runtime_or_kernel_writes() {
    let mut publisher = BankPublisher::default();
    publisher.clear().unwrap();
    publisher.clear().unwrap();
    assert!(
        publisher.pending.is_none() && publisher.active.is_none() && publisher.admission.is_none()
    );
}
