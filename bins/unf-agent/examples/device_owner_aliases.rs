//! Bounded fixture adapter for the real CNI alias derivation; no kernel writes.
use std::io::{self, Read};

use anyhow::{Result, ensure};
use unf_cni_state::{AttachmentPhase, AttachmentRecord, MAX_TRANSACTION_MESSAGE_BYTES};
use unf_link::VethPlan;

fn aliases(bytes: &[u8]) -> Result<[String; 2]> {
    ensure!(
        bytes.len() <= MAX_TRANSACTION_MESSAGE_BYTES,
        "oversized attachment"
    );
    let record: AttachmentRecord = serde_json::from_slice(bytes)?;
    ensure!(
        record.phase == AttachmentPhase::Ready
            && record.spec.workload_uid.is_some()
            && record.creation_token.is_some(),
        "ready UID/nonce-bound fixture attachment required"
    );
    let plan = VethPlan::from_attachment(&record)?;
    let (host, peer) = plan.ownership_aliases();
    ensure!(
        host.len() <= 96 && peer.len() <= 96,
        "unsupported alias width"
    );
    Ok([host.to_owned(), peer.to_owned()])
}

fn main() -> Result<()> {
    ensure!(
        std::env::var("UNF_DEVICE_OBSERVATION_ISOLATED_CONTAINER").as_deref() == Ok("yes"),
        "isolated fixture opt-in required"
    );
    let mut bytes = Vec::new();
    io::stdin()
        .take((MAX_TRANSACTION_MESSAGE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    serde_json::to_writer(io::stdout(), &aliases(&bytes)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn record() -> Value {
        json!({"spec":{"key":{"network":"fixture","containerId":"sandbox","ifname":"eth0"},
            "netns":"/run/netns/fixture","mtu":1500,"workloadUid":"fixture-pod"},
            "hostInterface":"unf012345678901","phase":"ready","creationToken":vec![1_u8;32],
            "lease":{"ipv4":{"address":"10.244.45.2","gateway":"10.244.45.1","prefixLen":32},
                "ipv6":{"address":"fd45::2","gateway":"fd45::1","prefixLen":128}}})
    }

    #[test]
    fn derives_complete_maximum_width_aliases_and_binds_all_owner_fields() {
        let original = record();
        let expected = aliases(&serde_json::to_vec(&original).unwrap()).unwrap();
        assert!(expected.iter().all(|value| value.len() == 96));
        assert_ne!(expected[0], expected[1]);
        for pointer in [
            "/spec/workloadUid",
            "/spec/key/network",
            "/spec/key/containerId",
            "/spec/key/ifname",
            "/creationToken/31",
        ] {
            let mut changed = original.clone();
            *changed.pointer_mut(pointer).unwrap() = if pointer == "/creationToken/31" {
                json!(2)
            } else {
                json!("different")
            };
            assert_ne!(
                aliases(&serde_json::to_vec(&changed).unwrap()).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn rejects_unbound_unready_zero_nonce_and_oversized_inputs() {
        for (pointer, value) in [
            ("/spec/workloadUid", Value::Null),
            ("/creationToken", Value::Null),
            ("/phase", json!("preparing")),
            ("/creationToken", json!(vec![0_u8; 32])),
        ] {
            let mut changed = record();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(aliases(&serde_json::to_vec(&changed).unwrap()).is_err());
        }
        assert!(aliases(&vec![b' '; MAX_TRANSACTION_MESSAGE_BYTES + 1]).is_err());
    }
}
