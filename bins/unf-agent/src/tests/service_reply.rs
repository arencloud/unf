//! Actual main-program reverse-Service provenance, not socket delivery proof.
use super::*;

fn native_transport(maps: &mut encryption_maps::EncryptionMaps, revision: u64) {
    use unf_ebpf_common::*;
    let config = EncryptionMapConfig {
        generation: 1,
        policy_revision: revision,
        service_revision: 1,
        egress_revision: 1,
        decision_count: 2,
        transport_count: 0,
        schema_version: ENCRYPTION_MAP_ABI_VERSION,
        active_bank: 0,
        epoch_count: 0,
        path_count: 0,
    };
    for (source, destination) in [(11, 22), (22, 11)] {
        let key = EncryptionDecisionKey {
            source_identity: IdentityId::new(source),
            destination_identity: IdentityId::new(destination),
            bank: 0,
            reserved: [0; 3],
        };
        let value = EncryptionDecisionValue {
            transport_id: 0,
            contract_revision: 0,
            policy_revision: revision,
            service_revision: 1,
            egress_revision: 1,
            key_epoch: 0,
            decision_witness: [5; 16],
            schema_version: ENCRYPTION_MAP_ABI_VERSION,
            disposition: ENCRYPTION_DISPOSITION_NATIVE,
            flags: ENCRYPTION_DECISION_FLAG_POLICY_AUTHORIZED
                | ENCRYPTION_DECISION_FLAG_SELECTION_BOUND,
        };
        maps.decisions
            .insert(
                encryption_maps::encode_decision_key(&key),
                encryption_maps::encode_decision_value(&value),
                0,
            )
            .unwrap();
    }
    maps.config
        .set(0, encryption_maps::encode_map_config(&config), 0)
        .unwrap();
}

fn deny(source: u32, destination: u32, protocol: u8, port: u16) -> PolicyMapEntry {
    PolicyMapEntry {
        key: unf_state::PolicyMapKey {
            source_identity: IdentityId::new(source),
            destination_identity: IdentityId::new(destination),
            protocol,
            destination_port: port,
        },
        decision: PolicyDecisionRecord {
            verdict: Verdict::Deny,
            reason: PolicyReason::ExplicitRule,
            policy_id: Some(PolicyId::new(1)),
            rule_id: Some(RuleId::new(1)),
        },
        shadow: None,
    }
}

#[test]
#[ignore = "requires actual main BPF execution and UNF_EBPF_OBJECT"]
fn privileged_reverse_service_requires_live_forward_policy_witness() {
    for ipv6 in [false, true] {
        for protocol in [6, 17] {
            verify(ipv6, protocol);
        }
    }
}

#[allow(clippy::too_many_lines)] // Keep exact packet/policy/translation stage ordering visible.
fn verify(ipv6: bool, protocol: u8) {
    let object = std::env::var_os("UNF_EBPF_OBJECT").unwrap();
    let mut ebpf = EbpfLoader::new().load_file(object).unwrap();
    load_dataplane_tail_programs(&mut ebpf).unwrap();
    let program: &mut SchedClassifier = ebpf
        .program_mut("unf_observe_ingress")
        .unwrap()
        .try_into()
        .unwrap();
    program.load().unwrap();
    let directory = tempdir().unwrap();
    let mut services = test_service_synchronizer(&mut ebpf, directory.path().join("service.json"));
    let state = test_agent_state();
    let client4 = Ipv4Addr::new(10, 42, 0, 5);
    let backend4 = Ipv4Addr::new(10, 42, 0, 20);
    let vip4 = Ipv4Addr::new(10, 96, 0, 10);
    let client6: Ipv6Addr = "fd00:42::5".parse().unwrap();
    let backend6: Ipv6Addr = "fd00:42::20".parse().unwrap();
    let vip6: Ipv6Addr = "fd00:96::10".parse().unwrap();
    activate_service_snapshot(
        &mut services,
        &dual_stack_service_snapshot(1, backend4, backend6, true),
        None,
        false,
        &state,
    )
    .unwrap();
    let (mut ids4, mut ids6, mut identity_config) = take_identity_maps(&mut ebpf).unwrap();
    for (address, id) in [(client4, 11), (backend4, 22)] {
        ids4[0]
            .insert(
                address.octets(),
                encode_identity_value(IdentityMapValue::new(IdentityId::new(id), 3)),
                0,
            )
            .unwrap();
    }
    for (address, id) in [(client6, 11), (backend6, 22)] {
        ids6[0]
            .insert(
                address.octets(),
                encode_identity_value(IdentityMapValue::new(IdentityId::new(id), 3)),
                0,
            )
            .unwrap();
    }
    identity_config
        .set(0, encode_identity_config(7, 3, 4, 0).unwrap(), 0)
        .unwrap();
    let (mut policies, _, _, _, _, mut policy_config) = take_policy_maps(&mut ebpf).unwrap();
    policy_config
        .set(0, encode_policy_config(7, 1, 0, 0).unwrap(), 0)
        .unwrap();
    let mut encryption = take_encryption_maps(&mut ebpf).unwrap();
    native_transport(&mut encryption, 1);
    let mut connections =
        AyaHashMap::<_, [u8; 40], [u8; 16]>::try_from(ebpf.take_map("CONNECTIONS").unwrap())
            .unwrap();
    let input =
        AyaPerCpuArray::<_, [u8; 80]>::try_from(ebpf.take_map("UL_INPUT_V1").unwrap()).unwrap();
    let mut fence =
        AyaArray::<_, [u8; 32]>::try_from(ebpf.take_map("UL_FENCE_V1").unwrap()).unwrap();
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(&7_u64.to_ne_bytes());
    bytes[8..16].copy_from_slice(&3_u64.to_ne_bytes());
    bytes[16..24].copy_from_slice(&9_u64.to_ne_bytes());
    bytes[24..26].copy_from_slice(&unf_ebpf_common::locality::ABI_VERSION.to_ne_bytes());
    fence.set(0, bytes, 0).unwrap();
    let (frontend_port, backend_port) = if protocol == 6 {
        (80, 8080)
    } else {
        (53, 5353)
    };
    let packet = |reply: bool, client_port: u16| {
        if ipv6 {
            if reply {
                ipv6_packet(protocol, backend6, client6, backend_port, client_port)
            } else {
                ipv6_packet(protocol, client6, vip6, client_port, frontend_port)
            }
        } else if reply {
            ipv4_packet(protocol, backend4, client4, backend_port, client_port)
        } else {
            ipv4_packet(protocol, client4, vip4, client_port, frontend_port)
        }
    };
    let request = packet(false, 40_000);
    let reply = packet(true, 40_000);
    assert_eq!(run_tc(&mut ebpf, "unf_observe_ingress", &request).0, 3);
    let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &reply);
    assert_eq!(action, 3);
    if ipv6 {
        assert_ipv6_packet(&translated, protocol, vip6, client6, frontend_port, 40_000);
    } else {
        assert_ipv4_packet(&translated, protocol, vip4, client4, frontend_port, 40_000);
    }
    let backend = if ipv6 {
        backend6.octets()
    } else {
        let mut address = [0; 16];
        address[..4].copy_from_slice(&backend4.octets());
        address
    };
    assert!(
        input
            .get(&0, 0)
            .unwrap()
            .iter()
            .any(|row| row[24..40] == backend
                && row[56..60] == 22_u32.to_ne_bytes()
                && row[72..74] == frontend_port.to_be_bytes()
                && row[74..76] == 40_000_u16.to_be_bytes()),
        "reply lost backend ownership or actual wire ports"
    );
    for key in connections.keys().collect::<Result<Vec<_>, _>>().unwrap() {
        connections.remove(&key).unwrap();
    }
    assert_eq!(
        run_tc(&mut ebpf, "unf_observe_ingress", &reply).0,
        2,
        "Service state alone is not reply permission"
    );
    assert_eq!(run_tc(&mut ebpf, "unf_observe_ingress", &request).0, 3);
    let reverse_deny = deny(22, 11, protocol, 40_000);
    policies
        .insert(
            encode_policy_key(&reverse_deny, 0),
            encode_policy_value(&reverse_deny, 2),
            0,
        )
        .unwrap();
    policy_config
        .set(0, encode_policy_config(7, 2, 1, 0).unwrap(), 0)
        .unwrap();
    native_transport(&mut encryption, 2);
    assert_eq!(
        run_tc(&mut ebpf, "unf_observe_ingress", &reply).0,
        3,
        "ADR 0070 established reply was lost across policy revision churn"
    );
    let idle = unf_ebpf_common::connection_timeout_ns(protocol).unwrap();
    let expired_at = monotonic_time_ns()
        .unwrap()
        .checked_sub(idle + 1_000_000_000)
        .expect("fixture requires kernel uptime longer than the protocol timeout");
    for key in connections.keys().collect::<Result<Vec<_>, _>>().unwrap() {
        let mut value = connections.get(&key, 0).unwrap();
        value[..8].copy_from_slice(&expired_at.to_ne_bytes());
        connections.insert(key, value, 0).unwrap();
    }
    assert_eq!(
        run_tc(&mut ebpf, "unf_observe_ingress", &reply).0,
        2,
        "expired policy witness retained Service reply authority"
    );
    assert_eq!(run_tc(&mut ebpf, "unf_observe_ingress", &request).0, 3);
    assert_eq!(
        run_tc(&mut ebpf, "unf_observe_ingress", &reply).0,
        3,
        "current allowed request lost stateful return"
    );
    // A current policy witness is not transport permission. With the bank
    // absent, removing the exact reverse decision must not restore the old
    // reverse-Service early PIPE bypass.
    let reverse_key = unf_ebpf_common::EncryptionDecisionKey {
        source_identity: IdentityId::new(22),
        destination_identity: IdentityId::new(11),
        bank: 0,
        reserved: [0; 3],
    };
    encryption
        .decisions
        .remove(&encryption_maps::encode_decision_key(&reverse_key))
        .unwrap();
    assert_eq!(
        run_tc(&mut ebpf, "unf_observe_ingress", &reply).0,
        2,
        "policy-tracked Service reply bypassed missing transport authority"
    );
    native_transport(&mut encryption, 2);
    assert_eq!(run_tc(&mut ebpf, "unf_observe_ingress", &reply).0, 3);
    policy_config.set(0, [0; 24], 0).unwrap();
    assert_eq!(
        run_tc(&mut ebpf, "unf_observe_ingress", &reply).0,
        2,
        "Service reply bypassed absent active policy configuration"
    );
    policy_config
        .set(0, encode_policy_config(7, 2, 1, 0).unwrap(), 0)
        .unwrap();
    assert_eq!(run_tc(&mut ebpf, "unf_observe_ingress", &request).0, 3);
    let forward_deny = deny(11, 22, protocol, backend_port);
    policies
        .insert(
            encode_policy_key(&forward_deny, 0),
            encode_policy_value(&forward_deny, 2),
            0,
        )
        .unwrap();
    policy_config
        .set(0, encode_policy_config(7, 2, 2, 0).unwrap(), 0)
        .unwrap();
    assert_eq!(
        run_tc(&mut ebpf, "unf_observe_ingress", &packet(false, 40_001)).0,
        2
    );
    assert_eq!(
        run_tc(&mut ebpf, "unf_observe_ingress", &packet(true, 40_001)).0,
        2,
        "denied forward created unsolicited reply authority"
    );
    println!(
        "service-reply-policy: family={} protocol={protocol} current-reply=true revision-churn-preserved=true missing-witness-denied=true expired-witness-denied=true absent-policy-denied=true missing-transport-denied=true denied-forward-reply-denied=true backend-preserved=true",
        if ipv6 { 6 } else { 4 }
    );
}
