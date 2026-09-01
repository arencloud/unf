use std::collections::BTreeMap;
use std::hint::black_box;
use std::mem::size_of;
use std::time::Instant;

use serde::Serialize;
use unf_common::{BackendId, ServiceId};
use unf_ebpf_common::{
    AddressFamily, SERVICE_CONNECTION_ROLE_FORWARD, ServiceBackendSlotKey, ServiceBackendSlotValue,
    ServiceConnectionKey, service_flow_hash,
};
use unf_service::build_maglev_table;

const FLOW_COUNT: usize = 200_000;
const LOOKUP_ITERATIONS: usize = 2_000_000;
const CARDINALITIES: [usize; 8] = [2, 8, 32, 128, 512, 1_024, 2_048, 4_096];

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MeasurementReport {
    schema_version: u16,
    fixture: Fixture,
    acceptance: Acceptance,
    results: Vec<ResultRow>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Fixture {
    flow_count: usize,
    lookup_iterations: usize,
    backend_cardinalities: [usize; 8],
    slot_bytes: usize,
    timing_note: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Acceptance {
    selected_min_slots_per_backend: usize,
    maximum_table_size: usize,
    maximum_table_balance_error_ppm: u64,
    packet_map_lookups_stable_hash: u8,
    packet_map_lookups_maglev: u8,
    capacity_fallback: &'static str,
    table_boundary_upgrade: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResultRow {
    backend_count: usize,
    table_size: usize,
    stable_hash_memory_bytes: usize,
    maglev_memory_bytes: usize,
    stable_hash_distribution_error_ppm: u64,
    maglev_distribution_error_ppm: u64,
    maglev_table_distribution_error_ppm: u64,
    stable_hash_add_remap_ppm: Option<u64>,
    maglev_add_remap_ppm: Option<u64>,
    stable_hash_remove_remap_ppm: u64,
    maglev_remove_remap_ppm: u64,
    stable_hash_compile_ns: u128,
    maglev_compile_ns: u128,
    stable_hash_update_map_writes: usize,
    maglev_update_map_writes: usize,
    stable_hash_lookup_ns: u128,
    maglev_lookup_ns: u128,
}

fn backends(count: usize) -> Vec<BackendId> {
    (1..=u32::try_from(count).expect("fixture cardinality fits u32"))
        .map(BackendId::new)
        .collect()
}

fn flow_hashes() -> Vec<u32> {
    (0..FLOW_COUNT)
        .map(|index| {
            let value = u64::try_from(index).expect("fixture index fits u64");
            let mut source = [0_u8; 16];
            source[0..8].copy_from_slice(&value.to_be_bytes());
            source[8..16].copy_from_slice(&value.rotate_left(29).to_be_bytes());
            let key = ServiceConnectionKey {
                source_address: source,
                destination_address: [0x42; 16],
                source_port: u16::try_from(1_024 + (index % 63_000))
                    .expect("fixture port fits u16")
                    .to_be_bytes(),
                destination_port: 443_u16.to_be_bytes(),
                protocol: if index % 2 == 0 { 6 } else { 17 },
                address_family: if index % 3 == 0 {
                    AddressFamily::Ipv4 as u8
                } else {
                    AddressFamily::Ipv6 as u8
                },
                role: SERVICE_CONNECTION_ROLE_FORWARD,
                reserved: 0,
            };
            service_flow_hash(&key, ServiceId::new(0x51_7e))
        })
        .collect()
}

fn stable_selection(hash: u32, backend_ids: &[BackendId]) -> BackendId {
    backend_ids[usize::try_from(hash).expect("u32 fits usize") % backend_ids.len()]
}

fn maglev_selection(hash: u32, table: &[BackendId]) -> BackendId {
    table[usize::try_from(hash).expect("u32 fits usize") % table.len()]
}

fn distribution_error_ppm(selected: impl Iterator<Item = BackendId>, count: usize) -> u64 {
    let mut distribution = BTreeMap::<BackendId, usize>::new();
    for backend in selected {
        *distribution.entry(backend).or_default() += 1;
    }
    maximum_distribution_error_ppm(&distribution, FLOW_COUNT, count)
}

fn maximum_distribution_error_ppm(
    distribution: &BTreeMap<BackendId, usize>,
    total: usize,
    count: usize,
) -> u64 {
    let total = u128::try_from(total).expect("fixture total fits u128");
    let count = u128::try_from(count).expect("fixture cardinality fits u128");
    let largest = distribution
        .values()
        .map(|actual| {
            let scaled = u128::try_from(*actual).expect("fixture count fits u128") * count;
            scaled.abs_diff(total) * 1_000_000 / total
        })
        .max()
        .unwrap_or(0);
    u64::try_from(largest).expect("parts per million fits u64")
}

fn table_distribution_error_ppm(table: &[BackendId], count: usize) -> u64 {
    let mut distribution = BTreeMap::<BackendId, usize>::new();
    for backend in table {
        *distribution.entry(*backend).or_default() += 1;
    }
    maximum_distribution_error_ppm(&distribution, table.len(), count)
}

fn remap_ppm(
    before: impl Iterator<Item = BackendId>,
    after: impl Iterator<Item = BackendId>,
) -> u64 {
    let remapped = before
        .zip(after)
        .filter(|(left, right)| left != right)
        .count();
    u64::try_from(remapped * 1_000_000 / FLOW_COUNT).expect("remap rate fits u64")
}

fn elapsed_ns(mut operation: impl FnMut()) -> u128 {
    let started = Instant::now();
    operation();
    started.elapsed().as_nanos()
}

fn measure(backend_count: usize, hashes: &[u32]) -> ResultRow {
    let backend_ids = backends(backend_count);
    let added = backends(backend_count + 1);
    let removed = backends(backend_count - 1);
    let compile_started = Instant::now();
    let table = build_maglev_table(ServiceId::new(0x51_7e), 7, &backend_ids).unwrap();
    let maglev_compile_ns = compile_started.elapsed().as_nanos();
    let added_table = build_maglev_table(ServiceId::new(0x51_7e), 7, &added);
    let removed_table = if removed.len() >= 2 {
        build_maglev_table(ServiceId::new(0x51_7e), 7, &removed).unwrap()
    } else {
        removed.clone()
    };
    let stable_compile_ns = elapsed_ns(|| {
        black_box(backend_ids.clone());
    });

    let stable_hash_distribution_error_ppm = distribution_error_ppm(
        hashes
            .iter()
            .map(|hash| stable_selection(*hash, &backend_ids)),
        backend_count,
    );
    let maglev_distribution_error_ppm = distribution_error_ppm(
        hashes.iter().map(|hash| maglev_selection(*hash, &table)),
        backend_count,
    );
    let maglev_table_distribution_error_ppm = table_distribution_error_ppm(&table, backend_count);
    let stable_hash_add_remap_ppm = added_table.as_ref().map(|_| {
        remap_ppm(
            hashes
                .iter()
                .map(|hash| stable_selection(*hash, &backend_ids)),
            hashes.iter().map(|hash| stable_selection(*hash, &added)),
        )
    });
    let maglev_add_remap_ppm = added_table.as_ref().map(|added_table| {
        remap_ppm(
            hashes.iter().map(|hash| maglev_selection(*hash, &table)),
            hashes
                .iter()
                .map(|hash| maglev_selection(*hash, added_table)),
        )
    });
    let stable_hash_remove_remap_ppm = remap_ppm(
        hashes
            .iter()
            .map(|hash| stable_selection(*hash, &backend_ids)),
        hashes.iter().map(|hash| stable_selection(*hash, &removed)),
    );
    let maglev_remove_remap_ppm = remap_ppm(
        hashes.iter().map(|hash| maglev_selection(*hash, &table)),
        hashes
            .iter()
            .map(|hash| maglev_selection(*hash, &removed_table)),
    );
    let stable_hash_lookup_ns = elapsed_ns(|| {
        for iteration in 0..LOOKUP_ITERATIONS {
            black_box(stable_selection(
                hashes[iteration % hashes.len()],
                &backend_ids,
            ));
        }
    });
    let maglev_lookup_ns = elapsed_ns(|| {
        for iteration in 0..LOOKUP_ITERATIONS {
            black_box(maglev_selection(hashes[iteration % hashes.len()], &table));
        }
    });
    let slot_bytes = size_of::<ServiceBackendSlotKey>() + size_of::<ServiceBackendSlotValue>();
    ResultRow {
        backend_count,
        table_size: table.len(),
        stable_hash_memory_bytes: backend_count * slot_bytes,
        maglev_memory_bytes: table.len() * slot_bytes,
        stable_hash_distribution_error_ppm,
        maglev_distribution_error_ppm,
        maglev_table_distribution_error_ppm,
        stable_hash_add_remap_ppm,
        maglev_add_remap_ppm,
        stable_hash_remove_remap_ppm,
        maglev_remove_remap_ppm,
        stable_hash_compile_ns: stable_compile_ns,
        maglev_compile_ns,
        stable_hash_update_map_writes: backend_count,
        maglev_update_map_writes: table.len(),
        stable_hash_lookup_ns,
        maglev_lookup_ns,
    }
}

fn main() {
    let hashes = flow_hashes();
    let report = MeasurementReport {
        schema_version: 1,
        fixture: Fixture {
            flow_count: FLOW_COUNT,
            lookup_iterations: LOOKUP_ITERATIONS,
            backend_cardinalities: CARDINALITIES,
            slot_bytes: size_of::<ServiceBackendSlotKey>() + size_of::<ServiceBackendSlotValue>(),
            timing_note: "single-process release build; nanoseconds are comparative observations, not a production SLA",
        },
        acceptance: Acceptance {
            selected_min_slots_per_backend: 16,
            maximum_table_size: 65_537,
            maximum_table_balance_error_ppm: 62_500,
            packet_map_lookups_stable_hash: 1,
            packet_map_lookups_maglev: 1,
            capacity_fallback: "deterministic StableHash when the fixed Maglev table does not fit the shared per-bank slot budget",
            table_boundary_upgrade: "a table-size boundary publishes a new immutable bank and revision; established flows remain pinned",
        },
        results: CARDINALITIES
            .iter()
            .map(|count| measure(*count, &hashes))
            .collect(),
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("measurement report serializes")
    );
}
