//! Non-transmitting context acquisition for the isolated device-lease fixture.
use std::{
    io::Read as _,
    os::fd::{AsFd as _, AsRawFd as _},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use aya::{
    Pod,
    maps::{Array, Map, MapData, MapError, MapType, ProgramArray, xdp::DevMap},
    programs::{SchedClassifier, TestRun, TestRunOptions},
};

fn context(ifindex: u32) -> Result<[u8; 44]> {
    ensure!(
        (2..=i32::MAX as u32).contains(&ifindex),
        "invalid device index"
    );
    // Stable Linux __sk_buff UAPI prefix: ifindex is the eleventh u32.
    // The kernel zero-fills the remainder of the context, resolves the actual
    // device in the calling namespace, and holds a reference for the call.
    let mut bytes = [0_u8; 44];
    bytes[40..44].copy_from_slice(&ifindex.to_ne_bytes());
    Ok(bytes)
}

fn packet() -> [u8; 42] {
    let mut bytes = [0_u8; 42];
    bytes[..6].copy_from_slice(&[2, 68, 70, 0, 1, 2]);
    bytes[6..12].copy_from_slice(&[2, 68, 70, 0, 1, 1]);
    bytes[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    bytes[14] = 0x45;
    bytes[16..18].copy_from_slice(&28_u16.to_be_bytes());
    bytes[22] = 64;
    bytes[23] = 17;
    bytes[26..30].copy_from_slice(&[10, 244, 46, 1]);
    bytes[30..34].copy_from_slice(&[10, 244, 46, 2]);
    bytes[34..36].copy_from_slice(&17779_u16.to_be_bytes());
    bytes[36..38].copy_from_slice(&17779_u16.to_be_bytes());
    bytes[38..40].copy_from_slice(&8_u16.to_be_bytes());
    let sum: u32 = bytes[14..34]
        .chunks_exact(2)
        .map(|word| u32::from(u16::from_be_bytes([word[0], word[1]])))
        .sum();
    let folded = (sum & 0xffff) + (sum >> 16);
    let folded = (folded & 0xffff) + (folded >> 16);
    let checksum = !u16::try_from(folded).expect("folded IPv4 checksum fits");
    bytes[24..26].copy_from_slice(&checksum.to_be_bytes());
    bytes
}

fn array<V: Pod>(path: &Path) -> Result<Array<MapData, V>> {
    let data = MapData::from_pin(path)?;
    ensure!(
        data.info()?.map_type()? == MapType::Array,
        "unexpected seed map type"
    );
    let array = Array::try_from(Map::Array(data))?;
    ensure!(array.len() == 1, "unexpected seed map capacity");
    Ok(array)
}

fn seed(directory: &Path, ifindex: u32) -> Result<()> {
    let input_context = context(ifindex)?;
    let input_packet = packet();
    let mut pointer: Array<_, u64> = array(&directory.join("maps/P9LEASEPTR"))?;
    let mut observation: Array<_, [u64; 4]> = array(&directory.join("maps/P9LEASERES"))?;
    // Only this disposable candidate is cleared; never read/export its pointer.
    // Both syscall failures and rejected contexts must leave no prior seed.
    pointer.set(0, 0, 0)?;
    let mut row = observation.get(&0, 0)?;
    row[3] = 0;
    observation.set(0, row, 0)?;
    let result = (|| -> Result<()> {
        let program = SchedClassifier::from_pin(directory.join("seed"))?;
        let mut output_context = [0_u8; 256];
        let mut output_packet = [0_u8; 42];
        let result = program
            .test_run(TestRunOptions {
                data_in: Some(&input_packet),
                data_out: Some(&mut output_packet),
                ctx_in: Some(&input_context),
                ctx_out: Some(&mut output_context),
                ..TestRunOptions::default()
            })
            .context("kernel device-context invocation")?;
        ensure!(
            result.return_value == 2
                && result.data_size_out == 42
                && (44..=256).contains(&result.ctx_size_out)
                && output_context[40..44] == ifindex.to_ne_bytes()
                && output_packet == input_packet,
            "unexpected non-transmitting seed result"
        );
        let observed = observation.get(&0, 0)?;
        ensure!(
            observed[..3] == row[..3] && observed[3] == 100,
            "device context did not pass ownership checks"
        );
        Ok(())
    })();
    if result.is_err() {
        pointer
            .set(0, 0, 0)
            .context("retire rejected private seed")?;
        row[3] = 0;
        observation.set(0, row, 0)?;
    }
    result
}

fn private_directory(directory: &Path) -> Result<()> {
    ensure!(
        directory.file_name().is_some_and(|name| name == "bpffs")
            && directory
                .parent()
                .and_then(Path::file_name)
                .is_some_and(|name| name
                    .to_string_lossy()
                    .starts_with("unf-device-observation.")),
        "unexpected private pin directory"
    );
    Ok(())
}

fn frozen_fdinfo(value: &str) -> bool {
    let rows: Vec<_> = value
        .lines()
        .filter_map(|line| line.strip_prefix("frozen:"))
        .collect();
    rows.len() == 1 && rows[0].trim() == "1"
}

fn exact_bank_maps(mut actual: Vec<u32>, mut expected: Vec<u32>) -> bool {
    actual.sort_unstable();
    expected.sort_unstable();
    expected.len() == 7
        && expected[0] != 0
        && expected.windows(2).all(|pair| pair[0] != pair[1])
        && actual == expected
}

fn publish(directory: &Path, bank: &Path) -> Result<()> {
    private_directory(bank)?;
    let mut expected_maps = Vec::with_capacity(7);
    let mut held_maps = Vec::with_capacity(6);
    let mut held_tag: Option<Array<MapData, u32>> = None;
    for (name, kind, entries, bytes) in [
        ("P9LEASECFG", MapType::Array, 1, 160),
        ("P9LEASEPTR", MapType::Array, 1, 8),
        ("P9LEASEDEV", MapType::DevMap, 4, 8),
        ("P9LEASEOWN", MapType::Array, 4, 104),
        ("P9LEASETAG", MapType::Array, 1, 4),
    ] {
        let map = MapData::from_pin(bank.join("maps").join(name))?;
        let info = map.info()?;
        expected_maps.push(info.id());
        ensure!(
            info.map_type()? == kind
                && info.max_entries() == entries
                && info.key_size() == 4
                && info.value_size() == bytes,
            "unexpected bank map shape"
        );
        let mut text = String::new();
        std::fs::File::open(format!(
            "/proc/self/fdinfo/{}",
            map.fd().as_fd().as_raw_fd()
        ))?
        .take(4097)
        .read_to_string(&mut text)?;
        ensure!(
            text.len() <= 4096 && frozen_fdinfo(&text),
            "bank is not sealed"
        );
        if name == "P9LEASETAG" {
            held_tag = Some(Array::try_from(Map::Array(map))?);
        } else {
            held_maps.push(map);
        }
    }
    let tag = held_tag.context("missing sealed tag descriptor")?;
    ensure!((1..=2).contains(&tag.get(&0, 0)?), "invalid bank tag");
    for (name, kind, entries, bytes) in [
        ("P9LEASECON", MapType::PerCpuArray, 1, 24),
        ("P9LEASESEQ", MapType::Array, 65536, 8),
    ] {
        let map = MapData::from_pin(bank.join("maps").join(name))?;
        let info = map.info()?;
        ensure!(
            info.map_type()? == kind
                && info.max_entries() == entries
                && info.key_size() == 4
                && info.value_size() == bytes,
            "unexpected bank observer map"
        );
        expected_maps.push(info.id());
        held_maps.push(map);
    }
    let data = MapData::from_pin(directory.join("maps/P9LEASENEXT"))?;
    let info = data.info()?;
    ensure!(
        info.map_type()? == MapType::ProgramArray && info.max_entries() == 1,
        "unexpected dispatcher map"
    );
    let mut dispatch = ProgramArray::try_from(Map::ProgramArray(data))?;
    let program = SchedClassifier::from_pin(bank.join("concurrent"))?;
    let program_info = program.info()?;
    let actual_maps = program_info
        .map_ids()?
        .context("unavailable program map identities")?;
    ensure!(
        exact_bank_maps(actual_maps, expected_maps),
        "classifier does not own this exact bank"
    );
    let id = program_info.id();
    dispatch.set(0, program.fd()?, 0)?;
    // Hold every checked descriptor through the publication syscall. A removed
    // pin cannot turn a checked map ID into a replacement object in this gap.
    drop(tag);
    drop(held_maps);
    println!(
        "{}",
        serde_json::json!({"schemaVersion":1,"publishedProgramId":id,
        "scope":"isolated-device-generation","productionAuthority":false})
    );
    Ok(())
}

fn ledger(directory: &Path) -> Result<()> {
    let data = MapData::from_pin(directory.join("maps/P9LEASESEQ"))?;
    ensure!(
        data.info()?.map_type()? == MapType::Array,
        "unexpected sequence map type"
    );
    let sequences: Array<_, [u32; 2]> = Array::try_from(Map::Array(data))?;
    ensure!(sequences.len() == 65_536, "unexpected sequence capacity");
    let mut entries = Vec::new();
    for key in 0..sequences.len() {
        let value = sequences.get(&key, 0)?;
        if value != [0, 0] {
            ensure!(
                (1..=2).contains(&value[0]) && (1..=2).contains(&value[1]),
                "invalid sequence observation"
            );
            entries.push([key, value[0], value[1]]);
        }
    }
    println!(
        "{}",
        serde_json::json!({"schemaVersion":1,"capacity":65536,
        "entries":entries,"productionAuthority":false})
    );
    Ok(())
}

fn main() -> Result<()> {
    ensure!(
        std::env::var("UNF_DEVICE_OBSERVATION_ISOLATED_CONTAINER").as_deref() == Ok("yes"),
        "isolated fixture opt-in required"
    );
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        arguments.len() == 2 || (arguments.len() == 3 && arguments[1] == "publish"),
        "expected private bpffs directory and index|bindings|ledger, or publish and a bank directory"
    );
    let directory = PathBuf::from(&arguments[0]);
    private_directory(&directory)?;
    if arguments[1] == "publish" {
        ensure!(arguments.len() == 3, "publish requires a bank directory");
        let bank = PathBuf::from(&arguments[2]);
        return publish(&directory, &bank);
    }
    if arguments[1] == "ledger" {
        return ledger(&directory);
    }
    if arguments[1] == "bindings" {
        let data = MapData::from_pin(directory.join("maps/P9LEASEDEV"))?;
        ensure!(
            data.info()?.map_type()? == MapType::DevMap,
            "unexpected device map type"
        );
        let devices = DevMap::try_from(Map::DevMap(data))?;
        ensure!(devices.len() == 4, "unexpected device binding capacity");
        let mut bindings = Vec::with_capacity(4);
        for index in 0..4 {
            match devices.get(index, 0) {
                Ok(value) => {
                    ensure!(
                        value.if_index > 1 && value.prog_id.is_none(),
                        "unexpected device binding"
                    );
                    bindings.push(Some(value.if_index));
                }
                Err(MapError::KeyNotFound) => bindings.push(None),
                Err(error) => return Err(error.into()),
            }
        }
        println!("{}", serde_json::to_string(&bindings)?);
        return Ok(());
    }
    let ifindex: u32 = arguments[1]
        .to_str()
        .context("non-UTF8 device index")?
        .parse()?;
    seed(&directory, ifindex)?;
    println!(
        "{}",
        serde_json::json!({"schemaVersion":1,"seedMethod":"kernelTestContext",
        "contextIfindex":ifindex,"programReturn":2,"packetTransmitted":false,"productionAuthority":false})
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealing_requires_one_exact_frozen_fdinfo_field() {
        assert!(frozen_fdinfo("map_type:\t2\nfrozen:\t1\n"));
        for invalid in [
            "",
            "frozen:\t0\n",
            "frozen:\t1\nfrozen:\t1\n",
            "notfrozen:\t1\n",
            "frozen:\t10\n",
        ] {
            assert!(!frozen_fdinfo(invalid));
        }
    }

    #[test]
    fn publication_requires_the_exact_distinct_generation_maps() {
        let expected: Vec<_> = (1..=7).collect();
        assert!(exact_bank_maps((1..=7).rev().collect(), expected.clone()));
        for actual in [
            vec![],
            (1..=6).collect(),
            (1..=8).collect(),
            (2..=8).collect(),
            vec![1, 2, 3, 4, 5, 6, 6],
        ] {
            assert!(!exact_bank_maps(actual, expected.clone()));
        }
        for invalid in [vec![], vec![0, 1, 2, 3, 4, 5, 6], vec![1, 2, 3, 4, 5, 6, 6]] {
            assert!(!exact_bank_maps(invalid.clone(), invalid));
        }
    }

    #[test]
    fn context_exposes_only_the_requested_device_coordinate() {
        let bytes = context(301).unwrap();
        assert!(bytes[..40].iter().all(|byte| *byte == 0));
        assert_eq!(bytes[40..44], 301_u32.to_ne_bytes());
        for invalid in [0, 1, u32::MAX] {
            assert!(context(invalid).is_err());
        }
    }

    #[test]
    fn synthetic_seed_frame_has_complete_ipv4_udp_headers() {
        let bytes = packet();
        assert_eq!(&bytes[12..14], &0x0800_u16.to_be_bytes());
        assert_eq!(bytes[14], 0x45);
        assert_eq!(bytes[23], 17);
        assert_eq!(&bytes[36..38], &17779_u16.to_be_bytes());
        assert_eq!(&bytes[38..40], &8_u16.to_be_bytes());
        let sum: u32 = bytes[14..34]
            .chunks_exact(2)
            .map(|word| u32::from(u16::from_be_bytes([word[0], word[1]])))
            .sum();
        assert_eq!((sum & 0xffff) + (sum >> 16), 0xffff);
    }
}
