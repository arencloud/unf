//! Non-transmitting context acquisition for the isolated device-lease fixture.
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use aya::{
    Pod,
    maps::{Array, Map, MapData, MapType},
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

fn main() -> Result<()> {
    ensure!(
        std::env::var("UNF_DEVICE_OBSERVATION_ISOLATED_CONTAINER").as_deref() == Ok("yes"),
        "isolated fixture opt-in required"
    );
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        arguments.len() == 2,
        "expected private bpffs directory and device index"
    );
    let directory = PathBuf::from(&arguments[0]);
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
