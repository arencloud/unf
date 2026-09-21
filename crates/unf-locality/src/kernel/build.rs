use std::fs::File;
use std::net::IpAddr;
use std::os::fd::AsFd as _;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use anyhow::{Context as _, Result, ensure};
use aya::{
    Ebpf, EbpfLoader,
    maps::{Array, HashMap, Map, MapData, MapType, xdp::DevMap},
    programs::{SchedClassifier, TestRun as _, TestRunOptions},
};
use rustix::thread::{LinkNameSpaceType, move_into_link_name_space};
use unf_ebpf_common::locality::{
    ABI_VERSION, AddressKey, AddressOwner, BankConfig, DeviceGeometry, Endpoint, MAX_ALIAS_LENGTH,
    MAX_ENDPOINTS,
};
use unf_link::kernel_layout::KernelDeviceLayout;

use super::{
    KernelLocalityBank,
    runtime::{RuntimeMaps, check_shape},
    sys::{self, Value},
};
use crate::LeasedLocalityBank;

pub(crate) struct PreparationControl {
    pub cancelled: Arc<AtomicBool>,
    pub deadline: Instant,
}

impl PreparationControl {
    pub fn check(&self) -> Result<()> {
        ensure!(
            !self.cancelled.load(Ordering::Acquire) && Instant::now() < self.deadline,
            "locality bank preparation cancelled or deadline exceeded"
        );
        Ok(())
    }
}

/// Runs inside the one persistent observation worker's blocking slot. That
/// permit must outlive this function, its joined namespace thread and recheck.
#[allow(clippy::too_many_lines)] // Keep the non-publishable-to-sealed transition in one auditable order.
pub(crate) async fn prepare(
    mut leased: LeasedLocalityBank,
    runtime: Arc<RuntimeMaps>,
    elf: &[u8],
    pin_root: &Path,
    control: &PreparationControl,
) -> Result<KernelLocalityBank> {
    control.check()?;
    ensure!(
        !elf.is_empty() && elf.len() <= 4 * 1024 * 1024,
        "locality ELF byte budget"
    );
    let endpoints = leased
        .observed()
        .endpoints()
        .context("retired locality observations")?;
    let count = u32::try_from(endpoints.len())?;
    ensure!(
        (1..=MAX_ENDPOINTS).contains(&count) && leased.leases().len() == endpoints.len(),
        "locality bank endpoint count"
    );
    let addresses = u32::try_from(
        leased
            .observed()
            .addresses()
            .context("retired addresses")?
            .len(),
    )?;
    let gate = MapData::from_fd(leased.leases()[0].duplicate_map_fd()?)?;
    let gate_capacity = gate.info()?.max_entries();
    ensure!(
        (count..=MAX_ENDPOINTS).contains(&gate_capacity),
        "locality gate capacity"
    );
    check_shape(&gate, MapType::Hash, 32, 8, gate_capacity, 128)?;
    let config = configuration(&leased, &KernelDeviceLayout::discover()?)?;

    // Only four exact live shared FDs are briefly pinned. Bank maps and programs
    // are anonymous. Aya can CREATE missing pins, so exact ID checks below are
    // mandatory even after the pin syscall succeeds. Never trust names alone.
    let pins = tempfile::Builder::new()
        .prefix("unf-locality-")
        .tempdir_in(pin_root)?;
    let shared = [
        ("UL_LEASE_V1", &gate),
        ("UL_INPUT_V1", &runtime.input),
        ("UL_FENCE_V1", &runtime.fence),
        ("UL_RESUME_V1", &runtime.resume),
    ];
    let mut loader = EbpfLoader::new();
    loader
        .map_max_entries("UL_ADDRESS_V1", addresses)
        .map_max_entries("UL_ENDPOINT_V1", count)
        .map_max_entries("UL_DEVICE_V1", count * 2)
        .map_max_entries("UL_POINTER_V1", count)
        .map_max_entries("UL_SEEDED_V1", count)
        .map_max_entries("UL_LEASE_V1", gate_capacity);
    for (name, map) in shared {
        let path = pins.path().join(name);
        map.pin(&path)?;
        loader.map_pin_path(name, path);
    }
    let mut object = loader.load(elf).context("load fresh locality ELF/maps")?;
    for (name, expected) in shared {
        ensure!(
            data(&object, name)?.info()?.id() == expected.info()?.id(),
            "substituted locality shared map {name}"
        );
    }
    // Remove only our random, privately created pin directory. Explicit close
    // surfaces cleanup errors; actual descriptors remain held by this object.
    pins.close()?;
    validate_shapes(&object, count, addresses)?;
    fill(&mut object, &leased, config, control)?;
    let seed: &mut SchedClassifier = object
        .program_mut("unf_locality_seed")
        .context("missing seed")?
        .try_into()?;
    seed.load().context("load locality non-transmitting seed")?;
    check_program_maps(
        &object,
        "unf_locality_seed",
        &[
            "UL_CONFIG_V1",
            "UL_ENDPOINT_V1",
            "UL_DEVICE_V1",
            "UL_POINTER_V1",
            "UL_SEEDED_V1",
        ],
    )?;
    seed_devices(&mut object, &leased, control)?;
    let seed: &mut SchedClassifier = object
        .program_mut("unf_locality_seed")
        .context("missing seed")?
        .try_into()?;
    seed.unload().context("destroy locality seed capability")?;
    ensure!(seed.fd().is_err(), "seed capability remains loaded");
    // Load privately BEFORE freeze. Linux 5.14's verifier attempts a direct
    // constant read from a frozen RDONLY_PROG multi-entry array, whose direct
    // value callback only supports one entry (ENOTSUPP). This order preserves
    // program-read-only enforcement and all sealing requirements at publication.
    // No consumer FD, pin, link or dispatch escapes during this transition.
    let consumer: &mut SchedClassifier = object
        .program_mut("unf_locality_bank")
        .context("missing consumer")?
        .try_into()?;
    consumer.load().context("load private locality consumer")?;
    check_program_maps(
        &object,
        "unf_locality_bank",
        &[
            "UL_CONFIG_V1",
            "UL_ADDRESS_V1",
            "UL_ENDPOINT_V1",
            "UL_DEVICE_V1",
            "UL_POINTER_V1",
            "UL_LEASE_V1",
            "UL_INPUT_V1",
            "UL_FENCE_V1",
            "UL_RESUME_V1",
            "UL_COUNTER_V1",
        ],
    )?;
    for name in [
        "UL_CONFIG_V1",
        "UL_ADDRESS_V1",
        "UL_ENDPOINT_V1",
        "UL_DEVICE_V1",
        "UL_POINTER_V1",
        "UL_SEEDED_V1",
    ] {
        control.check()?;
        sys::freeze(data(&object, name)?.fd().as_fd())
            .with_context(|| format!("seal locality map {name}"))?;
    }
    control.check()?;
    leased.recheck().await?;
    control.check()?;
    Ok(KernelLocalityBank {
        object,
        leased,
        runtime,
    })
}

fn configuration(leased: &LeasedLocalityBank, layout: &KernelDeviceLayout) -> Result<BankConfig> {
    let observed = leased.observed();
    let endpoints = observed.endpoints().context("retired endpoints")?;
    let cookies = endpoints
        .first()
        .context("empty locality bank")?
        .namespace_cookies()
        .context("retired namespace coordinates")?;
    let offsets = layout.offsets();
    let geometry = DeviceGeometry {
        skb_device: offsets.skb_device,
        device_index: offsets.device_index,
        device_net: offsets.device_net,
        net_cookie: offsets.net_cookie,
        device_peer: offsets.device_peer,
        device_flags: offsets.device_flags,
        device_alias: offsets.device_alias,
        alias_data: offsets.alias_data,
    };
    let config = BankConfig {
        identity_epoch: observed.context().identity_epoch,
        identity_revision: observed.context().identity_revision.get(),
        routing_revision: observed.context().routing_revision.get(),
        host_cookie: cookies.host(),
        endpoints: u32::try_from(endpoints.len())?,
        addresses: u32::try_from(observed.addresses().context("retired addresses")?.len())?,
        schema_version: ABI_VERSION,
        flags: 0,
        reserved: 0,
        geometry,
        placement_digest: observed.placement_digest().0,
    };
    ensure!(
        config.valid(),
        "invalid discovered locality bank configuration"
    );
    Ok(config)
}

fn fill(
    object: &mut Ebpf,
    leased: &LeasedLocalityBank,
    config: BankConfig,
    control: &PreparationControl,
) -> Result<()> {
    let mut configuration: Array<_, Value<BankConfig>> =
        Array::try_from(object.map_mut("UL_CONFIG_V1").context("configuration")?)?;
    configuration.set(0, Value(config), 0)?;
    ensure!(
        configuration.get(&0, 0)?.0 == config,
        "configuration readback mismatch"
    );
    let mut rows: Array<_, Value<Endpoint>> =
        Array::try_from(object.map_mut("UL_ENDPOINT_V1").context("endpoints")?)?;
    for (index, (observed, lease)) in leased
        .observed()
        .endpoints()
        .context("retired endpoints")?
        .iter()
        .zip(leased.leases())
        .enumerate()
    {
        control.check()?;
        let (links, _) = observed.readback().context("retired link observation")?;
        let cookies = observed
            .namespace_cookies()
            .context("retired namespace observation")?;
        let (host_alias, peer_alias) = observed.ownership_aliases();
        let row = Endpoint {
            nonce: *lease.nonce(),
            serial: lease.serial(),
            host_cookie: cookies.host(),
            peer_cookie: cookies.peer(),
            host_index: links.host_index,
            peer_index: links.peer_index,
            host_mac: links.host_address,
            peer_mac: links.peer_address,
            reserved: 0,
            host_alias: alias(host_alias)?,
            peer_alias: alias(peer_alias)?,
        };
        ensure!(
            row.valid(config.host_cookie),
            "invalid observed endpoint row"
        );
        let index = u32::try_from(index)?;
        rows.set(index, Value(row), 0)?;
        ensure!(rows.get(&index, 0)?.0 == row, "endpoint readback mismatch");
    }
    let mut addresses: HashMap<_, Value<AddressKey>, Value<AddressOwner>> =
        HashMap::try_from(object.map_mut("UL_ADDRESS_V1").context("addresses")?)?;
    for (address, owner) in leased.observed().addresses().context("retired addresses")? {
        control.check()?;
        let key = address_key(*address);
        let owner = AddressOwner {
            endpoint: u32::try_from(owner.endpoint())?,
            identity: owner.identity().get(),
        };
        ensure!(
            key.valid() && owner.valid(config.endpoints),
            "invalid address owner"
        );
        addresses.insert(Value(key), Value(owner), 1)?;
        ensure!(
            addresses.get(&Value(key), 0)?.0 == owner,
            "address readback mismatch"
        );
    }
    Ok(())
}

fn alias(text: &str) -> Result<[u8; 104]> {
    ensure!(
        !text.is_empty() && text.len() <= MAX_ALIAS_LENGTH && !text.as_bytes().contains(&0),
        "invalid complete ownership alias"
    );
    let mut result = [0; 104];
    result[..text.len()].copy_from_slice(text.as_bytes());
    Ok(result)
}

fn address_key(address: IpAddr) -> AddressKey {
    match address {
        IpAddr::V4(value) => {
            let mut address = [0; 16];
            address[..4].copy_from_slice(&value.octets());
            AddressKey { address, family: 4 }
        }
        IpAddr::V6(value) => AddressKey {
            address: value.octets(),
            family: 6,
        },
    }
}

fn validate_shapes(object: &Ebpf, count: u32, addresses: u32) -> Result<()> {
    for (name, kind, key, value, entries, flags) in [
        ("UL_CONFIG_V1", MapType::Array, 4, 112, 1, 128),
        ("UL_ADDRESS_V1", MapType::Hash, 20, 8, addresses, 128),
        ("UL_ENDPOINT_V1", MapType::Array, 4, 288, count, 128),
        ("UL_DEVICE_V1", MapType::DevMap, 4, 8, count * 2, 128),
        ("UL_POINTER_V1", MapType::Array, 4, 8, count, 0),
        ("UL_SEEDED_V1", MapType::Array, 4, 4, count, 0),
        ("UL_COUNTER_V1", MapType::PerCpuArray, 4, 40, 1, 0),
    ] {
        check_shape(data(object, name)?, kind, key, value, entries, flags)
            .with_context(|| format!("locality bank shape {name}"))?;
    }
    Ok(())
}

fn data<'a>(object: &'a Ebpf, name: &str) -> Result<&'a MapData> {
    match object.map(name).context("missing locality map")? {
        Map::Array(data)
        | Map::HashMap(data)
        | Map::DevMap(data)
        | Map::PerCpuArray(data)
        | Map::ProgramArray(data) => Ok(data),
        _ => anyhow::bail!("unexpected locality map type"),
    }
}

fn check_program_maps(object: &Ebpf, name: &str, names: &[&str]) -> Result<()> {
    let program: &SchedClassifier = object
        .program(name)
        .context("missing locality program")?
        .try_into()?;
    let mut actual = program
        .info()?
        .map_ids()?
        .context("unavailable program map identities")?;
    let mut expected = names
        .iter()
        .map(|name| Ok(data(object, name)?.info()?.id()))
        .collect::<Result<Vec<_>>>()?;
    actual.sort_unstable();
    expected.sort_unstable();
    ensure!(
        !expected.is_empty()
            && expected[0] != 0
            && expected.windows(2).all(|p| p[0] != p[1])
            && actual == expected,
        "locality program {name} has unexpected map identities"
    );
    Ok(())
}

fn seed_devices(
    object: &mut Ebpf,
    leased: &LeasedLocalityBank,
    control: &PreparationControl,
) -> Result<()> {
    // One dedicated OS thread for this entire bounded cohort, never setns on a
    // Tokio worker. Joining contains namespace failure/panic before slot release.
    std::thread::scope(|scope| {
        scope.spawn(|| -> Result<()> {
            let original = File::open("/proc/thread-self/ns/net")?;
            let result = seed_loop(object, leased, control);
            let restore = move_into_link_name_space(original.as_fd(), Some(LinkNameSpaceType::Network));
            match (result, restore) {
                (Ok(()), Ok(())) => Ok(()),
                (result, restore) => anyhow::bail!("locality device preparation failed: operation={result:?}, namespace_restore={restore:?}"),
            }
        }).join().map_err(|_| anyhow::anyhow!("locality namespace worker panicked"))?
    })
}

fn seed_loop(
    object: &mut Ebpf,
    leased: &LeasedLocalityBank,
    control: &PreparationControl,
) -> Result<()> {
    for (index, endpoint) in leased
        .observed()
        .endpoints()
        .context("retired endpoints")?
        .iter()
        .enumerate()
    {
        control.check()?;
        let index = u32::try_from(index)?;
        let (host, peer) = endpoint
            .namespace_descriptors()
            .context("retired namespace descriptors")?;
        let (links, _) = endpoint.readback().context("retired links")?;
        move_into_link_name_space(host, Some(LinkNameSpaceType::Network))?;
        {
            let mut devices = DevMap::try_from(object.map_mut("UL_DEVICE_V1").context("devices")?)?;
            devices.set(index * 2, links.host_index, None, 0)?;
            move_into_link_name_space(peer, Some(LinkNameSpaceType::Network))?;
            devices.set(index * 2 + 1, links.peer_index, None, 0)?;
            move_into_link_name_space(host, Some(LinkNameSpaceType::Network))?;
            ensure!(
                devices.get(index * 2, 0)?.if_index == links.host_index
                    && devices.get(index * 2 + 1, 0)?.if_index == links.peer_index,
                "device binding readback mismatch"
            );
        }
        control.check()?;
        let program: &SchedClassifier = object
            .program("unf_locality_seed")
            .context("seed")?
            .try_into()?;
        let mut input = [0_u8; 64];
        input[12..14].copy_from_slice(&0x88b5_u16.to_be_bytes());
        input[14..22].copy_from_slice(b"UNFLOC01");
        input[22..26].copy_from_slice(&index.to_be_bytes());
        let mut context = [0_u8; 44];
        context[40..44].copy_from_slice(&links.host_index.to_ne_bytes());
        let mut output = [0_u8; 64];
        let mut output_context = [0_u8; 256];
        let result = program.test_run(TestRunOptions {
            data_in: Some(&input),
            data_out: Some(&mut output),
            ctx_in: Some(&context),
            ctx_out: Some(&mut output_context),
            ..TestRunOptions::default()
        })?;
        ensure!(
            result.return_value == 2
                && result.data_size_out == 64
                && (44..=256).contains(&result.ctx_size_out)
                && output == input
                && output_context[40..44] == links.host_index.to_ne_bytes(),
            "unexpected non-transmitting locality seed result"
        );
        let seeded: Array<_, u32> =
            Array::try_from(object.map("UL_SEEDED_V1").context("seed status")?)?;
        ensure!(
            seeded.get(&index, 0)? == 1,
            "locality seed rejected actual device ownership"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancellation_and_deadline_stop_preparation() {
        let control = PreparationControl {
            cancelled: Arc::new(AtomicBool::new(false)),
            deadline: Instant::now() + std::time::Duration::from_secs(60),
        };
        assert!(control.check().is_ok());
        control.cancelled.store(true, Ordering::Release);
        assert!(control.check().is_err());
        let expired = PreparationControl {
            cancelled: Arc::new(AtomicBool::new(false)),
            deadline: Instant::now(),
        };
        assert!(expired.check().is_err());
    }
    #[test]
    fn aliases_are_complete_and_zero_padded() {
        for text in ["", "x\0y", &"x".repeat(97)] {
            assert!(alias(text).is_err());
        }
        let value = alias(&"x".repeat(96)).unwrap();
        assert_eq!(value[..96], [b'x'; 96]);
        assert_eq!(value[96..], [0; 8]);
    }
    #[test]
    fn addresses_have_canonical_family_and_bytes() {
        let v4 = address_key("192.0.2.1".parse().unwrap());
        assert_eq!(v4.family, 4);
        assert_eq!(v4.address[..4], [192, 0, 2, 1]);
        assert_eq!(v4.address[4..], [0; 12]);
        assert!(v4.valid());
        let v6 = address_key("2001:db8::1".parse().unwrap());
        assert_eq!(v6.family, 6);
        assert!(v6.valid());
    }
}
