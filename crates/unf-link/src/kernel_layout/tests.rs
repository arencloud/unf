use super::*;

#[derive(Clone)]
struct Table {
    strings: Vec<u8>,
    records: Vec<Vec<u8>>,
    string_base: u32,
}

impl Table {
    fn new(string_base: u32) -> Self {
        Self {
            strings: vec![0],
            records: Vec::new(),
            string_base,
        }
    }
    fn name(&mut self, name: &str) -> u32 {
        if name.is_empty() {
            return 0;
        }
        let offset = self.string_base + u32::try_from(self.strings.len()).unwrap();
        self.strings.extend_from_slice(name.as_bytes());
        self.strings.push(0);
        offset
    }
    fn record(&mut self, name: &str, info: u32, value: u32, extra: &[u32]) {
        let name = self.name(name);
        self.records.push(
            [name, info, value]
                .into_iter()
                .chain(extra.iter().copied())
                .flat_map(u32::to_le_bytes)
                .collect(),
        );
    }
    fn structure(&mut self, name: &str, kind: u32, size: u32, members: &[(&str, u32, u32)]) {
        let extra: Vec<_> = members
            .iter()
            .flat_map(|(name, id, offset)| [self.name(name), *id, *offset])
            .collect();
        self.record(
            name,
            kind << 24 | u32::try_from(members.len()).unwrap(),
            size,
            &extra,
        );
    }
    fn encode(&self) -> Vec<u8> {
        let types: Vec<_> = self.records.iter().flatten().copied().collect();
        let len = u32::try_from(types.len()).unwrap();
        [
            0x0001_eb9f,
            24,
            0,
            len,
            len,
            u32::try_from(self.strings.len()).unwrap(),
        ]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .chain(types)
        .chain(self.strings.iter().copied())
        .collect()
    }
    fn set(&mut self, id: usize, word: usize, value: u32) {
        self.records[id - 1][word * 4..word * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
}

fn base() -> Table {
    let mut t = Table::new(0);
    t.record("int", 1 << 24, 4, &[32]); // 1
    t.record("u64", 1 << 24, 8, &[64]); // 2
    t.record("char", 1 << 24, 1, &[8]); // 3
    t.record("", 2 << 24, 12, &[]); // 4
    t.record("", 2 << 24, 13, &[]); // 5
    t.record("", 2 << 24, 15, &[]); // 6
    t.record("", 3 << 24, 0, &[3, 1, 0]); // 7
    t.structure("", 4, 8, &[("net", 5, 0)]); // 8
    t.record("possible_net_t", 8 << 24, 8, &[]); // 9
    t.structure("", 4, 24, &[("dev", 4, 128)]); // 10
    t.structure("", 5, 24, &[("", 10, 0)]); // 11
    t.structure(
        "net_device",
        4,
        128,
        &[
            ("ifindex", 1, 64),
            ("nd_net", 9, 128),
            ("flags", 1, 192),
            ("ifalias", 6, 256),
        ],
    ); // 12
    t.structure("net", 4, 64, &[("net_cookie", 2, 256)]); // 13
    t.structure("sk_buff", 4, 128, &[("", 11, 0)]); // 14
    t.structure("dev_ifalias", 4, 16, &[("ifalias", 7, 128)]); // 15
    t
}

fn module(base: &Table) -> Table {
    let mut module = Table::new(u32::try_from(base.strings.len()).unwrap());
    module.structure("veth_priv", 4, 16, &[("peer", 4, 0)]);
    module
}

fn expected() -> DeviceOffsets {
    DeviceOffsets {
        skb_device: 16,
        device_index: 8,
        device_net: 16,
        net_cookie: 32,
        device_peer: 128,
        device_flags: 24,
        device_alias: 32,
        alias_data: 16,
    }
}

#[test]
fn split_and_builtin_layouts_agree_but_bytes_have_distinct_digests() {
    let mut base = base();
    let module = module(&base);
    let split = KernelDeviceLayout::from_btf(&base.encode(), Some(&module.encode())).unwrap();
    base.structure("veth_priv", 4, 16, &[("peer", 4, 0)]);
    let builtin = KernelDeviceLayout::from_btf(&base.encode(), None).unwrap();
    assert_eq!(split.offsets(), expected());
    assert_eq!(builtin.offsets(), expected());
    assert_ne!(split.btf_digest(), builtin.btf_digest());
}

#[test]
fn every_truncation_and_trailing_byte_is_rejected_without_panic() {
    let base = base();
    let module = module(&base);
    let base = base.encode();
    let module = module.encode();
    for end in 0..base.len() {
        assert!(
            KernelDeviceLayout::from_btf(&base[..end], Some(&module)).is_err(),
            "base {end}"
        );
    }
    for end in 0..module.len() {
        assert!(
            KernelDeviceLayout::from_btf(&base, Some(&module[..end])).is_err(),
            "module {end}"
        );
    }
    let mut trailing = base;
    trailing.push(0);
    assert!(KernelDeviceLayout::from_btf(&trailing, Some(&module)).is_err());
}

#[test]
fn malformed_headers_and_sections_are_rejected() {
    let base = base();
    let module = module(&base).encode();
    let valid = base.encode();
    for (offset, value) in [
        (0, 0),
        (0, 0x9feb_0100),
        (0, 0x0002_eb9f),
        (0, 0x0101_eb9f),
        (4, 32),
        (8, 4),
        (12, u32::MAX),
        (12, 1),
        (16, 0),
        (20, u32::MAX),
        (20, 0),
    ] {
        let mut bytes = valid.clone();
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        assert!(
            KernelDeviceLayout::from_btf(&bytes, Some(&module)).is_err(),
            "{offset} {value}"
        );
    }
    let mut bytes = valid.clone();
    *bytes.last_mut().unwrap() = 1;
    assert!(KernelDeviceLayout::from_btf(&bytes, Some(&module)).is_err());
    let mut bytes = valid;
    let start = 24 + usize::try_from(btf::word(&bytes, 12).unwrap()).unwrap();
    bytes[start] = 1;
    assert!(KernelDeviceLayout::from_btf(&bytes, Some(&module)).is_err());
}

#[test]
fn wrong_types_bitfields_cycles_extents_and_offsets_are_rejected() {
    let source = base();
    let module = module(&source).encode();
    let mutations = [
        (1, 1, 31 << 24),
        (1, 1, 1 << 24 | 1),
        (1, 1, 0x8100_0000),
        (1, 2, 8),
        (1, 3, 31),
        (1, 3, 32 | 1 << 16),
        (2, 2, 4),
        (3, 3, 7),
        (4, 2, 13),
        (4, 2, 0),
        (4, 2, 900_000),
        (5, 2, 12),
        (6, 2, 13),
        (7, 5, 1),
        (7, 3, 1),
        (8, 2, 4),
        (9, 2, 9),
        (9, 2, 0),
        (10, 5, 129),
        (10, 5, 512),
        (10, 2, 20),
        (11, 4, 11),
        (11, 5, 64),
        (12, 2, 9000),
        (12, 2, 32),
        (12, 5, 65),
        (12, 5, 1000),
        (12, 7, 1),
        (12, 8, 129),
        (12, 10, 2),
        (12, 11, 200),
        (12, 13, 5),
        (12, 14, 264),
        (13, 5, 512),
        (14, 2, 32),
        (15, 2, 264),
        (15, 5, 64),
        (12, 0, u32::MAX),
    ];
    for (id, word, value) in mutations {
        let mut base = source.clone();
        base.set(id, word, value);
        assert!(
            KernelDeviceLayout::from_btf(&base.encode(), Some(&module)).is_err(),
            "type {id} word {word} value {value}"
        );
    }
    for id in [10, 12, 13, 15] {
        let mut base = source.clone();
        let info = btf::word(&base.records[id - 1], 4).unwrap();
        base.set(id, 1, info | 0x8000_0000);
        base.set(id, 5, 0x0100_0080);
        assert!(KernelDeviceLayout::from_btf(&base.encode(), Some(&module)).is_err());
    }
}

#[test]
fn split_string_and_type_names_cannot_silently_fall_back_to_base() {
    let base = base();
    let mut module = module(&base);
    module.set(1, 0, u32::MAX);
    assert!(KernelDeviceLayout::from_btf(&base.encode(), Some(&module.encode())).is_err());
    let mut module = module.clone();
    module.set(1, 0, 0);
    assert!(KernelDeviceLayout::from_btf(&base.encode(), Some(&module.encode())).is_err());
    assert!(KernelDeviceLayout::from_btf(&base.encode(), None).is_err());
}

#[test]
fn duplicate_names_and_anonymous_members_fail_closed() {
    let mut base = base();
    let module = module(&base).encode();
    base.records.push(base.records[11].clone());
    assert!(KernelDeviceLayout::from_btf(&base.encode(), Some(&module)).is_err());
    base.records.pop();
    let duplicate = base.records[9][12..].to_vec();
    base.records[9].extend_from_slice(&duplicate);
    base.set(10, 1, 4 << 24 | 2);
    assert!(KernelDeviceLayout::from_btf(&base.encode(), Some(&module)).is_err());
}

#[test]
fn matching_split_copies_are_checked_not_first_selected() {
    let base = base();
    let mut module = module(&base);
    // Copy all base types after module type 16, relocating every reference and
    // nonzero string coordinate. This models modern split-module duplication.
    let string_shift = u32::try_from(base.strings.len() + module.strings.len()).unwrap();
    for original in &base.records {
        let mut words: Vec<_> = original
            .chunks_exact(4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
            .collect();
        if words[0] != 0 {
            words[0] += string_shift;
        }
        match words[1] >> 24 {
            2 | 8 => words[2] += 16,
            3 => {
                words[3] += 16;
                words[4] += 16;
            }
            4 | 5 => {
                for member in words[3..].chunks_exact_mut(3) {
                    if member[0] != 0 {
                        member[0] += string_shift;
                    }
                    member[1] += 16;
                }
            }
            _ => {}
        }
        module
            .records
            .push(words.into_iter().flat_map(u32::to_le_bytes).collect());
    }
    module.strings.extend_from_slice(&base.strings);
    module.set(1, 4, 20); // veth peer references copied pointer (type 4 + 16).
    assert_eq!(
        KernelDeviceLayout::from_btf(&base.encode(), Some(&module.encode()))
            .unwrap()
            .offsets(),
        expected()
    );
    for (id, word, value) in [
        (13, 2, 160),
        (13, 5, 96),
        (14, 2, 80),
        (15, 2, 160),
        (16, 2, 24),
        (16, 5, 192),
        (5, 2, 29),
    ] {
        let mut bad = module.clone();
        bad.set(id, word, value);
        assert!(
            KernelDeviceLayout::from_btf(&base.encode(), Some(&bad.encode())).is_err(),
            "split {id}/{word}"
        );
    }
}

#[test]
fn private_tail_must_agree_with_qualified_historical_geometry() {
    let mut base = base();
    let name = base.name("priv");
    base.records[11].extend([name, 7, 1024].into_iter().flat_map(u32::to_le_bytes));
    base.set(12, 1, 4 << 24 | 5);
    let module = module(&base).encode();
    assert_eq!(
        KernelDeviceLayout::from_btf(&base.encode(), Some(&module))
            .unwrap()
            .offsets(),
        expected()
    );
    base.set(12, 17, 960);
    assert!(KernelDeviceLayout::from_btf(&base.encode(), Some(&module)).is_err());
}

#[test]
fn byte_type_and_traversal_budgets_are_enforced() {
    assert!(read_bounded(&[0; 5][..], 4).is_err());
    assert_eq!(read_bounded(&[0; 4][..], 4).unwrap().len(), 4);
    assert!(KernelDeviceLayout::from_btf(&vec![0; MAX_BASE_BTF_BYTES + 1], None).is_err());
    let mut base = base();
    let module = module(&base).encode();
    assert!(
        KernelDeviceLayout::from_btf(&base.encode(), Some(&vec![0; MAX_MODULE_BTF_BYTES + 1]))
            .is_err()
    );
    let anonymous = base.records[10][12..].to_vec();
    for _ in 0..64 {
        base.records[10].extend_from_slice(&anonymous);
    }
    base.set(11, 1, 5 << 24 | 0x41);
    assert!(KernelDeviceLayout::from_btf(&base.encode(), Some(&module)).is_err());
    let mut base = Table::new(0);
    let record: Vec<_> = [0_u32, 2 << 24, 0]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    base.records = vec![record; 200_001];
    assert!(KernelDeviceLayout::from_btf(&base.encode(), None).is_err());
}

#[test]
fn arbitrary_single_bit_mutations_never_panic() {
    // Accepted mutations can legitimately change unused names or valid sizes.
    // The invariant here is total bounded parsing, not blanket rejection.
    let base = base();
    let module = module(&base).encode();
    let mut bytes = base.encode();
    for index in 0..bytes.len() {
        for bit in 0..8 {
            bytes[index] ^= 1 << bit;
            let _ = KernelDeviceLayout::from_btf(&bytes, Some(&module));
            bytes[index] ^= 1 << bit;
        }
    }
}
