//! Bounded, read-only Linux BTF layout discovery for the device lifetime probe.
//!
//! Offsets are metadata, not device ownership, a lease, or packet permission.
//! Only the little-endian 64-bit layout used by the qualified x86-64 probe is
//! supported. Unsupported encodings/layouts fail closed. No external programs,
//! kernel pointers, BPF writes, namespace switches or unbounded JSON trees.

use std::{collections::VecDeque, fs::File, io::Read};

use sha2::{Digest as _, Sha256};
use thiserror::Error;

mod btf;
use btf::{Btf, Type};

pub const MAX_BASE_BTF_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_MODULE_BTF_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum KernelLayoutError {
    #[error("unsupported or malformed device BTF: {0}")]
    Invalid(&'static str),
    #[error("device BTF read failed: {0}")]
    Io(#[from] std::io::Error),
}

type Result<T> = std::result::Result<T, KernelLayoutError>;

fn require(condition: bool, message: &'static str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(KernelLayoutError::Invalid(message))
    }
}

/// Immutable discovery result. Not deserializable or constructible from offsets.
/// A caller still needs independent live kernel capability/ownership checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelDeviceLayout {
    offsets: DeviceOffsets,
    btf_digest: [u8; 32],
}

/// Public values are for loading a separately verified program or diagnostics;
/// copying them never conveys authentication or lifetime authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceOffsets {
    pub skb_device: u32,
    pub device_index: u32,
    pub device_net: u32,
    pub net_cookie: u32,
    pub device_peer: u32,
    pub device_flags: u32,
    pub device_alias: u32,
    pub alias_data: u32,
}

impl KernelDeviceLayout {
    /// Read the current kernel and optional loaded veth module BTF. The veth
    /// type may instead be built into vmlinux. Absence is not a fallback layout.
    /// The caller must run this blocking discovery off its async event loop.
    ///
    /// # Errors
    /// Rejects unsupported architecture, unreadable/oversized BTF, malformed
    /// metadata, ambiguous structures and conflicting base/module layouts.
    pub fn discover() -> Result<Self> {
        require(
            cfg!(all(target_arch = "x86_64", target_endian = "little")),
            "architecture",
        )?;
        let base = read_bounded(File::open("/sys/kernel/btf/vmlinux")?, MAX_BASE_BTF_BYTES)?;
        let module = match File::open("/sys/kernel/btf/veth") {
            Ok(file) => Some(read_bounded(file, MAX_MODULE_BTF_BYTES)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        Self::from_btf(&base, module.as_deref())
    }

    /// Discover from a bounded base and optional split-module BTF inventory.
    /// Intended also for independent replay of public, captured kernel metadata.
    /// Byte provenance is the caller's responsibility; the digest is integrity
    /// only and must never substitute for live kernel/boot authentication.
    ///
    /// # Errors
    /// Rejects unknown encoding, capacity, missing/wrong fields, alias cycles,
    /// invalid references, bitfields, anonymous-member ambiguity, conflicting
    /// duplicate layouts, and unsupported private-area geometry.
    pub fn from_btf(base: &[u8], module: Option<&[u8]>) -> Result<Self> {
        require(base.len() <= MAX_BASE_BTF_BYTES, "base byte budget")?;
        require(
            module.is_none_or(|data| data.len() <= MAX_MODULE_BTF_BYTES),
            "module byte budget",
        )?;
        let btf = Btf::parse(base, module)?;
        let skbs = btf.named("sk_buff")?;
        let devices = btf.named("net_device")?;
        let nets = btf.named("net")?;
        let peers = btf.named("veth_priv")?;
        let aliases = btf.named("dev_ifalias")?;
        let mut accepted = None;
        // At most two definitions per name, one in each inventory. Every
        // combination must agree, including sizes, not just the first match.
        for skb in &skbs {
            for device in &devices {
                for net in &nets {
                    for peer in &peers {
                        for alias in &aliases {
                            let candidate = derive(&btf, *skb, *device, *net, *peer, *alias)?;
                            if let Some(previous) = &accepted {
                                require(previous == &candidate, "conflicting base/module layouts")?;
                            } else {
                                accepted = Some(candidate);
                            }
                        }
                    }
                }
            }
        }
        let (offsets, _) = accepted.ok_or(KernelLayoutError::Invalid("no device layout"))?;
        let mut digest = Sha256::new();
        digest.update(b"unf:kernel-device-btf:v1\0");
        digest.update((base.len() as u64).to_le_bytes());
        digest.update(base);
        digest.update([u8::from(module.is_some())]);
        if let Some(module) = module {
            digest.update((module.len() as u64).to_le_bytes());
            digest.update(module);
        }
        Ok(Self {
            offsets,
            btf_digest: digest.finalize().into(),
        })
    }

    #[must_use]
    pub const fn offsets(&self) -> DeviceOffsets {
        self.offsets
    }

    #[must_use]
    pub const fn btf_digest(&self) -> &[u8; 32] {
        &self.btf_digest
    }
}

fn read_bounded(reader: impl Read, budget: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(budget as u64 + 1).read_to_end(&mut bytes)?;
    require(bytes.len() <= budget, "stream byte budget")?;
    Ok(bytes)
}

#[derive(Clone, Copy)]
struct Field {
    offset: u32,
    type_id: u32,
    available: u32,
}

impl Btf<'_> {
    fn field(&self, id: u32, name: &str) -> Result<Field> {
        self.optional_field(id, name)?
            .ok_or(KernelLayoutError::Invalid("missing member"))
    }

    fn optional_field(&self, id: u32, name: &str) -> Result<Option<Field>> {
        let mut queue = VecDeque::from([(id, 0_u32, 0_u8)]);
        let mut found = None;
        for _ in 0..64 {
            let Some((id, offset, depth)) = queue.pop_front() else {
                return Ok(found);
            };
            let container = self.resolved(id)?;
            require(
                depth <= 8 && matches!(container.kind(), 4 | 5) && container.vlen() <= 512,
                "member traversal budget/shape",
            )?;
            for member in container.extra.chunks_exact(12) {
                let member_name = self.string(btf::word(member, 0)?)?;
                let member_id = btf::word(member, 4)?;
                let raw_offset = btf::word(member, 8)?;
                let bitfield = container.flag() && raw_offset >> 24 != 0;
                let bits = if container.flag() {
                    raw_offset & 0x00ff_ffff
                } else {
                    raw_offset
                };
                if member_name != name && !member_name.is_empty() {
                    continue;
                }
                require(
                    !bitfield && bits % 8 == 0 && bits / 8 <= container.value,
                    "member bitfield/offset",
                )?;
                let local = bits / 8;
                let absolute = offset
                    .checked_add(local)
                    .ok_or(KernelLayoutError::Invalid("member offset overflow"))?;
                require(absolute <= 65_536, "member offset budget")?;
                if member_name == name {
                    require(found.is_none(), "ambiguous member")?;
                    found = Some(Field {
                        offset: absolute,
                        type_id: member_id,
                        available: container.value - local,
                    });
                } else {
                    let child = self.resolved(member_id)?;
                    require(
                        matches!(child.kind(), 4 | 5) && child.value <= container.value - local,
                        "anonymous container extent",
                    )?;
                    require(queue.len() < 64, "member queue budget")?;
                    queue.push_back((member_id, absolute, depth + 1));
                }
            }
        }
        require(queue.is_empty(), "member visit budget")?;
        Ok(found)
    }

    fn pointer(&self, id: u32, name: &str) -> Result<()> {
        let pointer = self.resolved(id)?;
        require(pointer.kind() == 2, "expected pointer")?;
        let target = self.resolved(pointer.value)?;
        require(
            target.kind() == 4 && self.string(target.name)? == name,
            "wrong pointer target",
        )
    }

    fn integer(&self, id: u32, size: u32) -> Result<()> {
        let integer = self.resolved(id)?;
        require(
            integer.kind() == 1 && integer.value == size,
            "integer width",
        )?;
        let encoding = btf::word(integer.extra, 0)?;
        require(
            encoding & 0xffff == size * 8
                && encoding & 0x00ff_0000 == 0
                && encoding & 0xf800_0000 == 0,
            "integer encoding",
        )
    }

    fn byte_tail(&self, id: u32) -> Result<()> {
        let array = self.resolved(id)?;
        require(
            array.kind() == 3 && btf::word(array.extra, 8)? == 0,
            "expected flexible byte array",
        )?;
        self.integer(btf::word(array.extra, 0)?, 1)
    }
}

fn fits(field: Field, owner: Type<'_>, width: u32, alignment: u32) -> Result<()> {
    require(
        width <= field.available
            && field.offset.is_multiple_of(alignment)
            && field
                .offset
                .checked_add(width)
                .is_some_and(|end| end <= owner.value),
        "member alignment/extent",
    )
}

fn derive(
    btf: &Btf<'_>,
    skb_id: u32,
    device_id: u32,
    net_id: u32,
    peer_id: u32,
    alias_id: u32,
) -> Result<(DeviceOffsets, [u32; 5])> {
    let skb = btf.item(skb_id)?;
    let device = btf.item(device_id)?;
    let net = btf.item(net_id)?;
    let peer = btf.item(peer_id)?;
    let alias = btf.item(alias_id)?;
    require(
        skb.value >= 64
            && (64..=8192).contains(&device.value)
            && (8..=256).contains(&peer.value)
            && (8..=256).contains(&alias.value),
        "structure size",
    )?;
    let skb_device = btf.field(skb_id, "dev")?;
    let index = btf.field(device_id, "ifindex")?;
    let nd_net = btf.field(device_id, "nd_net")?;
    let net_pointer = btf.field(nd_net.type_id, "net")?;
    let device_net = Field {
        offset: nd_net
            .offset
            .checked_add(net_pointer.offset)
            .ok_or(KernelLayoutError::Invalid("net offset overflow"))?,
        type_id: net_pointer.type_id,
        available: nd_net.available,
    };
    let cookie = btf.field(net_id, "net_cookie")?;
    let peer_pointer = btf.field(peer_id, "peer")?;
    let flags = btf.field(device_id, "flags")?;
    let alias_pointer = btf.field(device_id, "ifalias")?;
    let alias_data = btf.field(alias_id, "ifalias")?;
    btf.pointer(skb_device.type_id, "net_device")?;
    btf.pointer(net_pointer.type_id, "net")?;
    btf.pointer(peer_pointer.type_id, "net_device")?;
    btf.pointer(alias_pointer.type_id, "dev_ifalias")?;
    btf.integer(index.type_id, 4)?;
    btf.integer(flags.type_id, 4)?;
    btf.integer(cookie.type_id, 8)?;
    btf.byte_tail(alias_data.type_id)?;
    fits(skb_device, skb, 8, 8)?;
    require(skb_device.offset <= 56, "skb bounded read window")?;
    fits(index, device, 4, 4)?;
    fits(device_net, device, 8, 8)?;
    fits(net_pointer, btf.resolved(nd_net.type_id)?, 8, 8)?;
    fits(cookie, net, 8, 8)?;
    fits(peer_pointer, peer, 8, 8)?;
    fits(flags, device, 4, 4)?;
    fits(alias_pointer, device, 8, 8)?;
    require(alias_data.offset == alias.value, "alias flexible tail")?;
    // Linux's historical netdev_priv uses ALIGN(sizeof(net_device), 32).
    // Newer kernels expose a flexible priv member: require it to agree, never
    // silently assume the historical formula if that member contradicts it.
    // This geometry still requires an independent real-kernel capability probe.
    let private = device.value.div_ceil(32) * 32;
    if let Some(tail) = btf.optional_field(device_id, "priv")? {
        btf.byte_tail(tail.type_id)?;
        require(tail.offset == private, "unsupported netdev private tail")?;
    }
    Ok((
        DeviceOffsets {
            skb_device: skb_device.offset,
            device_index: index.offset,
            device_net: device_net.offset,
            net_cookie: cookie.offset,
            device_peer: private + peer_pointer.offset,
            device_flags: flags.offset,
            device_alias: alias_pointer.offset,
            alias_data: alias_data.offset,
        },
        [skb.value, device.value, net.value, peer.value, alias.value],
    ))
}

#[cfg(test)]
mod tests;
