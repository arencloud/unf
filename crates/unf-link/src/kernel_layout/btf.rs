//! Narrow safe BTF v1 reader. Borrow payloads; store just one offset per type.
//! Encoding: Linux include/uapi/linux/btf.h. Split IDs/strings follow libbpf.

use super::{KernelLayoutError, Result, require};

const MAX_TYPES: usize = 200_000;

pub(super) fn word(bytes: &[u8], offset: usize) -> Result<u32> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or(KernelLayoutError::Invalid("truncated word"))?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

struct Inventory<'a> {
    types: &'a [u8],
    strings: &'a [u8],
    offsets: Vec<u32>,
}

#[derive(Clone, Copy)]
pub(super) struct Type<'a> {
    pub name: u32,
    info: u32,
    pub value: u32,
    pub extra: &'a [u8],
}

impl Type<'_> {
    pub fn kind(self) -> u32 {
        (self.info >> 24) & 0x7f
    }
    pub fn vlen(self) -> u32 {
        self.info & 0x00ff_ffff
    }
    pub fn flag(self) -> bool {
        self.info >> 31 != 0
    }
}

impl<'a> Inventory<'a> {
    fn parse(bytes: &'a [u8], budget: usize, split: bool) -> Result<Self> {
        require(
            bytes.get(..4) == Some(&[0x9f, 0xeb, 1, 0]),
            "little-endian BTF v1 header",
        )?;
        // Deliberately reject extended headers until their additional sections
        // and encoding have independent coverage. Never guess record lengths.
        require(word(bytes, 4)? == 24, "unsupported BTF header extension")?;
        let type_offset = word(bytes, 8)? as usize;
        let type_len = word(bytes, 12)? as usize;
        let str_offset = word(bytes, 16)? as usize;
        let str_len = word(bytes, 20)? as usize;
        require(
            type_offset == 0 && type_len.is_multiple_of(4) && str_offset == type_len,
            "BTF section geometry",
        )?;
        let type_end = 24_usize
            .checked_add(type_len)
            .ok_or(KernelLayoutError::Invalid("section overflow"))?;
        let end = type_end
            .checked_add(str_len)
            .ok_or(KernelLayoutError::Invalid("section overflow"))?;
        require(end == bytes.len(), "truncated or trailing BTF sections")?;
        let types = bytes
            .get(24..type_end)
            .ok_or(KernelLayoutError::Invalid("type section"))?;
        let strings = &bytes[type_end..end];
        require(
            (split || strings.first() == Some(&0))
                && (strings.is_empty() && split || strings.last() == Some(&0)),
            "string table terminator",
        )?;
        let mut offsets = Vec::new();
        let mut offset = 0;
        while offset < types.len() {
            require(offsets.len() < budget, "type count budget")?;
            let info = word(types, offset + 4)?;
            let kind = (info >> 24) & 0x7f;
            let vlen = (info & 0x00ff_ffff) as usize;
            let flag = info >> 31 != 0;
            // Linux BTF uses kflag=1 on declaration/type tags to encode
            // compiler attributes. Their record sizes and reference geometry
            // do not change; attributes are not additional layout authority.
            require(
                !flag || matches!(kind, 4..=7 | 17..=19),
                "unsupported kind flag",
            )?;
            let extra = match kind {
                1 | 14 | 17 => {
                    require(vlen == 0, "fixed type vlen")?;
                    4
                }
                3 => {
                    require(vlen == 0, "array vlen")?;
                    12
                }
                2 | 7..=11 | 16 | 18 => {
                    require(vlen == 0, "fixed type vlen")?;
                    0
                }
                12 => {
                    require(vlen <= 2, "function linkage")?;
                    0
                }
                4 | 5 | 15 | 19 => vlen
                    .checked_mul(12)
                    .ok_or(KernelLayoutError::Invalid("type size overflow"))?,
                6 | 13 => vlen
                    .checked_mul(8)
                    .ok_or(KernelLayoutError::Invalid("type size overflow"))?,
                _ => return Err(KernelLayoutError::Invalid("unknown BTF kind")),
            };
            let next = offset
                .checked_add(12)
                .and_then(|value| value.checked_add(extra))
                .ok_or(KernelLayoutError::Invalid("record overflow"))?;
            require(next <= types.len(), "truncated type payload")?;
            offsets.push(
                u32::try_from(offset)
                    .map_err(|_| KernelLayoutError::Invalid("type offset budget"))?,
            );
            offset = next;
        }
        Ok(Self {
            types,
            strings,
            offsets,
        })
    }

    fn item(&self, index: usize) -> Result<Type<'a>> {
        let start = *self
            .offsets
            .get(index)
            .ok_or(KernelLayoutError::Invalid("missing type"))? as usize;
        let end = self
            .offsets
            .get(index + 1)
            .map_or(self.types.len(), |offset| *offset as usize);
        Ok(Type {
            name: word(self.types, start)?,
            info: word(self.types, start + 4)?,
            value: word(self.types, start + 8)?,
            extra: &self.types[start + 12..end],
        })
    }
}

pub(super) struct Btf<'a> {
    base: Inventory<'a>,
    module: Option<Inventory<'a>>,
}

impl<'a> Btf<'a> {
    pub fn parse(base: &'a [u8], module: Option<&'a [u8]>) -> Result<Self> {
        let base = Inventory::parse(base, MAX_TYPES, false)?;
        let module = module
            .map(|bytes| Inventory::parse(bytes, MAX_TYPES - base.offsets.len(), true))
            .transpose()?;
        let btf = Self { base, module };
        for inventory in std::iter::once(&btf.base).chain(btf.module.iter()) {
            for index in 0..inventory.offsets.len() {
                let item = inventory.item(index)?;
                if matches!(item.kind(), 17 | 18) {
                    require(
                        !btf.string(item.name)?.is_empty(),
                        "empty attribute/tag name",
                    )?;
                }
            }
        }
        Ok(btf)
    }

    pub fn item(&self, id: u32) -> Result<Type<'a>> {
        let index = id
            .checked_sub(1)
            .ok_or(KernelLayoutError::Invalid("void reference"))? as usize;
        if index < self.base.offsets.len() {
            self.base.item(index)
        } else {
            self.module
                .as_ref()
                .ok_or(KernelLayoutError::Invalid("missing split type"))?
                .item(index - self.base.offsets.len())
        }
    }

    pub fn resolved(&self, mut id: u32) -> Result<Type<'a>> {
        for _ in 0..=8 {
            let item = self.item(id)?;
            if !matches!(item.kind(), 8..=11 | 18) {
                return Ok(item);
            }
            id = item.value;
        }
        Err(KernelLayoutError::Invalid("alias depth/cycle"))
    }

    pub fn string(&self, offset: u32) -> Result<&'a str> {
        let offset = offset as usize;
        let tail = if offset < self.base.strings.len() {
            &self.base.strings[offset..]
        } else {
            self.module
                .as_ref()
                .and_then(|module| module.strings.get(offset - self.base.strings.len()..))
                .ok_or(KernelLayoutError::Invalid("string offset"))?
        };
        let end = tail
            .iter()
            .take(4097)
            .position(|byte| *byte == 0)
            .ok_or(KernelLayoutError::Invalid("string length/terminator"))?;
        std::str::from_utf8(&tail[..end])
            .map_err(|_| KernelLayoutError::Invalid("non UTF-8 identifier"))
    }

    pub fn named(&self, name: &str) -> Result<Vec<u32>> {
        let mut matches = Vec::new();
        let mut start = 1;
        for inventory in std::iter::once(&self.base).chain(self.module.iter()) {
            let mut found = None;
            for index in 0..inventory.offsets.len() {
                let item = inventory.item(index)?;
                if item.kind() == 4 && self.string(item.name)? == name {
                    require(found.is_none(), "ambiguous named structure")?;
                    found = Some(
                        u32::try_from(start + index)
                            .map_err(|_| KernelLayoutError::Invalid("type ID budget"))?,
                    );
                }
            }
            if let Some(id) = found {
                matches.push(id);
            }
            start += inventory.offsets.len();
        }
        require(!matches.is_empty(), "missing named structure")?;
        Ok(matches)
    }
}
