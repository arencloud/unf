use std::os::fd::{AsFd as _, OwnedFd};
use std::sync::Arc;

use anyhow::{Context as _, Result, ensure};
use aya::maps::{Array, Map, MapData, MapType, ProgramArray};
use aya::programs::SchedClassifier;
use unf_ebpf_common::locality::{ABI_VERSION, PlacementFence};
use unf_encryption::EncryptionLocalityContext;

use super::sys::Value;

/// Held exact runtime FDs, not names, shape-only permissions or reopened pins.
/// Construct once per actual runtime. Replacement must fence the old runtime
/// before the CNI server can mutate its journal.
pub struct LocalityRuntimeMaps {
    pub(crate) maps: Arc<RuntimeMaps>,
}

pub(crate) struct RuntimeMaps {
    pub input: MapData,
    pub fence: MapData,
    pub resume: MapData,
    pub dispatch: MapData,
}

impl LocalityRuntimeMaps {
    /// Bind actual maps provided by the loaded policy/Service runtime and
    /// withdraw admission immediately. This does not authenticate arbitrary
    /// caller FDs: the caller owns the runtime and must supply its actual maps.
    ///
    /// # Errors
    /// Rejects incompatible, aliased maps or failure to withdraw old admission.
    pub fn bind(
        input: OwnedFd,
        fence: OwnedFd,
        resume: OwnedFd,
        dispatch: OwnedFd,
    ) -> Result<Self> {
        let maps = RuntimeMaps {
            input: MapData::from_fd(input)?,
            fence: MapData::from_fd(fence)?,
            resume: MapData::from_fd(resume)?,
            dispatch: MapData::from_fd(dispatch)?,
        };
        check_shape(&maps.input, MapType::PerCpuArray, 4, 80, 1, 0)?;
        check_shape(&maps.fence, MapType::Array, 4, 32, 1, 128)?;
        check_shape(&maps.resume, MapType::ProgramArray, 4, 4, 4, 0)?;
        check_shape(&maps.dispatch, MapType::ProgramArray, 4, 4, 1, 0)?;
        let mut ids = [
            maps.input.info()?.id(),
            maps.fence.info()?.id(),
            maps.resume.info()?.id(),
            maps.dispatch.info()?.id(),
        ];
        ids.sort_unstable();
        ensure!(
            ids[0] != 0 && ids.windows(2).all(|p| p[0] != p[1]),
            "aliased locality runtime maps"
        );
        let mut result = Self {
            maps: Arc::new(maps),
        };
        result.withdraw()?;
        Ok(result)
    }

    /// Withdraw BEFORE any applied identity/routing change or journal-serving
    /// runtime replacement. Failure is fatal to publication, not a reason to
    /// continue with the previous bank.
    ///
    /// # Errors
    /// Reports either fence or dispatch failure, attempting both regardless.
    pub fn withdraw(&mut self) -> Result<()> {
        let fence = self.write_fence(PlacementFence {
            identity_epoch: 0,
            identity_revision: 0,
            routing_revision: 0,
            schema_version: 0,
            reserved: [0; 6],
        });
        let dispatch = (|| -> Result<()> {
            let mut map =
                ProgramArray::try_from(Map::ProgramArray(duplicate(&self.maps.dispatch)?))?;
            match map.clear_index(&0) {
                Ok(()) | Err(aya::maps::MapError::KeyNotFound) => Ok(()),
                Err(aya::maps::MapError::SyscallError(error))
                    if error.io_error.kind() == std::io::ErrorKind::NotFound =>
                {
                    Ok(())
                }
                Err(error) => Err(error.into()),
            }
        })();
        match (fence, dispatch) {
            (Ok(()), Ok(())) => Ok(()),
            (fence, dispatch) => {
                anyhow::bail!("locality withdrawal failed: fence={fence:?}, dispatch={dispatch:?}")
            }
        }
    }

    /// Publish fresh applied coordinates only after the identity/routing commit.
    /// This is not a locality grant: exact bank, ownership, leases and route
    /// proof remain required on each packet. Hold the applied-state lock.
    ///
    /// # Errors
    /// Rejects zero coordinates or uncertain fence write/readback. On failure
    /// attempts withdrawal; the caller must stop admission if it also fails.
    pub fn set_applied(&mut self, context: &EncryptionLocalityContext) -> Result<()> {
        let value = PlacementFence {
            identity_epoch: context.identity_epoch,
            identity_revision: context.identity_revision.get(),
            routing_revision: context.routing_revision.get(),
            schema_version: ABI_VERSION,
            reserved: [0; 6],
        };
        ensure!(
            value.identity_epoch != 0
                && value.identity_revision != 0
                && value.routing_revision != 0,
            "invalid locality applied context"
        );
        if let Err(error) = self.write_fence(value) {
            let withdrawal = self.withdraw();
            anyhow::bail!("locality applied fence failed: {error:#}; withdrawal={withdrawal:?}");
        }
        Ok(())
    }

    fn write_fence(&self, value: PlacementFence) -> Result<()> {
        let mut map: Array<_, Value<PlacementFence>> =
            Array::try_from(Map::Array(duplicate(&self.maps.fence)?))?;
        map.set(0, Value(value), 0)?;
        ensure!(
            map.get(&0, 0)?.0 == value,
            "locality fence readback mismatch"
        );
        Ok(())
    }

    pub(super) fn publish(&mut self, classifier: &SchedClassifier) -> Result<u32> {
        let id = classifier.info()?.id();
        let result = (|| -> Result<()> {
            let mut dispatch =
                ProgramArray::try_from(Map::ProgramArray(duplicate(&self.maps.dispatch)?))?;
            dispatch.set(0, classifier.fd()?, 0)?;
            // The UAPI lookup of a program array returns a program ID, not FD.
            // Aya's Array wrapper performs that same fixed-width lookup.
            let readback: Array<_, u32> =
                Array::try_from(Map::Array(duplicate(&self.maps.dispatch)?))?;
            ensure!(
                readback.get(&0, 0)? == id,
                "locality dispatch readback mismatch"
            );
            Ok(())
        })();
        if let Err(error) = result {
            let withdrawal = self.withdraw();
            anyhow::bail!("locality dispatch failed: {error:#}; withdrawal={withdrawal:?}");
        }
        Ok(id)
    }
}

pub(super) fn duplicate(map: &MapData) -> Result<MapData> {
    MapData::from_fd(map.fd().as_fd().try_clone_to_owned()?)
        .context("duplicate actual locality map")
}

pub(super) fn check_shape(
    map: &MapData,
    kind: MapType,
    key: u32,
    value: u32,
    entries: u32,
    flags: u32,
) -> Result<()> {
    let info = map.info()?;
    ensure!(
        info.id() != 0
            && info.map_type()? == kind
            && info.key_size() == key
            && info.value_size() == value
            && info.max_entries() == entries
            && info.map_flags() == flags,
        "incompatible locality map shape"
    );
    Ok(())
}
