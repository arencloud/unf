//! Pinned Aya transaction adapter for the encryption fast-path ABI island.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use aya::Ebpf;
use aya::maps::lpm_trie::Key as AyaLpmKey;
use aya::maps::{
    Array as AyaArray, HashMap as AyaHashMap, IterableMap, LpmTrie as AyaLpmTrie, MapData,
};
use tracing::info;
use unf_ebpf_common::{
    ENCRYPTION_BANK_COUNT, ENCRYPTION_CONNECTION_MAP_CAPACITY,
    ENCRYPTION_DECISION_FLAG_ADDRESS_BOUND, ENCRYPTION_DECISION_MAP_CAPACITY,
    ENCRYPTION_DISPOSITION_NATIVE, ENCRYPTION_DISPOSITION_REQUIRED,
    ENCRYPTION_FLOW_FLAG_ESTABLISHED_LEASE, ENCRYPTION_MAP_ABI_VERSION,
    ENCRYPTION_PATH_MAP_CAPACITY, ENCRYPTION_PATH_PREFIX_BASE_BITS,
    ENCRYPTION_TRANSPORT_FLAG_KERNEL_READBACK, ENCRYPTION_TRANSPORT_MAP_CAPACITY,
    EncryptionDecisionKey, EncryptionDecisionValue, EncryptionIpv4PathData, EncryptionIpv6PathData,
    EncryptionMapConfig, EncryptionPathValue, EncryptionTransportKey, EncryptionTransportValue,
    encryption_route_mark,
};
use unf_encryption::{
    AdmittedEncryptionGeneration, EncryptionActivationMode, EncryptionActivationWitness,
    EncryptionFastPathState, EncryptionGenerationPathProofPermit, EncryptionRoutePublicationPermit,
    FastPathMapCheckpoint, FastPathMapRecoveryAction, FastPathMapTransactionPhase,
    FastPathPublishedGeneration, LinuxPreparedLocalGeneration, PathProvenEncryptionActivationLatch,
};

use super::{load_secure_json, persist_secure_json, reject_node_block_symlinks};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct EncodedEncryptionBank {
    decisions: BTreeMap<[u8; 12], [u8; 72]>,
    transports: BTreeMap<[u8; 16], [u8; 80]>,
    ipv4_paths: BTreeMap<(u32, [u8; 8]), [u8; 48]>,
    ipv6_paths: BTreeMap<(u32, [u8; 20]), [u8; 48]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EncodedEncryptionGeneration {
    bank: EncodedEncryptionBank,
    config: [u8; 48],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct EncryptionMapMutationStats {
    inserted: usize,
    updated: usize,
    removed: usize,
    retained: usize,
}

pub(super) struct EncryptionMaps {
    pub(super) decisions: AyaHashMap<MapData, [u8; 12], [u8; 72]>,
    pub(super) transports: AyaHashMap<MapData, [u8; 16], [u8; 80]>,
    pub(super) ipv4_paths: AyaLpmTrie<MapData, [u8; 8], [u8; 48]>,
    pub(super) ipv6_paths: AyaLpmTrie<MapData, [u8; 20], [u8; 48]>,
    pub(super) config: AyaArray<MapData, [u8; 48]>,
    pub(super) connections: AyaHashMap<MapData, [u8; 40], [u8; 64]>,
}

pub(super) struct EncryptionMapSynchronizer {
    maps: EncryptionMaps,
    state_path: PathBuf,
    active: Option<FastPathMapCheckpoint>,
    pending: Option<FastPathMapCheckpoint>,
    requires_local_revalidation: bool,
}

impl EncryptionMapSynchronizer {
    pub(super) fn recover(
        maps: EncryptionMaps,
        state_path: PathBuf,
        pins_existed: bool,
    ) -> Result<Self> {
        if !state_path.is_absolute() {
            bail!("encryption fast-path state path must be absolute");
        }
        let mut synchronizer = Self {
            maps,
            state_path,
            active: None,
            pending: None,
            requires_local_revalidation: false,
        };
        synchronizer.validate_shapes()?;
        synchronizer.validate_all_entries()?;
        let current = load_optional_checkpoint(&synchronizer.state_path, "encryption fast path")?;
        let pending_path = pending_checkpoint_path(&synchronizer.state_path)?;
        let pending = load_optional_checkpoint(&pending_path, "pending encryption fast path")?;

        if let Some(checkpoint) = &current {
            if checkpoint.transaction.phase != FastPathMapTransactionPhase::Committed {
                bail!("current encryption map checkpoint is not committed");
            }
            checkpoint
                .verify()
                .context("verify current encryption checkpoint")?;
        }
        if let Some(checkpoint) = &pending {
            checkpoint
                .verify()
                .context("verify pending encryption checkpoint")?;
            if checkpoint.transaction.prior
                != current
                    .as_ref()
                    .map(|checkpoint| checkpoint.transaction.desired.published)
            {
                bail!("pending encryption checkpoint does not bind the current generation");
            }
            // A serialized checkpoint cannot replace the Node-local route
            // permit. Keep every unfinished crash boundary inert until a new
            // tri-plane latch revalidates the exact transaction.
            synchronizer.active = current;
            synchronizer.pending = Some(checkpoint.clone());
            synchronizer.requires_local_revalidation = true;
        } else if let Some(checkpoint) = current {
            synchronizer.require_exact_published(&checkpoint)?;
            synchronizer.active = Some(checkpoint);
            synchronizer.requires_local_revalidation = true;
        } else {
            synchronizer.require_quiescent()?;
        }

        if pins_existed {
            info!(
                encryption_map_abi = ENCRYPTION_MAP_ABI_VERSION,
                generation = synchronizer
                    .active
                    .as_ref()
                    .map_or(0, |checkpoint| checkpoint
                        .transaction
                        .desired
                        .published
                        .generation
                        .get()),
                "recovered proof-carrying encryption ABI island"
            );
        }
        Ok(synchronizer)
    }

    pub(super) const fn requires_local_revalidation(&self) -> bool {
        self.requires_local_revalidation
    }

    /// A loaded but empty encryption island is not packet authority. During a
    /// fresh installation or adjacent upgrade, every agent may publish its
    /// Node-local facts while the prior TC program remains attached, but the
    /// new tail-call graph must not become reachable until one complete
    /// proof-carrying generation has committed locally.
    pub(super) const fn has_active_generation(&self) -> bool {
        self.active.is_some() && !self.requires_local_revalidation
    }

    /// Physically removes expired established-flow leases for one retired key
    /// epoch and proves no matching connection entry remains. The active map
    /// generation must already have removed the epoch's transport authority.
    pub(super) fn purge_epoch_connections(&mut self, epoch: u64) -> Result<u64> {
        if epoch == 0 {
            bail!("cannot purge the zero encryption epoch");
        }
        if self.pending.is_some() || self.requires_local_revalidation {
            bail!("cannot retire encryption connections across an unsettled map boundary");
        }
        let active = self
            .active
            .as_ref()
            .context("cannot retire encryption connections without an active checkpoint")?;
        let state = active.desired_state()?;
        if state
            .transports
            .iter()
            .any(|(_, transport)| transport.key_epoch == epoch)
        {
            bail!("active encryption transport still references the retiring epoch");
        }
        let keys = self
            .maps
            .connections
            .iter()
            .map(|entry| {
                let (key, value) = entry.context("scan retiring encryption connections")?;
                validate_connection_entry(&key, &value)?;
                Ok((
                    key,
                    u64::from_ne_bytes(value[16..24].try_into().expect("fixed key epoch")),
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let mut removed = 0_u64;
        for (key, key_epoch) in keys {
            if key_epoch == epoch {
                self.maps.connections.remove(&key)?;
                removed = removed.saturating_add(1);
            }
        }
        for entry in &self.maps.connections {
            let (_, value) = entry.context("prove retired encryption connection absence")?;
            if u64::from_ne_bytes(value[16..24].try_into().expect("fixed key epoch")) == epoch {
                bail!("retired encryption connection survived exact purge");
            }
        }
        Ok(removed)
    }

    /// Completes the real Linux route-before-Aya transition from one exact
    /// kernel-converged Node capability. Controller substitution and route
    /// drift fail before this adapter can mutate the inactive map bank.
    pub(super) fn apply_linux_generation(
        &mut self,
        prepared: LinuxPreparedLocalGeneration,
        admitted: AdmittedEncryptionGeneration,
        route_permit: EncryptionRoutePublicationPermit,
        path_permit: EncryptionGenerationPathProofPermit,
        now_unix_ms: u64,
    ) -> Result<()> {
        let prior = self
            .active
            .as_ref()
            .map(|checkpoint| checkpoint.transaction.desired.published);
        let convergence_witness = prepared.witness();
        let latch = prepared
            .admit_and_activate_linux_path_proven(
                admitted,
                prior,
                route_permit,
                path_permit,
                now_unix_ms,
            )
            .context("activate exact Node-local Linux encryption generation")?;
        self.apply_path_proven(latch, now_unix_ms)?;
        info!(
            convergence_witness = ?convergence_witness.0,
            "Node-local WireGuard, policy routes, and Aya generation converged"
        );
        Ok(())
    }

    fn apply_path_proven(
        &mut self,
        latch: PathProvenEncryptionActivationLatch,
        now_unix_ms: u64,
    ) -> Result<()> {
        let prior = self
            .active
            .as_ref()
            .map(|checkpoint| checkpoint.transaction.desired.published);
        let witness = latch.activation_witness();
        let path_witness = latch.path_witness();
        let material = latch
            .open(prior, self.pending.as_ref(), now_unix_ms)
            .context("open path-proven encryption activation latch")?;
        info!(path_witness = ?path_witness.0, "current duplex path quorum consumed at map boundary");
        self.apply_material(material, witness)
    }

    fn apply_material(
        &mut self,
        material: unf_encryption::EncryptionActivationMaterial,
        witness: EncryptionActivationWitness,
    ) -> Result<()> {
        let (distributed_checkpoint, desired, route_permit, mode) = material.into_parts();
        route_permit
            .verify_for(&desired)
            .context("reverify route-before-authority publication permit")?;
        if mode == EncryptionActivationMode::RevalidateCurrent {
            if self.pending.is_some() {
                bail!("current-generation revalidation cannot bypass a pending transaction");
            }
            let active = self
                .active
                .as_ref()
                .context("current-generation revalidation has no active checkpoint")?;
            self.require_exact_published(active)?;
            self.requires_local_revalidation = false;
            info!(
                activation_witness = ?witness.0,
                generation = desired.config.generation,
                "tri-plane encryption authority revalidated after restart"
            );
            return Ok(());
        }
        let pending_path = pending_checkpoint_path(&self.state_path)?;
        let checkpoint = if self.pending.is_some() {
            distributed_checkpoint
        } else {
            match fs::symlink_metadata(&pending_path) {
                Ok(_) => bail!("untracked pending encryption transaction is quarantined"),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error).context("inspect pending encryption transaction"),
            }
            persist_secure_json(
                &pending_path,
                &distributed_checkpoint,
                "pending encryption fast path",
            )?;
            distributed_checkpoint
        };
        let current = self.active.clone();
        if let Err(error) = self.recover_pending(current.as_ref(), checkpoint, &pending_path) {
            self.pending =
                load_optional_checkpoint(&pending_path, "failed pending encryption fast path")?;
            self.requires_local_revalidation = true;
            return Err(error);
        }
        self.active = load_optional_checkpoint(&self.state_path, "applied encryption fast path")?;
        self.pending = None;
        self.requires_local_revalidation = false;
        info!(
            activation_witness = ?witness.0,
            generation = desired.config.generation,
            "tri-plane encryption activation committed"
        );
        Ok(())
    }

    fn recover_pending(
        &mut self,
        current: Option<&FastPathMapCheckpoint>,
        mut pending: FastPathMapCheckpoint,
        pending_path: &Path,
    ) -> Result<()> {
        let desired = pending
            .desired_state()
            .context("rebuild desired map image")?;
        let desired_encoded = encode_generation(&desired)?;
        let target_bank = pending.transaction.desired.published.bank;
        let observed_target = self.read_bank(target_bank)?;
        let observed_target_digest = if observed_target == desired_encoded.bank {
            Some(desired.state_digest)
        } else if observed_target == EncodedEncryptionBank::default() {
            None
        } else {
            let mut mismatch = desired.state_digest;
            mismatch.0[0] ^= u8::MAX;
            Some(mismatch)
        };
        let config = self
            .maps
            .config
            .get(&0, 0)
            .context("read encryption map config during recovery")?;
        let observed_active =
            self.observed_active_generation(config, current, &pending, &desired_encoded)?;
        let action = pending
            .transaction
            .recover(observed_active, observed_target_digest)
            .context("select encryption map recovery action")?;

        match action {
            FastPathMapRecoveryAction::ClearAndRestageInactive => {
                let stats = self.reconcile_bank(target_bank, &desired_encoded.bank)?;
                self.require_exact_bank(target_bank, &desired_encoded.bank)?;
                info!(
                    bank = target_bank,
                    inserted = stats.inserted,
                    updated = stats.updated,
                    removed = stats.removed,
                    retained = stats.retained,
                    "causal delta staged encryption map bank"
                );
                pending.record_staged(&desired)?;
                persist_secure_json(pending_path, &pending, "staged encryption fast path")?;
                self.activate_and_commit(&mut pending, &desired, &desired_encoded, pending_path)
            }
            FastPathMapRecoveryAction::ActivateDesired => {
                self.activate_and_commit(&mut pending, &desired, &desired_encoded, pending_path)
            }
            FastPathMapRecoveryAction::CommitObservedDesired => {
                if pending.transaction.phase == FastPathMapTransactionPhase::Prepared {
                    pending.record_staged(&desired)?;
                    persist_secure_json(
                        pending_path,
                        &pending,
                        "recovered staged encryption fast path",
                    )?;
                }
                pending.commit(&desired)?;
                persist_secure_json(pending_path, &pending, "committed encryption fast path")?;
                commit_pending_checkpoint(&self.state_path, pending_path)
            }
            FastPathMapRecoveryAction::ReuseCommitted => {
                commit_pending_checkpoint(&self.state_path, pending_path)
            }
            FastPathMapRecoveryAction::RollbackComplete => remove_checkpoint(pending_path),
            FastPathMapRecoveryAction::RefuseUnknownState => {
                bail!("encryption map/checkpoint state has no safe recovery action")
            }
        }
    }

    fn activate_and_commit(
        &mut self,
        pending: &mut FastPathMapCheckpoint,
        desired: &EncryptionFastPathState,
        encoded: &EncodedEncryptionGeneration,
        pending_path: &Path,
    ) -> Result<()> {
        self.maps
            .config
            .set(0, encoded.config, 0)
            .context("activate encryption map bank")?;
        self.require_exact_published(pending)?;
        pending.commit(desired)?;
        persist_secure_json(pending_path, pending, "committed encryption fast path")?;
        commit_pending_checkpoint(&self.state_path, pending_path)
    }

    fn observed_active_generation(
        &self,
        observed_config: [u8; 48],
        current: Option<&FastPathMapCheckpoint>,
        pending: &FastPathMapCheckpoint,
        desired: &EncodedEncryptionGeneration,
    ) -> Result<Option<FastPathPublishedGeneration>> {
        if observed_config == desired.config
            && self.read_bank(pending.transaction.desired.published.bank)? == desired.bank
        {
            return Ok(Some(pending.transaction.desired.published));
        }
        if let Some(current) = current {
            let current_state = current.desired_state()?;
            let current_encoded = encode_generation(&current_state)?;
            if observed_config == current_encoded.config
                && self.read_bank(current_state.config.active_bank)? == current_encoded.bank
            {
                return Ok(Some(current.transaction.desired.published));
            }
        } else if observed_config == [0; 48] {
            return Ok(None);
        }
        bail!("published encryption map state does not match current or desired checkpoint")
    }

    fn require_exact_published(&self, checkpoint: &FastPathMapCheckpoint) -> Result<()> {
        checkpoint.verify()?;
        let state = checkpoint.desired_state()?;
        let encoded = encode_generation(&state)?;
        let observed = self
            .maps
            .config
            .get(&0, 0)
            .context("read published encryption map config")?;
        if observed != encoded.config {
            bail!("published encryption config differs from its durable checkpoint");
        }
        self.require_exact_bank(state.config.active_bank, &encoded.bank)
    }

    fn require_quiescent(&self) -> Result<()> {
        let config = self
            .maps
            .config
            .get(&0, 0)
            .context("read encryption quarantine config")?;
        if config != [0; 48]
            || self.read_bank(0)? != EncodedEncryptionBank::default()
            || self.read_bank(1)? != EncodedEncryptionBank::default()
            || self.maps.connections.iter().next().transpose()?.is_some()
        {
            bail!(
                "encryption ABI island contains state without a proof-carrying checkpoint; refusing startup"
            );
        }
        Ok(())
    }

    fn validate_shapes(&self) -> Result<()> {
        validate_capacity(
            "ENCRYPTION_DECISIONS",
            self.maps.decisions.map(),
            ENCRYPTION_DECISION_MAP_CAPACITY,
        )?;
        validate_capacity(
            "ENCRYPTION_TRANSPORTS",
            self.maps.transports.map(),
            ENCRYPTION_TRANSPORT_MAP_CAPACITY,
        )?;
        validate_capacity(
            "ENCRYPTION_PATHS_V4",
            self.maps.ipv4_paths.map(),
            ENCRYPTION_PATH_MAP_CAPACITY,
        )?;
        validate_capacity(
            "ENCRYPTION_PATHS_V6",
            self.maps.ipv6_paths.map(),
            ENCRYPTION_PATH_MAP_CAPACITY,
        )?;
        validate_capacity("ENCRYPTION_CONFIG", self.maps.config.map(), 1)?;
        validate_capacity(
            "ENCRYPTION_CONNECTIONS",
            self.maps.connections.map(),
            ENCRYPTION_CONNECTION_MAP_CAPACITY,
        )
    }

    fn validate_all_entries(&self) -> Result<()> {
        for entry in &self.maps.decisions {
            let (key, value) = entry.context("iterate persistent encryption decisions")?;
            validate_decision_entry(&key, &value)?;
        }
        for entry in &self.maps.transports {
            let (key, value) = entry.context("iterate persistent encryption transports")?;
            validate_transport_entry(&key, &value)?;
        }
        for entry in &self.maps.ipv4_paths {
            let (key, value) = entry.context("iterate persistent IPv4 encryption paths")?;
            validate_path_entry(key.prefix_len(), &key.data(), &value, 32)?;
        }
        for entry in &self.maps.ipv6_paths {
            let (key, value) = entry.context("iterate persistent IPv6 encryption paths")?;
            validate_path_entry(key.prefix_len(), &key.data(), &value, 128)?;
        }
        for entry in &self.maps.connections {
            let (key, value) = entry.context("iterate persistent encryption connections")?;
            validate_connection_entry(&key, &value)?;
        }
        Ok(())
    }

    fn read_bank(&self, bank: u8) -> Result<EncodedEncryptionBank> {
        if bank >= ENCRYPTION_BANK_COUNT {
            bail!("invalid encryption map bank {bank}");
        }
        let mut observed = EncodedEncryptionBank::default();
        for entry in &self.maps.decisions {
            let (key, value) = entry.context("read encryption decision bank")?;
            if key[8] == bank {
                observed.decisions.insert(key, value);
            }
        }
        for entry in &self.maps.transports {
            let (key, value) = entry.context("read encryption transport bank")?;
            if key[8] == bank {
                observed.transports.insert(key, value);
            }
        }
        for entry in &self.maps.ipv4_paths {
            let (key, value) = entry.context("read IPv4 encryption path bank")?;
            let data = key.data();
            if data[0] == bank {
                observed.ipv4_paths.insert((key.prefix_len(), data), value);
            }
        }
        for entry in &self.maps.ipv6_paths {
            let (key, value) = entry.context("read IPv6 encryption path bank")?;
            let data = key.data();
            if data[0] == bank {
                observed.ipv6_paths.insert((key.prefix_len(), data), value);
            }
        }
        Ok(observed)
    }

    fn require_exact_bank(&self, bank: u8, expected: &EncodedEncryptionBank) -> Result<()> {
        if self.read_bank(bank)? != *expected {
            bail!("encryption map bank {bank} differs from its proof-carrying mirror");
        }
        Ok(())
    }

    fn reconcile_bank(
        &mut self,
        bank: u8,
        desired: &EncodedEncryptionBank,
    ) -> Result<EncryptionMapMutationStats> {
        let current = self.read_bank(bank)?;
        let mut stats = EncryptionMapMutationStats::default();
        for key in current.decisions.keys() {
            if !desired.decisions.contains_key(key) {
                self.maps.decisions.remove(key)?;
                stats.removed += 1;
            }
        }
        for key in current.transports.keys() {
            if !desired.transports.contains_key(key) {
                self.maps.transports.remove(key)?;
                stats.removed += 1;
            }
        }
        for (prefix, key) in current.ipv4_paths.keys() {
            if !desired.ipv4_paths.contains_key(&(*prefix, *key)) {
                self.maps
                    .ipv4_paths
                    .remove(&AyaLpmKey::new(*prefix, *key))?;
                stats.removed += 1;
            }
        }
        for (prefix, key) in current.ipv6_paths.keys() {
            if !desired.ipv6_paths.contains_key(&(*prefix, *key)) {
                self.maps
                    .ipv6_paths
                    .remove(&AyaLpmKey::new(*prefix, *key))?;
                stats.removed += 1;
            }
        }
        for (key, value) in &desired.decisions {
            match current.decisions.get(key) {
                Some(current) if current == value => stats.retained += 1,
                Some(_) => {
                    self.maps.decisions.insert(key, value, 0)?;
                    stats.updated += 1;
                }
                None => {
                    self.maps.decisions.insert(key, value, 0)?;
                    stats.inserted += 1;
                }
            }
        }
        for (key, value) in &desired.transports {
            match current.transports.get(key) {
                Some(current) if current == value => stats.retained += 1,
                Some(_) => {
                    self.maps.transports.insert(key, value, 0)?;
                    stats.updated += 1;
                }
                None => {
                    self.maps.transports.insert(key, value, 0)?;
                    stats.inserted += 1;
                }
            }
        }
        for ((prefix, key), value) in &desired.ipv4_paths {
            match current.ipv4_paths.get(&(*prefix, *key)) {
                Some(current) if current == value => stats.retained += 1,
                Some(_) => {
                    self.maps
                        .ipv4_paths
                        .insert(&AyaLpmKey::new(*prefix, *key), value, 0)?;
                    stats.updated += 1;
                }
                None => {
                    self.maps
                        .ipv4_paths
                        .insert(&AyaLpmKey::new(*prefix, *key), value, 0)?;
                    stats.inserted += 1;
                }
            }
        }
        for ((prefix, key), value) in &desired.ipv6_paths {
            match current.ipv6_paths.get(&(*prefix, *key)) {
                Some(current) if current == value => stats.retained += 1,
                Some(_) => {
                    self.maps
                        .ipv6_paths
                        .insert(&AyaLpmKey::new(*prefix, *key), value, 0)?;
                    stats.updated += 1;
                }
                None => {
                    self.maps
                        .ipv6_paths
                        .insert(&AyaLpmKey::new(*prefix, *key), value, 0)?;
                    stats.inserted += 1;
                }
            }
        }
        Ok(stats)
    }
}

pub(super) fn take_encryption_maps(ebpf: &mut Ebpf) -> Result<EncryptionMaps> {
    let decisions = AyaHashMap::<_, [u8; 12], [u8; 72]>::try_from(
        ebpf.take_map("ENCRYPTION_DECISIONS")
            .context("eBPF object does not contain ENCRYPTION_DECISIONS map")?,
    )
    .context("open ENCRYPTION_DECISIONS map")?;
    let transports = AyaHashMap::<_, [u8; 16], [u8; 80]>::try_from(
        ebpf.take_map("ENCRYPTION_TRANSPORTS")
            .context("eBPF object does not contain ENCRYPTION_TRANSPORTS map")?,
    )
    .context("open ENCRYPTION_TRANSPORTS map")?;
    let ipv4_paths = AyaLpmTrie::<_, [u8; 8], [u8; 48]>::try_from(
        ebpf.take_map("ENCRYPTION_PATHS_V4")
            .context("eBPF object does not contain ENCRYPTION_PATHS_V4 map")?,
    )
    .context("open ENCRYPTION_PATHS_V4 map")?;
    let ipv6_paths = AyaLpmTrie::<_, [u8; 20], [u8; 48]>::try_from(
        ebpf.take_map("ENCRYPTION_PATHS_V6")
            .context("eBPF object does not contain ENCRYPTION_PATHS_V6 map")?,
    )
    .context("open ENCRYPTION_PATHS_V6 map")?;
    let config = AyaArray::<_, [u8; 48]>::try_from(
        ebpf.take_map("ENCRYPTION_CONFIG")
            .context("eBPF object does not contain ENCRYPTION_CONFIG map")?,
    )
    .context("open ENCRYPTION_CONFIG map")?;
    let connections = AyaHashMap::<_, [u8; 40], [u8; 64]>::try_from(
        ebpf.take_map("ENCRYPTION_CONNECTIONS")
            .context("eBPF object does not contain ENCRYPTION_CONNECTIONS map")?,
    )
    .context("open ENCRYPTION_CONNECTIONS map")?;
    Ok(EncryptionMaps {
        decisions,
        transports,
        ipv4_paths,
        ipv6_paths,
        config,
        connections,
    })
}

fn encode_generation(state: &EncryptionFastPathState) -> Result<EncodedEncryptionGeneration> {
    state
        .verify_integrity()
        .context("verify encryption map state")?;
    let mut bank = EncodedEncryptionBank::default();
    for (key, value) in &state.decisions {
        let key = encode_decision_key(key);
        if key[8] != state.config.active_bank
            || bank
                .decisions
                .insert(key, encode_decision_value(value))
                .is_some()
        {
            bail!("desired encryption decisions contain duplicate or foreign state");
        }
    }
    for (key, value) in &state.transports {
        let key = encode_transport_key(key);
        if key[8] != state.config.active_bank
            || bank
                .transports
                .insert(key, encode_transport_value(value))
                .is_some()
        {
            bail!("desired encryption transports contain duplicate or foreign state");
        }
    }
    for (prefix, data, value) in &state.ipv4_paths {
        let key = encode_ipv4_path_data(*data);
        let prefix = ENCRYPTION_PATH_PREFIX_BASE_BITS + prefix;
        if key[0] != state.config.active_bank
            || bank
                .ipv4_paths
                .insert((prefix, key), encode_path_value(value))
                .is_some()
        {
            bail!("desired encryption paths contain duplicate or foreign IPv4 state");
        }
    }
    for (prefix, data, value) in &state.ipv6_paths {
        let key = encode_ipv6_path_data(data);
        let prefix = ENCRYPTION_PATH_PREFIX_BASE_BITS + prefix;
        if key[0] != state.config.active_bank
            || bank
                .ipv6_paths
                .insert((prefix, key), encode_path_value(value))
                .is_some()
        {
            bail!("desired encryption paths contain duplicate or foreign IPv6 state");
        }
    }
    Ok(EncodedEncryptionGeneration {
        bank,
        config: encode_map_config(&state.config),
    })
}

pub(super) fn encode_decision_key(key: &EncryptionDecisionKey) -> [u8; 12] {
    let mut encoded = [0; 12];
    encoded[0..4].copy_from_slice(&key.source_identity.get().to_ne_bytes());
    encoded[4..8].copy_from_slice(&key.destination_identity.get().to_ne_bytes());
    encoded[8] = key.bank;
    encoded[9..12].copy_from_slice(&key.reserved);
    encoded
}

pub(super) fn encode_decision_value(value: &EncryptionDecisionValue) -> [u8; 72] {
    let mut encoded = [0; 72];
    for (index, field) in [
        value.transport_id,
        value.contract_revision,
        value.policy_revision,
        value.service_revision,
        value.egress_revision,
        value.key_epoch,
    ]
    .into_iter()
    .enumerate()
    {
        encoded[index * 8..index * 8 + 8].copy_from_slice(&field.to_ne_bytes());
    }
    encoded[48..64].copy_from_slice(&value.decision_witness);
    encoded[64..66].copy_from_slice(&value.schema_version.to_ne_bytes());
    encoded[66] = value.disposition;
    encoded[67] = value.flags;
    encoded
}

pub(super) fn encode_transport_key(key: &EncryptionTransportKey) -> [u8; 16] {
    let mut encoded = [0; 16];
    encoded[0..8].copy_from_slice(&key.transport_id.to_ne_bytes());
    encoded[8] = key.bank;
    encoded[9..16].copy_from_slice(&key.reserved);
    encoded
}

pub(super) fn encode_transport_value(value: &EncryptionTransportValue) -> [u8; 80] {
    let mut encoded = [0; 80];
    for (index, field) in [
        value.key_epoch,
        value.contract_revision,
        value.drain_until_monotonic_ns,
    ]
    .into_iter()
    .enumerate()
    {
        encoded[index * 8..index * 8 + 8].copy_from_slice(&field.to_ne_bytes());
    }
    for (index, field) in [
        value.fwmark,
        value.route_table,
        value.interface_index,
        value.mtu,
    ]
    .into_iter()
    .enumerate()
    {
        encoded[24 + index * 4..28 + index * 4].copy_from_slice(&field.to_ne_bytes());
    }
    encoded[40..56].copy_from_slice(&value.kernel_configuration_digest);
    encoded[56..72].copy_from_slice(&value.readiness_digest);
    encoded[72..74].copy_from_slice(&value.schema_version.to_ne_bytes());
    encoded[74] = value.state;
    encoded[75] = value.flags;
    encoded[76..80].copy_from_slice(&value.reserved);
    encoded
}

pub(super) fn encode_ipv4_path_data(value: EncryptionIpv4PathData) -> [u8; 8] {
    let mut encoded = [0; 8];
    encoded[0] = value.bank;
    encoded[1..4].copy_from_slice(&value.reserved);
    encoded[4..8].copy_from_slice(&value.destination_address);
    encoded
}

pub(super) fn encode_ipv6_path_data(value: &EncryptionIpv6PathData) -> [u8; 20] {
    let mut encoded = [0; 20];
    encoded[0] = value.bank;
    encoded[1..4].copy_from_slice(&value.reserved);
    encoded[4..20].copy_from_slice(&value.destination_address);
    encoded
}

pub(super) fn encode_path_value(value: &EncryptionPathValue) -> [u8; 48] {
    let mut encoded = [0; 48];
    for (index, field) in [value.transport_id, value.contract_revision, value.key_epoch]
        .into_iter()
        .enumerate()
    {
        encoded[index * 8..index * 8 + 8].copy_from_slice(&field.to_ne_bytes());
    }
    encoded[24..40].copy_from_slice(&value.binding_witness);
    encoded[40..42].copy_from_slice(&value.schema_version.to_ne_bytes());
    encoded[42] = value.flags;
    encoded[43..48].copy_from_slice(&value.reserved);
    encoded
}

pub(super) fn encode_map_config(value: &EncryptionMapConfig) -> [u8; 48] {
    let mut encoded = [0; 48];
    for (index, field) in [
        value.generation,
        value.policy_revision,
        value.service_revision,
        value.egress_revision,
    ]
    .into_iter()
    .enumerate()
    {
        encoded[index * 8..index * 8 + 8].copy_from_slice(&field.to_ne_bytes());
    }
    encoded[32..36].copy_from_slice(&value.decision_count.to_ne_bytes());
    encoded[36..40].copy_from_slice(&value.transport_count.to_ne_bytes());
    encoded[40..42].copy_from_slice(&value.schema_version.to_ne_bytes());
    encoded[42] = value.active_bank;
    encoded[43] = value.epoch_count;
    encoded[44..48].copy_from_slice(&value.path_count.to_ne_bytes());
    encoded
}

fn validate_decision_entry(key: &[u8; 12], value: &[u8; 72]) -> Result<()> {
    let disposition = value[66];
    let transport = u64::from_ne_bytes(value[0..8].try_into().expect("fixed transport ID"));
    let contract = u64::from_ne_bytes(value[8..16].try_into().expect("fixed contract revision"));
    let epoch = u64::from_ne_bytes(value[40..48].try_into().expect("fixed key epoch"));
    if key[8] >= ENCRYPTION_BANK_COUNT
        || key[0..4] == [0; 4]
        || key[4..8] == [0; 4]
        || key[9..12] != [0; 3]
        || value[16..40].chunks_exact(8).any(|field| field == [0; 8])
        || value[48..64] == [0; 16]
        || u16::from_ne_bytes(value[64..66].try_into().expect("fixed decision schema"))
            != ENCRYPTION_MAP_ABI_VERSION
        || !matches!(
            disposition,
            ENCRYPTION_DISPOSITION_NATIVE | ENCRYPTION_DISPOSITION_REQUIRED
        )
        || !matches!(
            value[67],
            flags if flags
                == unf_ebpf_common::ENCRYPTION_DECISION_FLAG_POLICY_AUTHORIZED
                    | unf_ebpf_common::ENCRYPTION_DECISION_FLAG_SELECTION_BOUND
                || flags
                    == unf_ebpf_common::ENCRYPTION_DECISION_FLAG_POLICY_AUTHORIZED
                        | unf_ebpf_common::ENCRYPTION_DECISION_FLAG_SELECTION_BOUND
                        | ENCRYPTION_DECISION_FLAG_ADDRESS_BOUND
        )
        || value[68..72] != [0; 4]
        || (disposition == ENCRYPTION_DISPOSITION_NATIVE
            && (transport != 0 || contract != 0 || epoch != 0))
        || (disposition == ENCRYPTION_DISPOSITION_REQUIRED
            && (contract == 0
                || epoch == 0
                || (value[67] & ENCRYPTION_DECISION_FLAG_ADDRESS_BOUND == 0) == (transport == 0)))
    {
        bail!("persistent encryption decision entry is incompatible");
    }
    Ok(())
}

fn validate_path_entry(prefix: u32, key: &[u8], value: &[u8; 48], family_bits: u32) -> Result<()> {
    let address_prefix = prefix.saturating_sub(ENCRYPTION_PATH_PREFIX_BASE_BITS);
    if key.len() != usize::try_from(4 + family_bits / 8).expect("bounded address family")
        || prefix < ENCRYPTION_PATH_PREFIX_BASE_BITS
        || prefix > ENCRYPTION_PATH_PREFIX_BASE_BITS + family_bits
        || key[0] >= ENCRYPTION_BANK_COUNT
        || key[1..4] != [0; 3]
        || value[0..24].chunks_exact(8).any(|field| field == [0; 8])
        || value[24..40] == [0; 16]
        || u16::from_ne_bytes(value[40..42].try_into().expect("fixed path schema"))
            != ENCRYPTION_MAP_ABI_VERSION
        || value[42..48] != [0; 6]
        || !prefix_bytes_are_canonical(&key[4..], address_prefix)
    {
        bail!("persistent encryption path entry is incompatible");
    }
    Ok(())
}

fn prefix_bytes_are_canonical(address: &[u8], prefix_len: u32) -> bool {
    address.iter().enumerate().all(|(index, byte)| {
        let first_bit = u32::try_from(index).unwrap_or(u32::MAX) * 8;
        if first_bit + 8 <= prefix_len {
            true
        } else if first_bit >= prefix_len {
            *byte == 0
        } else {
            let retained = prefix_len - first_bit;
            let mask = u8::MAX << (8 - retained);
            *byte & !mask == 0
        }
    })
}

fn validate_transport_entry(key: &[u8; 16], value: &[u8; 80]) -> Result<()> {
    let drain_until = u64::from_ne_bytes(value[16..24].try_into().expect("fixed drain deadline"));
    let fwmark = u32::from_ne_bytes(value[24..28].try_into().expect("fixed outer fwmark"));
    let state = value[74];
    if key[0..8] == [0; 8]
        || key[8] >= ENCRYPTION_BANK_COUNT
        || key[9..16] != [0; 7]
        || value[0..16].chunks_exact(8).any(|field| field == [0; 8])
        || encryption_route_mark(fwmark).is_none()
        || value[28..40].chunks_exact(4).any(|field| field == [0; 4])
        || value[40..56] == [0; 16]
        || value[56..72] == [0; 16]
        || u16::from_ne_bytes(value[72..74].try_into().expect("fixed transport schema"))
            != ENCRYPTION_MAP_ABI_VERSION
        || !matches!(
            state,
            unf_ebpf_common::ENCRYPTION_TRANSPORT_ACTIVE
                | unf_ebpf_common::ENCRYPTION_TRANSPORT_DRAINING
        )
        || (state == unf_ebpf_common::ENCRYPTION_TRANSPORT_ACTIVE && drain_until != 0)
        || (state == unf_ebpf_common::ENCRYPTION_TRANSPORT_DRAINING && drain_until == 0)
        || value[75] != ENCRYPTION_TRANSPORT_FLAG_KERNEL_READBACK
        || value[76..80] != [0; 4]
    {
        bail!("persistent encryption transport entry is incompatible");
    }
    Ok(())
}

fn validate_connection_entry(key: &[u8; 40], value: &[u8; 64]) -> Result<()> {
    if !matches!(key[36], 6 | 17 | 132)
        || !matches!(key[37], 4 | 6)
        || key[38..40] != [0; 2]
        || value[0..8] == [0; 8]
        || value[8..32].chunks_exact(8).any(|field| field == [0; 8])
        || value[40..56] == [0; 16]
        || u16::from_ne_bytes(value[56..58].try_into().expect("fixed CEL schema"))
            != ENCRYPTION_MAP_ABI_VERSION
        || value[58] != ENCRYPTION_FLOW_FLAG_ESTABLISHED_LEASE
        || value[59..64] != [0; 5]
    {
        bail!("persistent encryption connection entry is incompatible");
    }
    Ok(())
}

fn validate_capacity(name: &str, map: &MapData, expected: u32) -> Result<()> {
    let observed = map
        .info()
        .with_context(|| format!("inspect persistent {name} map"))?
        .max_entries();
    if observed != expected {
        bail!("persistent {name} capacity is {observed}; expected {expected}");
    }
    Ok(())
}

fn pending_checkpoint_path(path: &Path) -> Result<PathBuf> {
    let file_name = path
        .file_name()
        .context("encryption fast-path state path must name a file")?
        .to_string_lossy();
    Ok(path.with_file_name(format!("{file_name}.pending")))
}

fn load_optional_checkpoint(
    path: &Path,
    description: &str,
) -> Result<Option<FastPathMapCheckpoint>> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("inspect {description} checkpoint")),
        Ok(_) => {
            let checkpoint = load_secure_json(path, description)?;
            FastPathMapCheckpoint::verify(&checkpoint)
                .with_context(|| format!("verify {description} checkpoint"))?;
            Ok(Some(checkpoint))
        }
    }
}

fn commit_pending_checkpoint(current: &Path, pending: &Path) -> Result<()> {
    reject_node_block_symlinks(current)?;
    reject_node_block_symlinks(pending)?;
    let parent = current
        .parent()
        .context("encryption checkpoint path has no parent")?;
    fs::rename(pending, current).with_context(|| {
        format!(
            "commit pending encryption checkpoint {} to {}",
            pending.display(),
            current.display()
        )
    })?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn remove_checkpoint(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("inspect encryption checkpoint for removal"),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            bail!("encryption checkpoint removal target is not a regular file")
        }
        Ok(_) => {
            fs::remove_file(path).context("remove encryption checkpoint")?;
            File::open(
                path.parent()
                    .context("encryption checkpoint has no parent")?,
            )?
            .sync_all()?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aya::EbpfLoader;
    use tempfile::tempdir;
    use unf_common::IdentityId;
    use unf_ebpf_common::{
        ENCRYPTION_DECISION_FLAG_POLICY_AUTHORIZED, ENCRYPTION_DECISION_FLAG_SELECTION_BOUND,
        ENCRYPTION_TRANSPORT_ACTIVE,
    };

    #[test]
    fn fixed_width_encoding_matches_the_shared_encryption_abi() {
        let decision_key = EncryptionDecisionKey {
            source_identity: IdentityId::new(11),
            destination_identity: IdentityId::new(21),
            bank: 1,
            reserved: [0; 3],
        };
        let decision_value = EncryptionDecisionValue {
            transport_id: 41,
            contract_revision: 42,
            policy_revision: 43,
            service_revision: 44,
            egress_revision: 45,
            key_epoch: 46,
            decision_witness: [7; 16],
            schema_version: ENCRYPTION_MAP_ABI_VERSION,
            disposition: ENCRYPTION_DISPOSITION_REQUIRED,
            flags: ENCRYPTION_DECISION_FLAG_POLICY_AUTHORIZED
                | ENCRYPTION_DECISION_FLAG_SELECTION_BOUND,
        };
        let key = encode_decision_key(&decision_key);
        let value = encode_decision_value(&decision_value);
        assert_eq!(u32::from_ne_bytes(key[0..4].try_into().unwrap()), 11);
        assert_eq!(u32::from_ne_bytes(key[4..8].try_into().unwrap()), 21);
        assert_eq!(key[8], 1);
        assert_eq!(u64::from_ne_bytes(value[0..8].try_into().unwrap()), 41);
        assert_eq!(u64::from_ne_bytes(value[40..48].try_into().unwrap()), 46);
        assert_eq!(value[68..72], [0; 4]);
        validate_decision_entry(&key, &value).unwrap();

        let transport_key = EncryptionTransportKey {
            transport_id: 41,
            bank: 1,
            reserved: [0; 7],
        };
        let transport_value = EncryptionTransportValue {
            key_epoch: 46,
            contract_revision: 42,
            drain_until_monotonic_ns: 0,
            fwmark: 0x0055_0100,
            route_table: 20_001,
            interface_index: 7,
            mtu: 1_420,
            kernel_configuration_digest: [8; 16],
            readiness_digest: [9; 16],
            schema_version: ENCRYPTION_MAP_ABI_VERSION,
            state: ENCRYPTION_TRANSPORT_ACTIVE,
            flags: ENCRYPTION_TRANSPORT_FLAG_KERNEL_READBACK,
            reserved: [0; 4],
        };
        let key = encode_transport_key(&transport_key);
        let value = encode_transport_value(&transport_value);
        assert_eq!(
            u32::from_ne_bytes(value[24..28].try_into().unwrap()),
            0x0055_0100
        );
        assert_eq!(u32::from_ne_bytes(value[36..40].try_into().unwrap()), 1_420);
        validate_transport_entry(&key, &value).unwrap();

        let path_data = EncryptionIpv4PathData {
            bank: 1,
            reserved: [0; 3],
            destination_address: [10, 42, 2, 0],
        };
        let path_value = EncryptionPathValue {
            transport_id: 41,
            contract_revision: 42,
            key_epoch: 46,
            binding_witness: [10; 16],
            schema_version: ENCRYPTION_MAP_ABI_VERSION,
            flags: 0,
            reserved: [0; 5],
        };
        let key = encode_ipv4_path_data(path_data);
        let value = encode_path_value(&path_value);
        assert_eq!(key, [1, 0, 0, 0, 10, 42, 2, 0]);
        assert_eq!(u64::from_ne_bytes(value[0..8].try_into().unwrap()), 41);
        validate_path_entry(ENCRYPTION_PATH_PREFIX_BASE_BITS + 24, &key, &value, 32).unwrap();

        let config = encode_map_config(&EncryptionMapConfig {
            generation: 50,
            policy_revision: 43,
            service_revision: 44,
            egress_revision: 45,
            decision_count: 1,
            transport_count: 1,
            schema_version: ENCRYPTION_MAP_ABI_VERSION,
            active_bank: 1,
            epoch_count: 1,
            path_count: 1,
        });
        assert_eq!(u64::from_ne_bytes(config[0..8].try_into().unwrap()), 50);
        assert_eq!(config[42..44], [1, 1]);
        assert_eq!(u32::from_ne_bytes(config[44..48].try_into().unwrap()), 1);
    }

    #[test]
    fn fixed_width_recovery_rejects_padding_and_unknown_banks() {
        let mut key = [0; 12];
        key[0..4].copy_from_slice(&11_u32.to_ne_bytes());
        key[4..8].copy_from_slice(&21_u32.to_ne_bytes());
        key[8] = ENCRYPTION_BANK_COUNT;
        let mut value = [0; 72];
        value[16..24].copy_from_slice(&1_u64.to_ne_bytes());
        value[24..32].copy_from_slice(&1_u64.to_ne_bytes());
        value[32..40].copy_from_slice(&1_u64.to_ne_bytes());
        value[48..64].fill(1);
        value[64..66].copy_from_slice(&ENCRYPTION_MAP_ABI_VERSION.to_ne_bytes());
        value[66] = ENCRYPTION_DISPOSITION_NATIVE;
        value[67] =
            ENCRYPTION_DECISION_FLAG_POLICY_AUTHORIZED | ENCRYPTION_DECISION_FLAG_SELECTION_BOUND;
        assert!(validate_decision_entry(&key, &value).is_err());
        key[8] = 0;
        value[71] = 1;
        assert!(validate_decision_entry(&key, &value).is_err());
    }

    #[test]
    #[ignore = "requires root BPF map creation and UNF_EBPF_OBJECT"]
    fn privileged_aya_island_opens_with_exact_shapes_and_quiescent_recovery() {
        let object = std::env::var_os("UNF_EBPF_OBJECT").expect("UNF_EBPF_OBJECT is set");
        let mut ebpf = EbpfLoader::new()
            .load_file(object)
            .expect("load verifier-approved eBPF object");
        let maps = take_encryption_maps(&mut ebpf).expect("take typed encryption maps");
        let directory = tempdir().expect("create checkpoint directory");
        let state_path = directory.path().join("encryption-fast-path.json");
        let synchronizer = EncryptionMapSynchronizer::recover(maps, state_path, false)
            .expect("fresh kernel maps recover as a quiescent ABI island");
        assert!(!synchronizer.requires_local_revalidation());
        assert!(!synchronizer.has_active_generation());
    }
}
