//! Typed `GoBGP` gRPC adapter for UNF egress advertisements.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use futures::TryStreamExt;
use thiserror::Error;
use tokio::time::{Duration, Instant, sleep};
use tonic::Code;
use tonic::transport::{Channel, Endpoint};
use unf_common::Revision;
use unf_egress::{
    EGRESS_BFD_EVIDENCE_ALGORITHM, EGRESS_BFD_EVIDENCE_SCHEMA_VERSION, EgressBfdDiagnostic,
    EgressBfdEvidenceError, EgressBfdSessionEvidence, EgressBfdSessionState, EgressBfdSnapshot,
    EgressBfdSnapshotDigest, EgressBgpAddressFamily, EgressBgpConfig, EgressBgpError,
    EgressBgpLargeCommunity, EgressBgpRoute, EgressBgpRouteReadback, EgressBgpSnapshot,
    EgressBgpTransaction, prepare_egress_bgp_transaction, rollback_snapshot,
    seal_egress_bfd_snapshot, seal_egress_bgp_snapshot, verify_egress_bgp_config,
    verify_egress_bgp_readback,
};

#[allow(clippy::all, clippy::pedantic)]
pub mod api {
    tonic::include_proto!("api");
}

const MANAGED_PEER_DESCRIPTION_PREFIX: &str = "unf/egress-bgp/";

#[derive(Debug, Error)]
pub enum GoBgpAdapterError {
    #[error("invalid GoBGP endpoint: {0}")]
    InvalidEndpoint(#[from] tonic::transport::Error),
    #[error("GoBGP request failed: {0}")]
    Rpc(#[from] tonic::Status),
    #[error("GoBGP state conflicts with the exact UNF contract")]
    StateConflict,
    #[error(
        "GoBGP global state conflicts with the exact UNF contract: ASN {asn}, router ID {router_id}"
    )]
    GlobalStateConflict { asn: u32, router_id: String },
    #[error("GoBGP returned malformed route state")]
    MalformedReadback,
    #[error("GoBGP peers did not establish within the bounded convergence window")]
    PeersNotEstablished,
    #[error(transparent)]
    Contract(#[from] EgressBgpError),
    #[error(transparent)]
    BfdEvidence(#[from] EgressBfdEvidenceError),
}

/// Typed adapter around an independently versioned `GoBGP` daemon. It owns only
/// peers marked with the UNF description prefix and paths injected through its
/// exact transactions.
#[derive(Debug, Clone)]
pub struct GoBgpAdapter {
    client: api::go_bgp_service_client::GoBgpServiceClient<Channel>,
}

impl GoBgpAdapter {
    /// Connects to one local `GoBGP` gRPC endpoint.
    ///
    /// # Errors
    ///
    /// Returns transport errors without changing daemon state.
    pub async fn connect(endpoint: &str) -> Result<Self, GoBgpAdapterError> {
        let channel = Endpoint::from_shared(endpoint.to_owned())?
            .connect()
            .await?;
        Ok(Self {
            client: api::go_bgp_service_client::GoBgpServiceClient::new(channel),
        })
    }

    /// Starts or verifies the exact global speaker and converges only UNF-owned
    /// peer definitions.
    ///
    /// # Errors
    ///
    /// Rejects global ASN/router-ID drift or a foreign peer occupying a desired
    /// address. Managed peer replacement and deletion remain scoped.
    pub async fn reconcile_speaker(
        &mut self,
        config: &EgressBgpConfig,
    ) -> Result<(), GoBgpAdapterError> {
        let config = verify_egress_bgp_config(config.clone())?;
        match self.client.get_bgp(api::GetBgpRequest {}).await {
            Ok(response) => {
                let global = response
                    .into_inner()
                    .global
                    .ok_or(GoBgpAdapterError::MalformedReadback)?;
                if global.asn == 0 {
                    self.start_bgp(&config).await?;
                } else if global.asn != config.local_asn
                    || global.router_id != config.router_id.to_string()
                    || global.use_multiple_paths != (config.maximum_paths_per_prefix > 1)
                    || !graceful_restart_matches(global.graceful_restart.as_ref(), &config)
                {
                    return Err(GoBgpAdapterError::GlobalStateConflict {
                        asn: global.asn,
                        router_id: global.router_id,
                    });
                }
            }
            Err(status) if status.code() == Code::FailedPrecondition => {
                self.start_bgp(&config).await?;
            }
            Err(status) => return Err(status.into()),
        }
        self.reconcile_peers(&config).await?;
        self.wait_for_peers(&config, Duration::from_secs(60)).await
    }

    /// Reads a complete digest-sealed BFD snapshot for every BFD-enabled peer.
    /// The record is liveness evidence only and carries no failover authority.
    ///
    /// # Errors
    ///
    /// Rejects missing peers, absent/malformed BFD state, or configuration
    /// drift instead of silently treating incomplete state as healthy.
    pub async fn read_bfd_snapshot(
        &mut self,
        config: &EgressBgpConfig,
        node_name: String,
        node_uid: String,
        source_epoch: u64,
        revision: Revision,
        observed_at_unix_seconds: u64,
    ) -> Result<EgressBfdSnapshot, GoBgpAdapterError> {
        let config = verify_egress_bgp_config(config.clone())?;
        let mut stream = self
            .client
            .list_peer(api::ListPeerRequest {
                address: String::new(),
                enable_advertised: false,
            })
            .await?
            .into_inner();
        let mut current = BTreeMap::new();
        while let Some(response) = stream.try_next().await? {
            let peer = response.peer.ok_or(GoBgpAdapterError::MalformedReadback)?;
            let address = peer
                .conf
                .as_ref()
                .map(|conf| conf.neighbor_address.clone())
                .ok_or(GoBgpAdapterError::MalformedReadback)?;
            current.insert(address, peer);
        }
        let sessions = config
            .peers
            .iter()
            .filter(|peer| peer.bfd.is_some())
            .map(|expected| {
                let peer = current
                    .get(&expected.address.to_string())
                    .ok_or(GoBgpAdapterError::MalformedReadback)?;
                if !bfd_peer_matches(peer, expected, &config) {
                    return Err(GoBgpAdapterError::StateConflict);
                }
                let state = peer
                    .state
                    .as_ref()
                    .and_then(|state| state.bfd_state.as_ref())
                    .ok_or(GoBgpAdapterError::MalformedReadback)?;
                let counters = state
                    .bfd_async
                    .as_ref()
                    .ok_or(GoBgpAdapterError::MalformedReadback)?;
                Ok(EgressBfdSessionEvidence {
                    peer_name: expected.name.clone(),
                    peer_address: expected.address,
                    failure_domain: expected.failure_domain.clone(),
                    state: bfd_session_state(state.session_state)?,
                    remote_state: bfd_session_state(state.remote_session_state)?,
                    local_diagnostic: bfd_diagnostic(state.local_diagnostic_code)?,
                    remote_diagnostic: bfd_diagnostic(state.remote_diagnostic_code)?,
                    failure_transitions: state.failure_transitions,
                    local_discriminator: state.local_discriminator,
                    remote_discriminator: state.remote_discriminator,
                    transmitted_packets: counters.transmitted_packets,
                    received_packets: counters.received_packets,
                })
            })
            .collect::<Result<Vec<_>, GoBgpAdapterError>>()?;
        Ok(seal_egress_bfd_snapshot(
            &config,
            EgressBfdSnapshot {
                schema_version: EGRESS_BFD_EVIDENCE_SCHEMA_VERSION,
                algorithm: EGRESS_BFD_EVIDENCE_ALGORITHM.to_owned(),
                config_digest: config.digest,
                node_name,
                node_uid,
                source_epoch,
                revision,
                observed_at_unix_seconds,
                sessions,
                digest: EgressBfdSnapshotDigest([0; 32]),
            },
        )?)
    }

    async fn start_bgp(&mut self, config: &EgressBgpConfig) -> Result<(), GoBgpAdapterError> {
        self.client
            .start_bgp(api::StartBgpRequest {
                global: Some(api::Global {
                    asn: config.local_asn,
                    router_id: config.router_id.to_string(),
                    listen_port: 179,
                    listen_addresses: vec!["0.0.0.0".to_owned(), "::".to_owned()],
                    families: Vec::new(),
                    use_multiple_paths: config.maximum_paths_per_prefix > 1,
                    route_selection_options: Some(api::RouteSelectionOptionsConfig {
                        always_compare_med: true,
                        ignore_as_path_length: false,
                        external_compare_router_id: true,
                        advertise_inactive_routes: false,
                        enable_aigp: false,
                        ignore_next_hop_igp_metric: false,
                        disable_best_path_selection: false,
                    }),
                    default_route_distance: None,
                    confederation: None,
                    graceful_restart: Some(api::GracefulRestart {
                        enabled: true,
                        restart_time: u32::from(config.graceful_restart.restart_seconds),
                        helper_only: false,
                        deferral_time: u32::from(config.graceful_restart.restart_seconds),
                        notification_enabled: true,
                        longlived_enabled: false,
                        stale_routes_time: u32::from(config.graceful_restart.stale_path_seconds),
                        peer_restart_time: 0,
                        peer_restarting: false,
                        local_restarting: false,
                        mode: String::new(),
                    }),
                    bind_to_device: String::new(),
                }),
            })
            .await?;
        Ok(())
    }

    /// Applies an exact route transaction, verifies local and per-peer RIBs,
    /// and restores the complete prior snapshot on any failure.
    ///
    /// # Errors
    ///
    /// Returns the first mutation/readback failure after attempting scoped
    /// rollback of all route changes made by this transaction.
    pub async fn apply_transaction(
        &mut self,
        config: &EgressBgpConfig,
        transaction: &EgressBgpTransaction,
    ) -> Result<EgressBgpSnapshot, GoBgpAdapterError> {
        let replayed = prepare_egress_bgp_transaction(
            config,
            rollback_snapshot(transaction),
            transaction.desired_snapshot.clone(),
        )?;
        if replayed.digest != transaction.digest {
            return Err(GoBgpAdapterError::StateConflict);
        }
        for route in &transaction.withdrawals {
            if let Err(error) = self.delete_route(route).await {
                self.restore_transaction(transaction).await;
                return Err(error);
            }
        }
        for route in &transaction.additions {
            if let Err(error) = self.add_route(route).await {
                self.restore_transaction(transaction).await;
                return Err(error);
            }
        }
        let readback = match self
            .readback(config, &transaction.desired_snapshot.routes)
            .await
        {
            Ok(readback) => readback,
            Err(error) => {
                self.restore_transaction(transaction).await;
                return Err(error);
            }
        };
        match verify_egress_bgp_readback(config, transaction, readback) {
            Ok(snapshot) => Ok(snapshot),
            Err(error) => {
                self.restore_transaction(transaction).await;
                Err(error.into())
            }
        }
    }

    /// Restores the exact pre-transaction route set and verifies that newly
    /// added routes are absent. This is used when a later durability barrier
    /// fails after daemon mutation succeeded.
    ///
    /// # Errors
    ///
    /// Returns an RPC or exact-readback failure; it never broadens cleanup to
    /// routes outside the supplied transaction.
    pub async fn rollback_transaction(
        &mut self,
        config: &EgressBgpConfig,
        transaction: &EgressBgpTransaction,
    ) -> Result<(), GoBgpAdapterError> {
        let config = verify_egress_bgp_config(config.clone())?;
        self.restore_transaction(transaction).await;
        let previous = rollback_snapshot(transaction);
        let readback = self.readback(&config, &previous.routes).await?;
        if readback.iter().any(|entry| {
            let expected = expected_peers_for_route(&config, &entry.route);
            !entry.local_rib || entry.advertised_to_peers != expected
        }) {
            return Err(GoBgpAdapterError::StateConflict);
        }
        for route in &transaction.additions {
            if previous
                .routes
                .iter()
                .any(|retained| retained.prefix == route.prefix)
            {
                continue;
            }
            if self
                .list_contains_route(api::TableType::Global, String::new(), route)
                .await?
            {
                return Err(GoBgpAdapterError::StateConflict);
            }
        }
        Ok(())
    }

    /// Reports whether an independently learned route with the exact next hop
    /// and Causal Route Capsule is visible in this speaker's global RIB.
    ///
    /// # Errors
    ///
    /// Returns an RPC or malformed-readback error without changing daemon state.
    pub async fn route_visible_in_global(
        &mut self,
        route: &EgressBgpRoute,
    ) -> Result<bool, GoBgpAdapterError> {
        self.list_contains_route(api::TableType::Global, String::new(), route)
            .await
    }

    /// Replays a durable complete snapshot into a restarted daemon and verifies
    /// both its local RIB and every required Adj-RIB-Out. A different route at
    /// any desired prefix is treated as a conflict instead of overwritten.
    ///
    /// # Errors
    ///
    /// Rejects snapshot drift, conflicting live prefixes, RPC failures, or an
    /// incomplete post-recovery readback.
    pub async fn reconcile_snapshot(
        &mut self,
        config: &EgressBgpConfig,
        snapshot: &EgressBgpSnapshot,
    ) -> Result<(), GoBgpAdapterError> {
        let config = verify_egress_bgp_config(config.clone())?;
        let replayed =
            seal_egress_bgp_snapshot(&config, snapshot.revision, snapshot.routes.clone())?;
        if &replayed != snapshot {
            return Err(GoBgpAdapterError::StateConflict);
        }
        for route in &snapshot.routes {
            if self
                .list_contains_route(api::TableType::Global, String::new(), route)
                .await?
            {
                continue;
            }
            if self.global_prefix_has_any_route(route).await? {
                return Err(GoBgpAdapterError::StateConflict);
            }
            self.add_route(route).await?;
        }
        let readback = self.readback(&config, &snapshot.routes).await?;
        if readback.iter().any(|entry| {
            !entry.local_rib
                || entry.advertised_to_peers != expected_peers_for_route(&config, &entry.route)
        }) {
            return Err(GoBgpAdapterError::StateConflict);
        }
        Ok(())
    }

    async fn wait_for_peers(
        &mut self,
        config: &EgressBgpConfig,
        timeout: Duration,
    ) -> Result<(), GoBgpAdapterError> {
        let deadline = Instant::now() + timeout;
        loop {
            let mut stream = self
                .client
                .list_peer(api::ListPeerRequest {
                    address: String::new(),
                    enable_advertised: false,
                })
                .await?
                .into_inner();
            let mut established = BTreeSet::new();
            while let Some(response) = stream.try_next().await? {
                let peer = response.peer.ok_or(GoBgpAdapterError::MalformedReadback)?;
                let address = peer
                    .conf
                    .as_ref()
                    .map(|conf| conf.neighbor_address.clone())
                    .ok_or(GoBgpAdapterError::MalformedReadback)?;
                let expected = config
                    .peers
                    .iter()
                    .find(|expected| expected.address.to_string() == address);
                let ready = peer.state.as_ref().is_some_and(|state| {
                    state.session_state == api::peer_state::SessionState::Established as i32
                        && expected.is_some_and(|expected| {
                            expected.bfd.is_none()
                                || state.bfd_state.as_ref().is_some_and(|bfd| {
                                    bfd.session_state == api::BfdSessionState::Up as i32
                                })
                        })
                });
                if ready {
                    established.insert(address);
                }
            }
            if config
                .peers
                .iter()
                .all(|peer| established.contains(&peer.address.to_string()))
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(GoBgpAdapterError::PeersNotEstablished);
            }
            sleep(Duration::from_millis(500)).await;
        }
    }

    async fn reconcile_peers(&mut self, config: &EgressBgpConfig) -> Result<(), GoBgpAdapterError> {
        let mut stream = self
            .client
            .list_peer(api::ListPeerRequest {
                address: String::new(),
                enable_advertised: false,
            })
            .await?
            .into_inner();
        let mut current = BTreeMap::new();
        while let Some(response) = stream.try_next().await? {
            let peer = response.peer.ok_or(GoBgpAdapterError::MalformedReadback)?;
            let address = peer
                .conf
                .as_ref()
                .map(|conf| conf.neighbor_address.clone())
                .ok_or(GoBgpAdapterError::MalformedReadback)?;
            current.insert(address, peer);
        }
        let desired_addresses = config
            .peers
            .iter()
            .map(|peer| peer.address.to_string())
            .collect::<BTreeSet<_>>();
        for peer in &config.peers {
            let address = peer.address.to_string();
            if let Some(existing) = current.get(&address) {
                let description = existing
                    .conf
                    .as_ref()
                    .map(|conf| conf.description.as_str())
                    .unwrap_or_default();
                if !description.starts_with(MANAGED_PEER_DESCRIPTION_PREFIX) {
                    return Err(GoBgpAdapterError::StateConflict);
                }
                if peer_matches(existing, peer, config) {
                    continue;
                }
                self.client
                    .delete_peer(api::DeletePeerRequest {
                        address: address.clone(),
                        interface: String::new(),
                    })
                    .await?;
            }
            self.client
                .add_peer(api::AddPeerRequest {
                    peer: Some(api_peer(peer, config)),
                })
                .await?;
        }
        for (address, peer) in current {
            let managed = peer.conf.as_ref().is_some_and(|conf| {
                conf.description
                    .starts_with(MANAGED_PEER_DESCRIPTION_PREFIX)
            });
            if managed && !desired_addresses.contains(&address) {
                self.client
                    .delete_peer(api::DeletePeerRequest {
                        address,
                        interface: String::new(),
                    })
                    .await?;
            }
        }
        Ok(())
    }

    async fn add_route(&mut self, route: &EgressBgpRoute) -> Result<(), GoBgpAdapterError> {
        self.client
            .add_path(api::AddPathRequest {
                table_type: api::TableType::Global.into(),
                vrf_id: String::new(),
                path: Some(api_path(route, false)),
            })
            .await?;
        Ok(())
    }

    async fn delete_route(&mut self, route: &EgressBgpRoute) -> Result<(), GoBgpAdapterError> {
        self.client
            .delete_path(api::DeletePathRequest {
                table_type: api::TableType::Global.into(),
                vrf_id: String::new(),
                family: Some(api_family(route.prefix.address)),
                path: Some(api_path(route, true)),
                uuid: Vec::new(),
            })
            .await?;
        Ok(())
    }

    async fn restore_transaction(&mut self, transaction: &EgressBgpTransaction) {
        for route in &transaction.additions {
            let _ = self.delete_route(route).await;
        }
        for route in &transaction.withdrawals {
            let _ = self.add_route(route).await;
        }
    }

    async fn readback(
        &mut self,
        config: &EgressBgpConfig,
        routes: &[EgressBgpRoute],
    ) -> Result<Vec<EgressBgpRouteReadback>, GoBgpAdapterError> {
        let mut result = Vec::with_capacity(routes.len());
        for route in routes {
            let local_rib = self
                .list_contains_route(api::TableType::Global, String::new(), route)
                .await?;
            let mut advertised_to_peers = BTreeSet::new();
            for peer in config.peers.iter().filter(|peer| {
                peer.families
                    .iter()
                    .any(|family| family_contains(*family, route.prefix.address))
            }) {
                if self
                    .list_contains_route(api::TableType::AdjOut, peer.address.to_string(), route)
                    .await?
                {
                    advertised_to_peers.insert(peer.name.clone());
                }
            }
            result.push(EgressBgpRouteReadback {
                route: route.clone(),
                local_rib,
                advertised_to_peers,
            });
        }
        Ok(result)
    }

    async fn list_contains_route(
        &mut self,
        table_type: api::TableType,
        name: String,
        route: &EgressBgpRoute,
    ) -> Result<bool, GoBgpAdapterError> {
        let prefix = format!("{}/{}", route.prefix.address, route.prefix.length);
        let mut stream = self
            .client
            .list_path(api::ListPathRequest {
                table_type: table_type.into(),
                name,
                family: Some(api_family(route.prefix.address)),
                prefixes: vec![api::TableLookupPrefix {
                    prefix,
                    r#type: api::table_lookup_prefix::Type::Exact.into(),
                    rd: String::new(),
                }],
                sort_type: api::list_path_request::SortType::Prefix.into(),
                enable_filtered: false,
                enable_nlri_binary: false,
                enable_attribute_binary: false,
                enable_only_binary: false,
                batch_size: 16,
            })
            .await?
            .into_inner();
        while let Some(response) = stream.try_next().await? {
            if response.destination.is_some_and(|destination| {
                destination
                    .paths
                    .iter()
                    .any(|path| path_matches_route(path, route))
            }) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn global_prefix_has_any_route(
        &mut self,
        route: &EgressBgpRoute,
    ) -> Result<bool, GoBgpAdapterError> {
        let prefix = format!("{}/{}", route.prefix.address, route.prefix.length);
        let mut stream = self
            .client
            .list_path(api::ListPathRequest {
                table_type: api::TableType::Global.into(),
                name: String::new(),
                family: Some(api_family(route.prefix.address)),
                prefixes: vec![api::TableLookupPrefix {
                    prefix,
                    r#type: api::table_lookup_prefix::Type::Exact.into(),
                    rd: String::new(),
                }],
                sort_type: api::list_path_request::SortType::Prefix.into(),
                enable_filtered: true,
                enable_nlri_binary: false,
                enable_attribute_binary: false,
                enable_only_binary: false,
                batch_size: 16,
            })
            .await?
            .into_inner();
        while let Some(response) = stream.try_next().await? {
            if response
                .destination
                .is_some_and(|destination| !destination.paths.is_empty())
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[allow(clippy::too_many_lines)]
fn api_peer(peer: &unf_egress::EgressBgpPeer, config: &EgressBgpConfig) -> api::Peer {
    api::Peer {
        apply_policy: None,
        conf: Some(api::PeerConf {
            auth_password: String::new(),
            description: format!("{MANAGED_PEER_DESCRIPTION_PREFIX}{}", peer.name),
            local_asn: config.local_asn,
            neighbor_address: peer.address.to_string(),
            peer_asn: peer.remote_asn,
            peer_group: String::new(),
            r#type: if peer.remote_asn == config.local_asn {
                api::PeerType::Internal.into()
            } else {
                api::PeerType::External.into()
            },
            remove_private: api::RemovePrivate::Unspecified.into(),
            route_flap_damping: false,
            send_community: 2,
            neighbor_interface: String::new(),
            vrf: String::new(),
            allow_own_asn: 0,
            replace_peer_asn: false,
            admin_down: false,
            send_software_version: true,
            allow_aspath_loop_local: false,
        }),
        ebgp_multihop: Some(api::EbgpMultihop {
            enabled: peer.multihop_ttl > 1,
            multihop_ttl: u32::from(peer.multihop_ttl),
        }),
        route_reflector: None,
        state: None,
        timers: Some(api::Timers {
            config: Some(api::TimersConfig {
                connect_retry: 5,
                hold_time: 30,
                keepalive_interval: 10,
                minimum_advertisement_interval: 0,
                idle_hold_time_after_reset: 0,
            }),
            state: None,
        }),
        transport: Some(api::Transport {
            local_address: String::new(),
            local_port: 0,
            mtu_discovery: true,
            passive_mode: false,
            remote_address: String::new(),
            remote_port: 179,
            tcp_mss: 0,
            bind_interface: String::new(),
            ip_tos: 192,
        }),
        route_server: None,
        graceful_restart: Some(api::GracefulRestart {
            enabled: true,
            restart_time: u32::from(config.graceful_restart.restart_seconds),
            helper_only: false,
            deferral_time: u32::from(config.graceful_restart.restart_seconds),
            notification_enabled: true,
            longlived_enabled: false,
            stale_routes_time: u32::from(config.graceful_restart.stale_path_seconds),
            peer_restart_time: 0,
            peer_restarting: false,
            local_restarting: false,
            mode: String::new(),
        }),
        afi_safis: peer
            .families
            .iter()
            .map(|family| api::AfiSafi {
                mp_graceful_restart: Some(api::MpGracefulRestart {
                    config: Some(api::MpGracefulRestartConfig { enabled: true }),
                    state: None,
                }),
                config: Some(api::AfiSafiConfig {
                    family: Some(api_family_for(*family)),
                    enabled: true,
                }),
                state: None,
                apply_policy: None,
                route_selection_options: None,
                use_multiple_paths: Some(api::UseMultiplePaths {
                    config: Some(api::UseMultiplePathsConfig {
                        enabled: config.maximum_paths_per_prefix > 1,
                    }),
                    state: None,
                    ebgp: Some(api::Ebgp {
                        config: Some(api::EbgpConfig {
                            allow_multiple_asn: false,
                            maximum_paths: u32::from(config.maximum_paths_per_prefix),
                        }),
                        state: None,
                    }),
                    ibgp: Some(api::Ibgp {
                        config: Some(api::IbgpConfig {
                            maximum_paths: u32::from(config.maximum_paths_per_prefix),
                        }),
                        state: None,
                    }),
                }),
                prefix_limits: Some(api::PrefixLimit {
                    family: Some(api_family_for(*family)),
                    max_prefixes: peer.maximum_received_prefixes,
                    shutdown_threshold_pct: 80,
                }),
                route_target_membership: None,
                long_lived_graceful_restart: None,
                add_paths: Some(api::AddPaths {
                    config: Some(api::AddPathsConfig {
                        receive: config.maximum_paths_per_prefix > 1,
                        send_max: u32::from(config.maximum_paths_per_prefix),
                    }),
                    state: None,
                }),
            })
            .collect(),
        ttl_security: Some(api::TtlSecurity {
            enabled: peer.multihop_ttl == 1,
            ttl_min: 255,
        }),
        bfd: peer.bfd.map(|bfd| api::BfdPeerConfig {
            enabled: true,
            port: u32::from(bfd.port),
            desired_minimum_tx_interval: bfd.desired_minimum_tx_interval_microseconds,
            required_minimum_receive: bfd.required_minimum_receive_interval_microseconds,
            detection_multiplier: u32::from(bfd.detection_multiplier),
        }),
    }
}

fn peer_matches(
    actual: &api::Peer,
    expected: &unf_egress::EgressBgpPeer,
    config: &EgressBgpConfig,
) -> bool {
    let Some(conf) = actual.conf.as_ref() else {
        return false;
    };
    conf.description == format!("{MANAGED_PEER_DESCRIPTION_PREFIX}{}", expected.name)
        && conf.local_asn == config.local_asn
        && conf.neighbor_address == expected.address.to_string()
        && conf.peer_asn == expected.remote_asn
        && actual.ebgp_multihop.as_ref().is_some_and(|multihop| {
            multihop.enabled == (expected.multihop_ttl > 1)
                && multihop.multihop_ttl == u32::from(expected.multihop_ttl)
        })
        && actual
            .ttl_security
            .as_ref()
            .is_some_and(|ttl| ttl.enabled == (expected.multihop_ttl == 1) && ttl.ttl_min == 255)
        && graceful_restart_matches(actual.graceful_restart.as_ref(), config)
        && bfd_config_matches(actual.bfd.as_ref(), expected.bfd.as_ref())
        && actual.afi_safis.len() == expected.families.len()
        && expected.families.iter().all(|family| {
            actual
                .afi_safis
                .iter()
                .any(|afi| afi_safi_matches(afi, *family, expected, config))
        })
}

fn bfd_config_matches(
    actual: Option<&api::BfdPeerConfig>,
    expected: Option<&unf_egress::EgressBgpBfdConfig>,
) -> bool {
    match (actual, expected) {
        (None, None) => true,
        (Some(actual), Some(expected)) => {
            actual.enabled
                && actual.port == u32::from(expected.port)
                && actual.desired_minimum_tx_interval
                    == expected.desired_minimum_tx_interval_microseconds
                && actual.required_minimum_receive
                    == expected.required_minimum_receive_interval_microseconds
                && actual.detection_multiplier == u32::from(expected.detection_multiplier)
        }
        _ => false,
    }
}

fn bfd_peer_matches(
    actual: &api::Peer,
    expected: &unf_egress::EgressBgpPeer,
    config: &EgressBgpConfig,
) -> bool {
    actual.conf.as_ref().is_some_and(|conf| {
        conf.description == format!("{MANAGED_PEER_DESCRIPTION_PREFIX}{}", expected.name)
            && conf.local_asn == config.local_asn
            && conf.neighbor_address == expected.address.to_string()
            && conf.peer_asn == expected.remote_asn
    }) && bfd_config_matches(actual.bfd.as_ref(), expected.bfd.as_ref())
}

fn bfd_session_state(value: i32) -> Result<EgressBfdSessionState, GoBgpAdapterError> {
    match api::BfdSessionState::try_from(value).map_err(|_| GoBgpAdapterError::MalformedReadback)? {
        api::BfdSessionState::Unspecified => Ok(EgressBfdSessionState::Unknown),
        api::BfdSessionState::Up => Ok(EgressBfdSessionState::Up),
        api::BfdSessionState::Down => Ok(EgressBfdSessionState::Down),
        api::BfdSessionState::AdminDown => Ok(EgressBfdSessionState::AdminDown),
        api::BfdSessionState::Init => Ok(EgressBfdSessionState::Init),
    }
}

fn bfd_diagnostic(value: i32) -> Result<EgressBfdDiagnostic, GoBgpAdapterError> {
    match api::BfdDiagnosticCode::try_from(value)
        .map_err(|_| GoBgpAdapterError::MalformedReadback)?
    {
        api::BfdDiagnosticCode::NoDiagnostic => Ok(EgressBfdDiagnostic::None),
        api::BfdDiagnosticCode::DetectionTimeout => Ok(EgressBfdDiagnostic::DetectionTimeout),
        api::BfdDiagnosticCode::EchoFailed => Ok(EgressBfdDiagnostic::EchoFailed),
        api::BfdDiagnosticCode::NeighborSignaledSessionDown => {
            Ok(EgressBfdDiagnostic::NeighborSignaledDown)
        }
        api::BfdDiagnosticCode::ForwardingPlaneReset => {
            Ok(EgressBfdDiagnostic::ForwardingPlaneReset)
        }
        api::BfdDiagnosticCode::PathDown => Ok(EgressBfdDiagnostic::PathDown),
        api::BfdDiagnosticCode::ConcatenatedPathDown => {
            Ok(EgressBfdDiagnostic::ConcatenatedPathDown)
        }
        api::BfdDiagnosticCode::AdministrativelyDown => {
            Ok(EgressBfdDiagnostic::AdministrativelyDown)
        }
        api::BfdDiagnosticCode::ReverseConcatenatedPathDown => {
            Ok(EgressBfdDiagnostic::ReverseConcatenatedPathDown)
        }
    }
}

fn graceful_restart_matches(
    actual: Option<&api::GracefulRestart>,
    config: &EgressBgpConfig,
) -> bool {
    actual.is_some_and(|graceful| {
        graceful.enabled
            && graceful.restart_time == u32::from(config.graceful_restart.restart_seconds)
            && graceful.deferral_time == u32::from(config.graceful_restart.restart_seconds)
            && graceful.notification_enabled
            && !graceful.longlived_enabled
            && graceful.stale_routes_time == u32::from(config.graceful_restart.stale_path_seconds)
    })
}

fn afi_safi_matches(
    actual: &api::AfiSafi,
    family: EgressBgpAddressFamily,
    peer: &unf_egress::EgressBgpPeer,
    config: &EgressBgpConfig,
) -> bool {
    let expected_family = api_family_for(family);
    actual
        .config
        .as_ref()
        .is_some_and(|afi| afi.enabled && afi.family.as_ref() == Some(&expected_family))
        && actual.prefix_limits.as_ref().is_some_and(|limit| {
            limit.family.as_ref() == Some(&expected_family)
                && limit.max_prefixes == peer.maximum_received_prefixes
                && limit.shutdown_threshold_pct == 80
        })
        && actual.add_paths.as_ref().is_some_and(|paths| {
            paths.config.as_ref().is_some_and(|paths| {
                paths.receive == (config.maximum_paths_per_prefix > 1)
                    && paths.send_max == u32::from(config.maximum_paths_per_prefix)
            })
        })
        && actual.use_multiple_paths.as_ref().is_some_and(|paths| {
            paths
                .config
                .as_ref()
                .is_some_and(|paths| paths.enabled == (config.maximum_paths_per_prefix > 1))
        })
}

fn api_path(route: &EgressBgpRoute, withdraw: bool) -> api::Path {
    let nlri = api_nlri(route);
    let mut attributes = vec![api::Attribute {
        attr: Some(api::attribute::Attr::Origin(api::OriginAttribute {
            origin: 0,
        })),
    }];
    if route.prefix.address.is_ipv4() {
        attributes.push(api::Attribute {
            attr: Some(api::attribute::Attr::NextHop(api::NextHopAttribute {
                next_hop: route.next_hop.to_string(),
            })),
        });
    } else {
        attributes.push(api::Attribute {
            attr: Some(api::attribute::Attr::MpReach(api::MpReachNlriAttribute {
                family: Some(api_family(route.prefix.address)),
                next_hops: vec![route.next_hop.to_string()],
                nlris: vec![nlri.clone()],
            })),
        });
    }
    attributes.push(api::Attribute {
        attr: Some(api::attribute::Attr::LargeCommunities(
            api::LargeCommunitiesAttribute {
                communities: route
                    .capsule
                    .communities
                    .iter()
                    .copied()
                    .map(api_large_community)
                    .collect(),
            },
        )),
    });
    api::Path {
        nlri: Some(nlri),
        pattrs: attributes,
        age: None,
        best: false,
        is_withdraw: withdraw,
        validation: None,
        no_implicit_withdraw: false,
        family: Some(api_family(route.prefix.address)),
        source_asn: 0,
        source_id: String::new(),
        filtered: false,
        stale: false,
        is_from_external: false,
        neighbor_ip: String::new(),
        uuid: Vec::new(),
        is_nexthop_invalid: false,
        identifier: 0,
        local_identifier: 0,
        nlri_binary: Vec::new(),
        pattrs_binary: Vec::new(),
        send_max_filtered: false,
    }
}

fn api_nlri(route: &EgressBgpRoute) -> api::Nlri {
    api::Nlri {
        nlri: Some(api::nlri::Nlri::Prefix(api::IpAddressPrefix {
            prefix_len: u32::from(route.prefix.length),
            prefix: route.prefix.address.to_string(),
        })),
    }
}

fn api_large_community(community: EgressBgpLargeCommunity) -> api::LargeCommunity {
    api::LargeCommunity {
        global_admin: community.global_admin,
        local_data1: community.local_data_one,
        local_data2: community.local_data_two,
    }
}

fn api_family(address: IpAddr) -> api::Family {
    api_family_for(if address.is_ipv4() {
        EgressBgpAddressFamily::Ipv4
    } else {
        EgressBgpAddressFamily::Ipv6
    })
}

fn api_family_for(family: EgressBgpAddressFamily) -> api::Family {
    api::Family {
        afi: match family {
            EgressBgpAddressFamily::Ipv4 => api::family::Afi::Ip,
            EgressBgpAddressFamily::Ipv6 => api::family::Afi::Ip6,
        }
        .into(),
        safi: api::family::Safi::Unicast.into(),
    }
}

fn family_contains(family: EgressBgpAddressFamily, address: IpAddr) -> bool {
    matches!(
        (family, address),
        (EgressBgpAddressFamily::Ipv4, IpAddr::V4(_))
            | (EgressBgpAddressFamily::Ipv6, IpAddr::V6(_))
    )
}

fn expected_peers_for_route(config: &EgressBgpConfig, route: &EgressBgpRoute) -> BTreeSet<String> {
    config
        .peers
        .iter()
        .filter(|peer| {
            peer.families
                .iter()
                .any(|family| family_contains(*family, route.prefix.address))
        })
        .map(|peer| peer.name.clone())
        .collect()
}

fn path_matches_route(path: &api::Path, route: &EgressBgpRoute) -> bool {
    let Some(nlri) = path.nlri.as_ref().and_then(|nlri| nlri.nlri.as_ref()) else {
        return false;
    };
    let api::nlri::Nlri::Prefix(prefix) = nlri else {
        return false;
    };
    if prefix.prefix != route.prefix.address.to_string()
        || prefix.prefix_len != u32::from(route.prefix.length)
        || path.stale
        || path.filtered
    {
        return false;
    }
    let mut next_hop = None;
    let mut communities = None;
    for attribute in &path.pattrs {
        match attribute.attr.as_ref() {
            Some(api::attribute::Attr::NextHop(value)) => {
                next_hop = value.next_hop.parse::<IpAddr>().ok();
            }
            Some(api::attribute::Attr::MpReach(value)) => {
                next_hop = value
                    .next_hops
                    .first()
                    .and_then(|value| value.parse::<IpAddr>().ok());
            }
            Some(api::attribute::Attr::LargeCommunities(value)) => {
                communities = Some(
                    value
                        .communities
                        .iter()
                        .map(|community| EgressBgpLargeCommunity {
                            global_admin: community.global_admin,
                            local_data_one: community.local_data1,
                            local_data_two: community.local_data2,
                        })
                        .collect::<BTreeSet<_>>(),
                );
            }
            _ => {}
        }
    }
    next_hop == Some(route.next_hop)
        && communities
            == Some(
                route
                    .capsule
                    .communities
                    .iter()
                    .copied()
                    .collect::<BTreeSet<_>>(),
            )
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use unf_common::Revision;
    use unf_egress::{
        EGRESS_BFD_SINGLE_HOP_PORT, EGRESS_BGP_ALGORITHM, EGRESS_BGP_SCHEMA_VERSION,
        EgressBgpBfdConfig, EgressBgpCausalRouteCapsule, EgressBgpConfigDigest,
        EgressBgpGracefulRestart, EgressBgpPeer, EgressBgpPrefix, EgressBgpRouteDigest,
        EgressIntentOwner, EgressIntentScope, EgressProviderRef, EgressReachabilityPlanDigest,
        seal_egress_bgp_config, seal_egress_bgp_route,
    };

    use super::*;

    fn config() -> EgressBgpConfig {
        seal_egress_bgp_config(EgressBgpConfig {
            schema_version: EGRESS_BGP_SCHEMA_VERSION,
            algorithm: EGRESS_BGP_ALGORITHM.to_owned(),
            revision: Revision::new(1),
            instance: "fabric-a".to_owned(),
            local_asn: 64_512,
            router_id: Ipv4Addr::new(192, 0, 2, 10),
            ipv4_next_hop: Some("198.51.100.10".parse().unwrap()),
            ipv6_next_hop: Some("2001:db8:100::10".parse().unwrap()),
            peers: vec![EgressBgpPeer {
                name: "tor-a".to_owned(),
                address: "198.51.100.1".parse().unwrap(),
                remote_asn: 64_513,
                failure_domain: "rack-a".to_owned(),
                families: BTreeSet::from([
                    EgressBgpAddressFamily::Ipv4,
                    EgressBgpAddressFamily::Ipv6,
                ]),
                multihop_ttl: 1,
                maximum_received_prefixes: 1_024,
                bfd: None,
            }],
            permitted_export_prefixes: vec![EgressBgpPrefix {
                address: "192.0.2.0".parse().unwrap(),
                length: 24,
            }],
            maximum_changed_prefixes: 16,
            maximum_total_prefixes: 256,
            maximum_paths_per_prefix: 4,
            graceful_restart: EgressBgpGracefulRestart {
                restart_seconds: 30,
                stale_path_seconds: 90,
            },
            digest: EgressBgpConfigDigest([0; 32]),
        })
        .unwrap()
    }

    #[test]
    fn typed_path_preserves_exact_causal_capsule() {
        let config = config();
        let route = seal_egress_bgp_route(
            &config,
            EgressIntentOwner {
                scope: EgressIntentScope::Cluster,
                name: "payments".to_owned(),
                uid: "policy-uid-a".to_owned(),
            },
            EgressProviderRef {
                name: "bgp".to_owned(),
                instance: "fabric-a".to_owned(),
            },
            Revision::new(2),
            3,
            "192.0.2.240".parse().unwrap(),
            "worker-a".to_owned(),
            "node-uid-a".to_owned(),
            EgressReachabilityPlanDigest([7; 32]),
        )
        .unwrap();
        let encoded = api_path(&route, false);
        assert!(path_matches_route(&encoded, &route));

        let mut stale = route.clone();
        stale.capsule = EgressBgpCausalRouteCapsule {
            communities: [EgressBgpLargeCommunity {
                global_admin: 1,
                local_data_one: 2,
                local_data_two: 3,
            }; 3],
        };
        stale.digest = EgressBgpRouteDigest([9; 32]);
        assert!(!path_matches_route(&encoded, &stale));
    }

    #[test]
    fn managed_peer_readback_detects_policy_drift() {
        let config = config();
        let mut actual = api_peer(&config.peers[0], &config);
        assert!(peer_matches(&actual, &config.peers[0], &config));

        actual.afi_safis[0]
            .prefix_limits
            .as_mut()
            .unwrap()
            .max_prefixes += 1;
        assert!(!peer_matches(&actual, &config.peers[0], &config));
    }

    #[test]
    fn typed_peer_preserves_bounded_bfd_and_detects_timer_drift() {
        let mut raw = config();
        raw.peers[0].bfd = Some(EgressBgpBfdConfig {
            port: EGRESS_BFD_SINGLE_HOP_PORT,
            desired_minimum_tx_interval_microseconds: 300_000,
            required_minimum_receive_interval_microseconds: 500_000,
            detection_multiplier: 3,
        });
        raw.digest = EgressBgpConfigDigest([0; 32]);
        let config = seal_egress_bgp_config(raw).unwrap();
        let mut actual = api_peer(&config.peers[0], &config);
        let bfd = actual.bfd.as_ref().unwrap();
        assert!(bfd.enabled);
        assert_eq!(bfd.port, 3_784);
        assert_eq!(bfd.desired_minimum_tx_interval, 300_000);
        assert_eq!(bfd.required_minimum_receive, 500_000);
        assert_eq!(bfd.detection_multiplier, 3);
        assert!(peer_matches(&actual, &config.peers[0], &config));

        actual.bfd.as_mut().unwrap().detection_multiplier = 4;
        assert!(!peer_matches(&actual, &config.peers[0], &config));
    }
}
