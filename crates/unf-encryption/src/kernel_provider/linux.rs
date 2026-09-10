use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use futures::{StreamExt as _, TryStreamExt as _};
use netlink_packet_core::{NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, NetlinkMessage, NetlinkPayload};
use netlink_packet_generic::GenlMessage;
use netlink_packet_wireguard::{
    WireguardAddressFamily, WireguardAllowedIp, WireguardAllowedIpAttr, WireguardAttribute,
    WireguardCmd, WireguardDeviceFlags, WireguardMessage, WireguardPeer, WireguardPeerAttribute,
    WireguardPeerFlags,
};
use rtnetlink::packet_route::address::AddressAttribute;
use rtnetlink::packet_route::link::{InfoKind, LinkAttribute, LinkFlags, LinkInfo, LinkMessage};
use rtnetlink::packet_route::route::{
    RouteAddress, RouteAttribute, RouteMessage, RouteProtocol, RouteScope, RouteType,
};
use rtnetlink::{Handle, LinkUnspec, LinkWireguard, RouteMessageBuilder};
use zeroize::Zeroize as _;

use super::{
    KernelApplyOutcome, KernelDeleteOutcome, UNF_WIREGUARD_ROUTE_PROTOCOL,
    WireGuardEpochActivation, WireGuardKernelError, WireGuardKernelPlan, WireGuardKernelSnapshot,
    WireGuardKernelSnapshotInput, WireGuardPeerReadback, WireGuardRouteReadback,
    WireGuardRouteScope,
};
use crate::{IpPrefix, WireGuardPrivateKey, WireGuardPublicKey};

const ENODEV_RAW_OS_ERROR: i32 = 19;
const MAX_KERNEL_ROUTE_READBACK: usize = 262_144;

#[derive(Debug, Default, Clone, Copy)]
pub struct LinuxWireGuardProvider;

impl LinuxWireGuardProvider {
    /// Creates an exact inactive/active epoch or replays an already exact one.
    ///
    /// # Errors
    ///
    /// Rejects foreign same-name/route state before mutation. A partial fresh
    /// stage is removed and positive absence is checked before failure returns.
    pub async fn apply(
        &self,
        plan: &WireGuardKernelPlan,
        private_key: &WireGuardPrivateKey,
    ) -> Result<(KernelApplyOutcome, WireGuardKernelSnapshot), WireGuardKernelError> {
        self.apply_with_checkpoint(plan, private_key, || Ok(()))
            .await
    }

    async fn apply_with_checkpoint<F>(
        &self,
        plan: &WireGuardKernelPlan,
        private_key: &WireGuardPrivateKey,
        after_device: F,
    ) -> Result<(KernelApplyOutcome, WireGuardKernelSnapshot), WireGuardKernelError>
    where
        F: FnOnce() -> Result<(), WireGuardKernelError>,
    {
        plan.verify()?;
        plan.verify_private_key(private_key)?;
        let handle = connect_route("open rtnetlink connection")?;
        let existing = find_link(&handle, &plan.interface_name).await?;
        if let Some(link) = existing {
            validate_owned_link(&link, plan)?;
            let snapshot = read_snapshot(&handle, plan, &link).await?;
            snapshot.verify_against(plan).map_err(|_| {
                WireGuardKernelError::ForeignState(
                    "owned interface exists but does not exactly match desired state".to_owned(),
                )
            })?;
            return Ok((KernelApplyOutcome::AlreadyExact, snapshot));
        }
        require_route_keys_absent(&handle, plan).await?;

        if let Err(cause) = create_and_configure_link(&handle, plan).await {
            return match rollback_fresh_stage(&handle, plan).await {
                Ok(()) => Err(cause),
                Err(error) => Err(WireGuardKernelError::Rollback {
                    cause: cause.to_string(),
                    rollback: error.to_string(),
                }),
            };
        }
        let link = require_link(&handle, &plan.interface_name).await?;
        let result = async {
            configure_device(plan, private_key).await?;
            after_device()?;
            add_proof_addresses(&handle, plan, link.header.index).await?;
            add_routes(&handle, plan, link.header.index).await?;
            let snapshot = read_snapshot(&handle, plan, &link).await?;
            snapshot.verify_against(plan)?;
            Ok(snapshot)
        }
        .await;
        match result {
            Ok(snapshot) => Ok((KernelApplyOutcome::Created, snapshot)),
            Err(cause) => {
                let rollback = rollback_fresh_stage(&handle, plan).await;
                match rollback {
                    Ok(()) => Err(cause),
                    Err(error) => Err(WireGuardKernelError::Rollback {
                        cause: cause.to_string(),
                        rollback: error.to_string(),
                    }),
                }
            }
        }
    }

    /// Independently reads and verifies the exact link, peer, and route state.
    ///
    /// # Errors
    ///
    /// Returns absent, foreign-state, netlink, parse, or exact-readback error.
    pub async fn readback(
        &self,
        plan: &WireGuardKernelPlan,
    ) -> Result<WireGuardKernelSnapshot, WireGuardKernelError> {
        plan.verify()?;
        let handle = connect_route("open rtnetlink readback connection")?;
        let link = require_link(&handle, &plan.interface_name).await?;
        validate_owned_link(&link, plan)?;
        let snapshot = read_snapshot(&handle, plan, &link).await?;
        snapshot.verify_against(plan)?;
        Ok(snapshot)
    }

    /// Deletes only an exact version-owned interface and its exact routes.
    ///
    /// # Errors
    ///
    /// Refuses partial, mutated, same-name foreign, or same-route-key foreign
    /// state. Successful deletion includes positive link and route absence.
    pub async fn delete(
        &self,
        plan: &WireGuardKernelPlan,
    ) -> Result<KernelDeleteOutcome, WireGuardKernelError> {
        plan.verify()?;
        let handle = connect_route("open rtnetlink cleanup connection")?;
        let Some(link) = find_link(&handle, &plan.interface_name).await? else {
            require_route_keys_absent(&handle, plan).await?;
            return Ok(KernelDeleteOutcome::AlreadyAbsent);
        };
        validate_owned_link(&link, plan)?;
        let snapshot = read_snapshot(&handle, plan, &link).await?;
        snapshot.verify_against(plan)?;
        handle
            .link()
            .del(link.header.index)
            .execute()
            .await
            .map_err(|error| kernel("delete WireGuard interface", &error))?;
        require_link_absent(&handle, &plan.interface_name).await?;
        require_route_keys_absent(&handle, plan).await?;
        Ok(KernelDeleteOutcome::Deleted)
    }

    /// Rolls back a fresh stage authorized by a verified prepared checkpoint.
    ///
    /// # Errors
    ///
    /// Refuses non-prepared, pre-existing, or non-staged transactions and any
    /// link whose versioned ownership alias does not exactly match the plan.
    pub async fn rollback_prepared(
        &self,
        transaction: &super::ProofCarryingKernelTransaction,
    ) -> Result<(), WireGuardKernelError> {
        transaction.verify()?;
        if transaction.phase != super::KernelTransactionPhase::Prepared
            || transaction.before_configuration_digest.is_some()
            || transaction.plan.activation != WireGuardEpochActivation::InactiveStaged
        {
            return Err(WireGuardKernelError::InvalidTransaction);
        }
        let handle = connect_route("open rtnetlink recovery connection")?;
        rollback_fresh_stage(&handle, &transaction.plan).await
    }
}

fn connect_route(operation: &'static str) -> Result<Handle, WireGuardKernelError> {
    let (connection, handle, _) =
        rtnetlink::new_connection().map_err(|error| WireGuardKernelError::Kernel {
            operation,
            message: error.to_string(),
        })?;
    tokio::spawn(connection);
    Ok(handle)
}

async fn create_and_configure_link(
    handle: &Handle,
    plan: &WireGuardKernelPlan,
) -> Result<(), WireGuardKernelError> {
    handle
        .link()
        .add(LinkWireguard::new(&plan.interface_name).build())
        .execute()
        .await
        .map_err(|error| kernel("create WireGuard interface", &error))?;
    let link = require_link(handle, &plan.interface_name).await?;
    let ownership = handle
        .link()
        .set(
            LinkUnspec::new_with_index(link.header.index)
                .alias(&plan.owner_alias)
                .build(),
        )
        .execute()
        .await;
    if let Err(error) = ownership {
        let cause = kernel("claim WireGuard link ownership", &error);
        let cleanup = handle.link().del(link.header.index).execute().await;
        return match cleanup {
            Ok(()) => {
                require_link_absent(handle, &plan.interface_name).await?;
                Err(cause)
            }
            Err(cleanup_error) => Err(WireGuardKernelError::Rollback {
                cause: cause.to_string(),
                rollback: kernel("remove unclaimed WireGuard interface", &cleanup_error)
                    .to_string(),
            }),
        };
    }
    let link = require_link(handle, &plan.interface_name).await?;
    validate_owned_link(&link, plan)?;
    handle
        .link()
        .set(
            LinkUnspec::new_with_index(link.header.index)
                .mtu(plan.mtu_envelope.interface_mtu)
                .alias(&plan.owner_alias)
                .up()
                .build(),
        )
        .execute()
        .await
        .map_err(|error| kernel("configure WireGuard link", &error))?;
    let link = require_link(handle, &plan.interface_name).await?;
    validate_owned_link(&link, plan)
}

async fn configure_device(
    plan: &WireGuardKernelPlan,
    private_key: &WireGuardPrivateKey,
) -> Result<(), WireGuardKernelError> {
    let (connection, mut handle, _) =
        genetlink::new_connection().map_err(|error| WireGuardKernelError::Kernel {
            operation: "open WireGuard generic-netlink connection",
            message: error.to_string(),
        })?;
    tokio::spawn(connection);
    let mut private_bytes = *private_key.expose_for_kernel();
    let peers = plan.peers.iter().map(encode_peer).collect::<Vec<_>>();
    let attributes = vec![
        WireguardAttribute::IfName(plan.interface_name.clone()),
        WireguardAttribute::PrivateKey(private_bytes),
        WireguardAttribute::ListenPort(plan.listen_port),
        WireguardAttribute::Fwmark(plan.fwmark),
        WireguardAttribute::Flags(WireguardDeviceFlags::ReplacePeers),
        WireguardAttribute::Peers(peers),
    ];
    let generic = GenlMessage::from_payload(WireguardMessage {
        cmd: WireguardCmd::SetDevice,
        attributes,
    });
    let mut request = NetlinkMessage::from(generic);
    request.header.flags = NLM_F_REQUEST | NLM_F_ACK;
    let response = handle.request(request).await;
    private_bytes.zeroize();
    let mut responses = response.map_err(|error| WireGuardKernelError::Kernel {
        operation: "resolve WireGuard generic-netlink family",
        message: error.to_string(),
    })?;
    while let Some(response) = responses.next().await {
        let response = response.map_err(|error| WireGuardKernelError::Kernel {
            operation: "decode WireGuard set response",
            message: error.to_string(),
        })?;
        if let NetlinkPayload::Error(error) = response.payload
            && error.code.is_some()
        {
            return Err(WireGuardKernelError::Kernel {
                operation: "set WireGuard device",
                message: error.to_io().to_string(),
            });
        }
    }
    Ok(())
}

fn encode_peer(peer: &super::WireGuardPeerPlan) -> WireguardPeer {
    let allowed_ips = peer
        .allowed_ips
        .iter()
        .map(|prefix| {
            WireguardAllowedIp(vec![
                WireguardAllowedIpAttr::Family(match prefix.address {
                    IpAddr::V4(_) => WireguardAddressFamily::Ipv4,
                    IpAddr::V6(_) => WireguardAddressFamily::Ipv6,
                }),
                WireguardAllowedIpAttr::IpAddr(prefix.address),
                WireguardAllowedIpAttr::Cidr(prefix.prefix_len),
            ])
        })
        .collect();
    WireguardPeer(vec![
        WireguardPeerAttribute::PublicKey(peer.public_key.0),
        WireguardPeerAttribute::Endpoint(peer.endpoint),
        WireguardPeerAttribute::PersistentKeepalive(peer.persistent_keepalive_seconds),
        WireguardPeerAttribute::AllowedIps(allowed_ips),
        WireguardPeerAttribute::Flags(WireguardPeerFlags::ReplaceAllowedIps),
    ])
}

async fn read_snapshot(
    handle: &Handle,
    plan: &WireGuardKernelPlan,
    link: &LinkMessage,
) -> Result<WireGuardKernelSnapshot, WireGuardKernelError> {
    let link_state = parse_link(link)?;
    let device = read_device(&plan.interface_name).await?;
    if device.interface_index != link.header.index || device.interface_name != plan.interface_name {
        return Err(WireGuardKernelError::ReadbackMismatch);
    }
    let routes = read_routes(handle, plan, link.header.index, true).await?;
    let proof_addresses = read_proof_addresses(handle, plan, link.header.index).await?;
    WireGuardKernelSnapshot::issue(WireGuardKernelSnapshotInput {
        interface_name: device.interface_name,
        interface_index: device.interface_index,
        owner_alias: link_state.owner_alias,
        is_up: link_state.is_up,
        mtu: link_state.mtu,
        public_key: device.public_key,
        listen_port: device.listen_port,
        fwmark: device.fwmark,
        proof_addresses,
        peers: device.peers,
        routes,
    })
}

async fn add_proof_addresses(
    handle: &Handle,
    plan: &WireGuardKernelPlan,
    interface_index: u32,
) -> Result<(), WireGuardKernelError> {
    for prefix in &plan.proof_addresses {
        handle
            .address()
            .add(interface_index, prefix.address, prefix.prefix_len)
            .replace()
            .execute()
            .await
            .map_err(|error| kernel("assign WireGuard proof address", &error))?;
    }
    Ok(())
}

async fn read_proof_addresses(
    handle: &Handle,
    plan: &WireGuardKernelPlan,
    interface_index: u32,
) -> Result<Vec<IpPrefix>, WireGuardKernelError> {
    let mut stream = handle
        .address()
        .get()
        .set_link_index_filter(interface_index)
        .execute();
    let mut observed = Vec::new();
    while let Some(message) = stream
        .try_next()
        .await
        .map_err(|error| kernel("read WireGuard proof addresses", &error))?
    {
        let address = message
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                AddressAttribute::Local(address) | AddressAttribute::Address(address) => {
                    Some(*address)
                }
                _ => None,
            });
        if let Some(address) = address {
            observed.push(IpPrefix {
                address,
                prefix_len: message.header.prefix_len,
            });
        }
        if observed.len() > crate::MAX_ENCRYPTION_PREFIXES_PER_NODE {
            return Err(WireGuardKernelError::CapacityExceeded);
        }
    }
    observed.sort_unstable();
    observed.dedup();
    if observed != plan.proof_addresses {
        return Err(WireGuardKernelError::ForeignState(
            "owned WireGuard interface has unexpected proof addresses".to_owned(),
        ));
    }
    Ok(observed)
}

struct ParsedDevice {
    interface_name: String,
    interface_index: u32,
    public_key: WireGuardPublicKey,
    listen_port: u16,
    fwmark: u32,
    peers: Vec<WireGuardPeerReadback>,
}

async fn read_device(interface_name: &str) -> Result<ParsedDevice, WireGuardKernelError> {
    let (connection, mut handle, _) =
        genetlink::new_connection().map_err(|error| WireGuardKernelError::Kernel {
            operation: "open WireGuard readback generic-netlink connection",
            message: error.to_string(),
        })?;
    tokio::spawn(connection);
    let generic = GenlMessage::from_payload(WireguardMessage {
        cmd: WireguardCmd::GetDevice,
        attributes: vec![WireguardAttribute::IfName(interface_name.to_owned())],
    });
    let mut request = NetlinkMessage::from(generic);
    request.header.flags = NLM_F_REQUEST | NLM_F_DUMP;
    let mut responses =
        handle
            .request(request)
            .await
            .map_err(|error| WireGuardKernelError::Kernel {
                operation: "resolve WireGuard readback family",
                message: error.to_string(),
            })?;
    let mut parsed_name = None;
    let mut parsed_index = None;
    let mut public_key = None;
    let mut listen_port = None;
    let mut fwmark = None;
    let mut peers = Vec::new();
    while let Some(response) = responses.next().await {
        let response = response.map_err(|error| WireGuardKernelError::Kernel {
            operation: "decode WireGuard readback",
            message: error.to_string(),
        })?;
        match response.payload {
            NetlinkPayload::InnerMessage(message) => {
                for attribute in message.payload.attributes {
                    match attribute {
                        WireguardAttribute::IfName(value) => set_once(&mut parsed_name, value)?,
                        WireguardAttribute::IfIndex(value) => set_once(&mut parsed_index, value)?,
                        WireguardAttribute::PrivateKey(mut secret) => secret.zeroize(),
                        WireguardAttribute::PublicKey(value) => {
                            set_once(&mut public_key, WireGuardPublicKey(value))?;
                        }
                        WireguardAttribute::ListenPort(value) => {
                            set_once(&mut listen_port, value)?;
                        }
                        WireguardAttribute::Fwmark(value) => set_once(&mut fwmark, value)?,
                        WireguardAttribute::Peers(values) => {
                            for peer in values {
                                peers.push(parse_peer(peer)?);
                            }
                        }
                        WireguardAttribute::Flags(_) | WireguardAttribute::Other(_) => {
                            return Err(WireGuardKernelError::ReadbackMismatch);
                        }
                        _ => return Err(WireGuardKernelError::ReadbackMismatch),
                    }
                }
            }
            NetlinkPayload::Error(error) if error.code.is_some() => {
                return Err(WireGuardKernelError::Kernel {
                    operation: "get WireGuard device",
                    message: error.to_io().to_string(),
                });
            }
            _ => {}
        }
    }
    peers.sort_by_key(|peer| peer.public_key);
    Ok(ParsedDevice {
        interface_name: parsed_name.ok_or(WireGuardKernelError::ReadbackMismatch)?,
        interface_index: parsed_index.ok_or(WireGuardKernelError::ReadbackMismatch)?,
        public_key: public_key.ok_or(WireGuardKernelError::ReadbackMismatch)?,
        listen_port: listen_port.ok_or(WireGuardKernelError::ReadbackMismatch)?,
        fwmark: fwmark.ok_or(WireGuardKernelError::ReadbackMismatch)?,
        peers,
    })
}

fn set_once<T: PartialEq>(slot: &mut Option<T>, value: T) -> Result<(), WireGuardKernelError> {
    if slot.as_ref().is_some_and(|prior| prior != &value) {
        return Err(WireGuardKernelError::ReadbackMismatch);
    }
    *slot = Some(value);
    Ok(())
}

fn parse_peer(peer: WireguardPeer) -> Result<WireGuardPeerReadback, WireGuardKernelError> {
    let mut public_key = None;
    let mut endpoint = None;
    let mut keepalive = 0;
    let mut handshake = 0;
    let mut received = 0;
    let mut transmitted = 0;
    let mut allowed_ips = None;
    for attribute in peer.0 {
        match attribute {
            WireguardPeerAttribute::PublicKey(value) => {
                set_once(&mut public_key, WireGuardPublicKey(value))?;
            }
            WireguardPeerAttribute::PresharedKey(mut secret) => {
                let nonzero = secret != [0; 32];
                secret.zeroize();
                if nonzero {
                    return Err(WireGuardKernelError::ForeignState(
                        "unexpected preshared key".to_owned(),
                    ));
                }
            }
            WireguardPeerAttribute::Endpoint(value) => set_once(&mut endpoint, value)?,
            WireguardPeerAttribute::PersistentKeepalive(value) => keepalive = value,
            WireguardPeerAttribute::LastHandshake(value) => handshake = value.seconds,
            WireguardPeerAttribute::RxBytes(value) => received = value,
            WireguardPeerAttribute::TxBytes(value) => transmitted = value,
            WireguardPeerAttribute::AllowedIps(values) => {
                let parsed = values
                    .iter()
                    .map(parse_allowed_ip)
                    .collect::<Result<Vec<_>, WireGuardKernelError>>()?;
                set_once(&mut allowed_ips, parsed)?;
            }
            WireguardPeerAttribute::ProtocolVersion(value) if value <= 1 => {}
            WireguardPeerAttribute::Flags(_)
            | WireguardPeerAttribute::ProtocolVersion(_)
            | WireguardPeerAttribute::Other(_) => {
                return Err(WireGuardKernelError::ReadbackMismatch);
            }
            _ => return Err(WireGuardKernelError::ReadbackMismatch),
        }
    }
    let mut allowed_ips = allowed_ips.ok_or(WireGuardKernelError::ReadbackMismatch)?;
    allowed_ips.sort();
    Ok(WireGuardPeerReadback {
        public_key: public_key.ok_or(WireGuardKernelError::ReadbackMismatch)?,
        endpoint: endpoint.ok_or(WireGuardKernelError::ReadbackMismatch)?,
        persistent_keepalive_seconds: keepalive,
        allowed_ips,
        last_handshake_unix_seconds: handshake,
        received_bytes: received,
        transmitted_bytes: transmitted,
    })
}

fn parse_allowed_ip(value: &WireguardAllowedIp) -> Result<IpPrefix, WireGuardKernelError> {
    let mut family = None;
    let mut address = None;
    let mut prefix_len = None;
    for attribute in &value.0 {
        match attribute {
            WireguardAllowedIpAttr::Family(value) => set_once(&mut family, *value)?,
            WireguardAllowedIpAttr::IpAddr(value) => set_once(&mut address, *value)?,
            WireguardAllowedIpAttr::Cidr(value) => set_once(&mut prefix_len, *value)?,
            WireguardAllowedIpAttr::Flags(_) | WireguardAllowedIpAttr::Other(_) => {
                return Err(WireGuardKernelError::ReadbackMismatch);
            }
            _ => return Err(WireGuardKernelError::ReadbackMismatch),
        }
    }
    let address = address.ok_or(WireGuardKernelError::ReadbackMismatch)?;
    let expected_family = match address {
        IpAddr::V4(_) => WireguardAddressFamily::Ipv4,
        IpAddr::V6(_) => WireguardAddressFamily::Ipv6,
    };
    if family != Some(expected_family) {
        return Err(WireGuardKernelError::ReadbackMismatch);
    }
    let prefix = IpPrefix {
        address,
        prefix_len: prefix_len.ok_or(WireGuardKernelError::ReadbackMismatch)?,
    };
    if !prefix.is_canonical() {
        return Err(WireGuardKernelError::ReadbackMismatch);
    }
    Ok(prefix)
}

struct ParsedLink {
    owner_alias: String,
    is_up: bool,
    mtu: u32,
}

fn parse_link(link: &LinkMessage) -> Result<ParsedLink, WireGuardKernelError> {
    let mut name = None;
    let mut alias = None;
    let mut mtu = None;
    let mut kind = None;
    for attribute in &link.attributes {
        match attribute {
            LinkAttribute::IfName(value) => name = Some(value.as_str()),
            LinkAttribute::IfAlias(value) => alias = Some(value.clone()),
            LinkAttribute::Mtu(value) => mtu = Some(*value),
            LinkAttribute::LinkInfo(values) => {
                for value in values {
                    if let LinkInfo::Kind(value) = value {
                        kind = Some(value.clone());
                    }
                }
            }
            _ => {}
        }
    }
    if name.is_none() || kind != Some(InfoKind::Wireguard) {
        return Err(WireGuardKernelError::ForeignState(
            "same-name link is not WireGuard".to_owned(),
        ));
    }
    Ok(ParsedLink {
        owner_alias: alias.ok_or_else(|| {
            WireGuardKernelError::ForeignState("WireGuard link has no ownership alias".to_owned())
        })?,
        is_up: link.header.flags.contains(LinkFlags::Up),
        mtu: mtu.ok_or(WireGuardKernelError::ReadbackMismatch)?,
    })
}

fn validate_owned_link(
    link: &LinkMessage,
    plan: &WireGuardKernelPlan,
) -> Result<(), WireGuardKernelError> {
    let parsed = parse_link(link)?;
    if parsed.owner_alias != plan.owner_alias {
        return Err(WireGuardKernelError::ForeignState(
            "same-name WireGuard link has another ownership alias".to_owned(),
        ));
    }
    Ok(())
}

async fn find_link(
    handle: &Handle,
    name: &str,
) -> Result<Option<LinkMessage>, WireGuardKernelError> {
    let mut links = handle.link().get().match_name(name.to_owned()).execute();
    let first = match links.try_next().await {
        Ok(link) => link,
        Err(rtnetlink::Error::NetlinkError(error))
            if error.to_io().raw_os_error() == Some(ENODEV_RAW_OS_ERROR) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(kernel("read WireGuard link", &error)),
    };
    if links
        .try_next()
        .await
        .map_err(|error| kernel("check duplicate WireGuard link", &error))?
        .is_some()
    {
        return Err(WireGuardKernelError::ForeignState(
            "duplicate interface name".to_owned(),
        ));
    }
    Ok(first)
}

async fn require_link(handle: &Handle, name: &str) -> Result<LinkMessage, WireGuardKernelError> {
    find_link(handle, name)
        .await?
        .ok_or(WireGuardKernelError::Absent)
}

async fn require_link_absent(handle: &Handle, name: &str) -> Result<(), WireGuardKernelError> {
    if find_link(handle, name).await?.is_some() {
        return Err(WireGuardKernelError::ReadbackMismatch);
    }
    Ok(())
}

async fn add_routes(
    handle: &Handle,
    plan: &WireGuardKernelPlan,
    interface_index: u32,
) -> Result<(), WireGuardKernelError> {
    for prefix in plan.route_prefixes() {
        handle
            .route()
            .add(build_route(prefix, plan.route_table, interface_index))
            .execute()
            .await
            .map_err(|error| kernel("add WireGuard route", &error))?;
    }
    Ok(())
}

fn build_route(prefix: IpPrefix, table: u32, interface_index: u32) -> RouteMessage {
    match prefix.address {
        IpAddr::V4(address) => RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(address, prefix.prefix_len)
            .output_interface(interface_index)
            .table_id(table)
            .protocol(RouteProtocol::from(UNF_WIREGUARD_ROUTE_PROTOCOL))
            .scope(RouteScope::Link)
            .build(),
        IpAddr::V6(address) => RouteMessageBuilder::<Ipv6Addr>::new()
            .destination_prefix(address, prefix.prefix_len)
            .output_interface(interface_index)
            .table_id(table)
            .protocol(RouteProtocol::from(UNF_WIREGUARD_ROUTE_PROTOCOL))
            .scope(RouteScope::Universe)
            .build(),
    }
}

async fn read_routes(
    handle: &Handle,
    plan: &WireGuardKernelPlan,
    interface_index: u32,
    require_complete: bool,
) -> Result<Vec<WireGuardRouteReadback>, WireGuardKernelError> {
    let desired = plan.route_prefixes();
    let messages = list_routes(handle).await?;
    let mut keyed = BTreeMap::<(IpPrefix, u32), Vec<&RouteMessage>>::new();
    for message in &messages {
        if let Some(key) = route_key(message) {
            keyed.entry(key).or_default().push(message);
        }
    }
    let mut routes = Vec::new();
    for prefix in &desired {
        match keyed.get(&(*prefix, plan.route_table)).map(Vec::as_slice) {
            None if require_complete => return Err(WireGuardKernelError::ReadbackMismatch),
            None => {}
            Some([message]) if route_is_exact(message, *prefix, interface_index) => {
                routes.push(WireGuardRouteReadback {
                    prefix: *prefix,
                    interface_index,
                    table: plan.route_table,
                    protocol: UNF_WIREGUARD_ROUTE_PROTOCOL,
                    scope: WireGuardRouteScope::for_prefix(*prefix),
                });
            }
            _ => {
                return Err(WireGuardKernelError::ForeignState(format!(
                    "route key {}/{} table {} is not exactly UNF-owned",
                    prefix.address, prefix.prefix_len, plan.route_table
                )));
            }
        }
    }
    if let Some(message) = messages.iter().find(|message| {
        route_oif(message) == Some(interface_index)
            && !is_kernel_generated_wireguard_multicast(message)
            && !is_kernel_generated_proof_address_route(message, plan, interface_index)
            && match route_key(message) {
                Some((prefix, table)) => {
                    table != plan.route_table
                        || !desired.contains(&prefix)
                        || !route_is_exact(message, prefix, interface_index)
                }
                None => true,
            }
    }) {
        return Err(WireGuardKernelError::ForeignState(format!(
            "unexpected route points at the owned WireGuard interface: key={:?}, protocol={:?}, scope={:?}, kind={:?}",
            route_key(message),
            message.header.protocol,
            message.header.scope,
            message.header.kind
        )));
    }
    Ok(routes)
}

async fn require_route_keys_absent(
    handle: &Handle,
    plan: &WireGuardKernelPlan,
) -> Result<(), WireGuardKernelError> {
    if !read_routes(handle, plan, 0, false).await?.is_empty() {
        return Err(WireGuardKernelError::ForeignState(
            "planned route key already exists".to_owned(),
        ));
    }
    Ok(())
}

async fn list_routes(handle: &Handle) -> Result<Vec<RouteMessage>, WireGuardKernelError> {
    let mut messages = Vec::new();
    for request in [
        RouteMessageBuilder::<Ipv4Addr>::new().build(),
        RouteMessageBuilder::<Ipv6Addr>::new().build(),
    ] {
        let mut routes = handle.route().get(request).execute();
        while let Some(route) = routes
            .try_next()
            .await
            .map_err(|error| kernel("list WireGuard routes", &error))?
        {
            messages.push(route);
            if messages.len() > MAX_KERNEL_ROUTE_READBACK {
                return Err(WireGuardKernelError::CapacityExceeded);
            }
        }
    }
    Ok(messages)
}

fn route_key(message: &RouteMessage) -> Option<(IpPrefix, u32)> {
    let address = message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Destination(RouteAddress::Inet(value)) => Some(IpAddr::V4(*value)),
            RouteAttribute::Destination(RouteAddress::Inet6(value)) => Some(IpAddr::V6(*value)),
            _ => None,
        })?;
    let table = message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Table(value) => Some(*value),
            _ => None,
        })
        .unwrap_or(u32::from(message.header.table));
    Some((
        IpPrefix {
            address,
            prefix_len: message.header.destination_prefix_length,
        },
        table,
    ))
}

fn route_is_exact(message: &RouteMessage, prefix: IpPrefix, interface_index: u32) -> bool {
    message.header.protocol == RouteProtocol::from(UNF_WIREGUARD_ROUTE_PROTOCOL)
        && message.header.scope
            == match WireGuardRouteScope::for_prefix(prefix) {
                WireGuardRouteScope::Link => RouteScope::Link,
                WireGuardRouteScope::Universe => RouteScope::Universe,
            }
        && route_oif(message) == Some(interface_index)
}

fn route_oif(message: &RouteMessage) -> Option<u32> {
    message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Oif(value) => Some(*value),
            _ => None,
        })
}

fn is_kernel_generated_wireguard_multicast(message: &RouteMessage) -> bool {
    route_key(message)
        == Some((
            IpPrefix {
                address: IpAddr::V6(Ipv6Addr::from(0xff00_u128 << 112)),
                prefix_len: 8,
            },
            255,
        ))
        && message.header.protocol == RouteProtocol::Kernel
        && message.header.scope == RouteScope::Universe
}

fn is_kernel_generated_proof_address_route(
    message: &RouteMessage,
    plan: &WireGuardKernelPlan,
    interface_index: u32,
) -> bool {
    route_key(message).is_some_and(|(prefix, table)| {
        plan.proof_addresses.contains(&prefix)
            && route_oif(message) == Some(interface_index)
            && message.header.protocol == RouteProtocol::Kernel
            && ((table == 255
                && message.header.scope
                    == match prefix.address {
                        IpAddr::V4(_) => RouteScope::Host,
                        IpAddr::V6(_) => RouteScope::Universe,
                    }
                && message.header.kind == RouteType::Local)
                || (table == 254
                    && message.header.scope
                        == match prefix.address {
                            IpAddr::V4(_) => RouteScope::Link,
                            IpAddr::V6(_) => RouteScope::Universe,
                        }
                    && message.header.kind == RouteType::Unicast))
    })
}

async fn rollback_fresh_stage(
    handle: &Handle,
    plan: &WireGuardKernelPlan,
) -> Result<(), WireGuardKernelError> {
    if let Some(link) = find_link(handle, &plan.interface_name).await? {
        validate_owned_link(&link, plan)?;
        read_routes(handle, plan, link.header.index, false).await?;
        handle
            .link()
            .del(link.header.index)
            .execute()
            .await
            .map_err(|error| kernel("rollback WireGuard interface", &error))?;
    }
    require_link_absent(handle, &plan.interface_name).await?;
    require_route_keys_absent(handle, plan).await
}

fn kernel(operation: &'static str, error: &rtnetlink::Error) -> WireGuardKernelError {
    WireGuardKernelError::Kernel {
        operation,
        message: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::env;

    use unf_common::Revision;

    use super::*;
    use crate::{
        OsWireGuardKeyGenerator, UnderlayAddressFamily, UnderlayMtuObservation,
        WireGuardKernelPlanInput, WireGuardKeyGenerator, WireGuardMtuEnvelope, WireGuardPeerPlan,
    };

    fn privileged_plan() -> (WireGuardKernelPlan, WireGuardPrivateKey) {
        let interface_name =
            env::var("UNF_WIREGUARD_TEST_INTERFACE").unwrap_or_else(|_| "unfwgtest9".to_owned());
        let mut generator = OsWireGuardKeyGenerator;
        let private_key = generator.generate().unwrap();
        let plan = WireGuardKernelPlan::new(WireGuardKernelPlanInput {
            cluster_id: "kernel-test".to_owned(),
            local_node_uid: "kernel-node-a".to_owned(),
            epoch: 9,
            revision: Revision::new(1),
            interface_name,
            local_public_key: private_key.public_key(),
            listen_port: 51_829,
            fwmark: 0x554e_0009,
            route_table: 29_909,
            mtu_envelope: WireGuardMtuEnvelope::derive(&[
                UnderlayMtuObservation {
                    peer_node_uid: "kernel-node-b".to_owned(),
                    family: UnderlayAddressFamily::Ipv4,
                    underlay_mtu: 1_500,
                },
                UnderlayMtuObservation {
                    peer_node_uid: "kernel-node-b".to_owned(),
                    family: UnderlayAddressFamily::Ipv6,
                    underlay_mtu: 1_500,
                },
            ])
            .unwrap(),
            local_pod_cidrs: vec![
                IpPrefix {
                    address: "10.245.1.0".parse().unwrap(),
                    prefix_len: 24,
                },
                IpPrefix {
                    address: "fd00:245:1::".parse().unwrap(),
                    prefix_len: 64,
                },
            ],
            activation: WireGuardEpochActivation::InactiveStaged,
            peers: vec![WireGuardPeerPlan {
                node_uid: "kernel-node-b".to_owned(),
                public_key: WireGuardPublicKey([42; 32]),
                endpoint: "192.0.2.42:51820".parse().unwrap(),
                persistent_keepalive_seconds: 0,
                allowed_ips: vec![
                    IpPrefix {
                        address: "198.51.100.0".parse().unwrap(),
                        prefix_len: 24,
                    },
                    IpPrefix {
                        address: "2001:db8:42::".parse().unwrap(),
                        prefix_len: 64,
                    },
                ],
            }],
        })
        .unwrap();
        (plan, private_key)
    }

    async fn prove_same_name_foreign_state_is_preserved(
        provider: &LinuxWireGuardProvider,
        plan: &WireGuardKernelPlan,
        private_key: &WireGuardPrivateKey,
        handle: &Handle,
    ) {
        handle
            .link()
            .add(LinkWireguard::new(&plan.interface_name).build())
            .execute()
            .await
            .unwrap();
        let foreign = require_link(handle, &plan.interface_name).await.unwrap();
        handle
            .link()
            .set(
                LinkUnspec::new_with_index(foreign.header.index)
                    .alias("not-owned-by-unf")
                    .build(),
            )
            .execute()
            .await
            .unwrap();
        assert!(matches!(
            provider.apply(plan, private_key).await,
            Err(WireGuardKernelError::ForeignState(_))
        ));
        let foreign = require_link(handle, &plan.interface_name).await.unwrap();
        assert_eq!(
            parse_link(&foreign).unwrap().owner_alias,
            "not-owned-by-unf"
        );
        handle
            .link()
            .del(foreign.header.index)
            .execute()
            .await
            .unwrap();
        require_link_absent(handle, &plan.interface_name)
            .await
            .unwrap();
    }

    async fn prove_foreign_route_key_is_preserved(
        provider: &LinuxWireGuardProvider,
        plan: &WireGuardKernelPlan,
        private_key: &WireGuardPrivateKey,
        handle: &Handle,
    ) {
        let interface = env::var("UNF_WIREGUARD_FOREIGN_TEST_INTERFACE")
            .unwrap_or_else(|_| "unfwgfrn9".to_owned());
        if let Some(stale) = find_link(handle, &interface).await.unwrap() {
            handle
                .link()
                .del(stale.header.index)
                .execute()
                .await
                .unwrap();
        }
        handle
            .link()
            .add(LinkWireguard::new(&interface).build())
            .execute()
            .await
            .unwrap();
        let foreign = require_link(handle, &interface).await.unwrap();
        handle
            .link()
            .set(
                LinkUnspec::new_with_index(foreign.header.index)
                    .up()
                    .build(),
            )
            .execute()
            .await
            .unwrap();
        let prefix = *plan.route_prefixes().iter().next().unwrap();
        handle
            .route()
            .add(build_route(prefix, plan.route_table, foreign.header.index))
            .execute()
            .await
            .unwrap();
        assert!(matches!(
            provider.apply(plan, private_key).await,
            Err(WireGuardKernelError::ForeignState(_))
        ));
        assert!(
            find_link(handle, &plan.interface_name)
                .await
                .unwrap()
                .is_none()
        );
        assert!(list_routes(handle).await.unwrap().iter().any(|route| {
            route_key(route) == Some((prefix, plan.route_table))
                && route_oif(route) == Some(foreign.header.index)
        }));
        handle
            .link()
            .del(foreign.header.index)
            .execute()
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires CAP_NET_ADMIN and kernel WireGuard"]
    async fn privileged_kernel_stage_readback_rollback_and_cleanup_are_exact() {
        let provider = LinuxWireGuardProvider;
        let (plan, private_key) = privileged_plan();
        let _ = provider.delete(&plan).await;

        let injected = provider
            .apply_with_checkpoint(&plan, &private_key, || {
                Err(WireGuardKernelError::Kernel {
                    operation: "injected after generic-netlink stage",
                    message: "fault".to_owned(),
                })
            })
            .await;
        assert!(injected.is_err());
        let after_rollback = provider.readback(&plan).await;
        assert!(
            matches!(after_rollback, Err(WireGuardKernelError::Absent)),
            "unexpected post-rollback readback: {after_rollback:?}"
        );

        let handle = connect_route("open foreign-state test connection").unwrap();
        prove_same_name_foreign_state_is_preserved(&provider, &plan, &private_key, &handle).await;
        prove_foreign_route_key_is_preserved(&provider, &plan, &private_key, &handle).await;

        let (outcome, first) = provider.apply(&plan, &private_key).await.unwrap();
        assert_eq!(outcome, KernelApplyOutcome::Created);
        first.verify_against(&plan).unwrap();
        let (outcome, replay) = provider.apply(&plan, &private_key).await.unwrap();
        assert_eq!(outcome, KernelApplyOutcome::AlreadyExact);
        assert_eq!(first.configuration_digest, replay.configuration_digest);

        let mut transaction = super::super::ProofCarryingKernelTransaction::begin(
            Revision::new(2),
            plan.clone(),
            None,
        )
        .unwrap();
        provider.rollback_prepared(&transaction).await.unwrap();
        transaction.record_rollback(true).unwrap();
        assert_eq!(
            transaction.recover(None).unwrap(),
            super::super::KernelRecoveryAction::RollbackComplete
        );
        assert_eq!(
            provider.apply(&plan, &private_key).await.unwrap().0,
            KernelApplyOutcome::Created
        );
        assert_eq!(
            provider.delete(&plan).await.unwrap(),
            KernelDeleteOutcome::Deleted
        );
        assert_eq!(
            provider.delete(&plan).await.unwrap(),
            KernelDeleteOutcome::AlreadyAbsent
        );
    }
}
