//! Namespace-relative peer observations, not packet-time device capabilities.
//!
//! Interface indexes can coincide in different namespaces. Both reciprocal
//! indexes and each observer's namespace ID must match independently held FDs.
//! NSIDs are never persisted or interpreted outside the observing namespace.

use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::PathBuf;

use futures::StreamExt;
use rtnetlink::Handle;
use rtnetlink::packet_core::{NLM_F_ACK, NLM_F_REQUEST, NetlinkMessage, NetlinkPayload};
use rtnetlink::packet_route::RouteNetlinkMessage;
use rtnetlink::packet_route::link::{LinkAttribute, LinkMessage};
use rtnetlink::packet_route::nsid::{NsidAttribute, NsidMessage};

use crate::LinkError;

pub(super) fn open_current_namespace() -> Result<File, LinkError> {
    // This fixed procfs magic link deliberately identifies the calling thread,
    // not the process leader or a caller-controlled CNI namespace pathname.
    let path = PathBuf::from("/proc/thread-self/ns/net");
    File::open(&path).map_err(|source| LinkError::OpenNamespace { path, source })
}

pub(super) async fn namespace_id(handle: &Handle, namespace: &File) -> Result<i32, LinkError> {
    let mut request = NsidMessage::default();
    request.attributes.push(NsidAttribute::Fd(
        u32::try_from(namespace.as_raw_fd())
            .map_err(|_| malformed("invalid namespace descriptor"))?,
    ));
    let mut request = NetlinkMessage::from(RouteNetlinkMessage::GetNsId(request));
    request.header.flags = NLM_F_REQUEST | NLM_F_ACK;
    let mut handle = handle.clone();
    let mut responses = handle
        .request(request)
        .map_err(|source| LinkError::Netlink {
            operation: "request descriptor-bound namespace ID",
            source,
        })?;
    let mut found = None;
    let mut messages = 0;
    while let Some(response) = responses.next().await {
        messages += 1;
        if messages > 4 {
            return Err(malformed("excess namespace-ID response messages"));
        }
        match response.payload {
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewNsId(message)) => {
                if found.replace(parse_namespace_id(&message)?).is_some() {
                    return Err(malformed("duplicate namespace-ID response"));
                }
            }
            NetlinkPayload::Error(error) if error.code.is_none() => {}
            NetlinkPayload::Error(error) => {
                return Err(LinkError::Netlink {
                    operation: "read descriptor-bound namespace ID",
                    source: rtnetlink::Error::NetlinkError(error),
                });
            }
            _ => return Err(malformed("unexpected namespace-ID response")),
        }
    }
    found.ok_or_else(|| malformed("missing namespace-ID response"))
}

fn parse_namespace_id(message: &NsidMessage) -> Result<i32, LinkError> {
    let mut ids = message
        .attributes
        .iter()
        .filter_map(|attribute| match attribute {
            NsidAttribute::Id(id) => Some(*id),
            _ => None,
        });
    match (ids.next(), ids.next()) {
        (Some(id), None) if id >= 0 => Ok(id),
        _ => Err(malformed("missing, unassigned or ambiguous namespace ID")),
    }
}

pub(super) fn validate_pair(
    host: &LinkMessage,
    peer: &LinkMessage,
    peer_namespace_id: i32,
    host_namespace_id: i32,
) -> Result<(), LinkError> {
    // Equal indexes across namespaces are valid. Equal namespace-ID integers
    // across observers have no meaning; compare each in its own namespace.
    validate_reference(host, peer.header.index, peer_namespace_id)?;
    validate_reference(peer, host.header.index, host_namespace_id)
}

fn validate_reference(link: &LinkMessage, index: u32, namespace: i32) -> Result<(), LinkError> {
    let mut indexes = link
        .attributes
        .iter()
        .filter_map(|attribute| match attribute {
            LinkAttribute::Link(index) => Some(*index),
            _ => None,
        });
    let mut namespaces = link
        .attributes
        .iter()
        .filter_map(|attribute| match attribute {
            LinkAttribute::LinkNetNsId(id) => Some(*id),
            _ => None,
        });
    if link.header.index == 0
        || index == 0
        || namespace < 0
        || (indexes.next(), indexes.next()) != (Some(index), None)
        || (namespaces.next(), namespaces.next()) != (Some(namespace), None)
    {
        return Err(malformed(
            "veth peer index or namespace does not match the anchored pair",
        ));
    }
    Ok(())
}

fn malformed(message: &str) -> LinkError {
    LinkError::Readback(message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(index: u32, peer: u32, namespace: i32) -> LinkMessage {
        let mut link = LinkMessage::default();
        link.header.index = index;
        link.attributes = vec![
            LinkAttribute::Link(peer),
            LinkAttribute::LinkNetNsId(namespace),
        ];
        link
    }

    #[test]
    fn reciprocal_peer_requires_namespace_identity_not_index_equality() {
        let host = link(5, 8, 0);
        let peer = link(8, 5, 7);
        validate_pair(&host, &peer, 0, 7).expect("different observer-relative NSIDs");
        assert!(validate_pair(&host, &peer, 1, 7).is_err());
        assert!(validate_pair(&host, &peer, 0, 8).is_err());
        assert!(validate_pair(&host, &peer, -1, 7).is_err());
        assert!(validate_pair(&host, &peer, 0, -1).is_err());
        validate_pair(&link(5, 5, 0), &link(5, 5, 7), 0, 7)
            .expect("equal indexes in different namespaces are valid");
    }

    #[test]
    fn reciprocal_peer_rejects_absent_duplicate_and_substituted_link_attributes() {
        let host = link(5, 8, 0);
        let peer = link(8, 5, 7);
        for side in 0..2 {
            for mutation in 0..8 {
                let mut host = host.clone();
                let mut peer = peer.clone();
                let target = if side == 0 { &mut host } else { &mut peer };
                match mutation {
                    0 => target.header.index = 0,
                    1 => target.header.index += 1,
                    2 => {
                        target.attributes.remove(0);
                    }
                    3 => {
                        target.attributes.remove(1);
                    }
                    4 => target.attributes[0] = LinkAttribute::Link(99),
                    5 => target.attributes[1] = LinkAttribute::LinkNetNsId(99),
                    6 => target.attributes.push(target.attributes[0].clone()),
                    _ => target.attributes.push(target.attributes[1].clone()),
                }
                assert!(
                    validate_pair(&host, &peer, 0, 7).is_err(),
                    "side={side} mutation={mutation}"
                );
            }
        }
    }

    #[test]
    fn namespace_id_reply_requires_one_assigned_id() {
        for attributes in [
            vec![],
            vec![NsidAttribute::Id(-1)],
            vec![NsidAttribute::Id(0), NsidAttribute::Id(0)],
            vec![NsidAttribute::Fd(3)],
        ] {
            let mut message = NsidMessage::default();
            message.attributes = attributes;
            assert!(parse_namespace_id(&message).is_err());
        }
        let mut message = NsidMessage::default();
        message.attributes = vec![NsidAttribute::Id(0)];
        assert_eq!(parse_namespace_id(&message).expect("zero is assigned"), 0);
    }
}
