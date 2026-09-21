//! Held namespace identity for a checked snapshot. Keeping a namespace alive
//! does not prevent veth deletion, movement, route drift or index reuse.

use std::fs::File;
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::fs::MetadataExt;

use crate::{LinkError, LinkReadback, VethPlan, open_namespace, peer_identity};

/// Opaque checked snapshot retaining the exact host and peer namespace FDs.
/// There is deliberately no deserialize/clone constructor or admission flag.
/// A successful recheck only proves another observation; it does not close the
/// time-of-check/time-of-use gap or grant a local Required plaintext exception.
pub struct VethObservation {
    plan: VethPlan,
    readback: LinkReadback,
    namespaces: Option<NamespaceDescriptors>,
    cookies: NamespaceCookies,
}

/// Socket-observed namespace coordinates, not placement or lifetime authority.
/// Multiple workload interfaces may legitimately share one peer cookie.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamespaceCookies {
    host: u64,
    peer: u64,
}

impl NamespaceCookies {
    pub(super) fn new(host: u64, peer: u64) -> Result<Self, LinkError> {
        if host == 0 || peer == 0 || host == peer {
            return Err(LinkError::Readback(
                "invalid or identical host/peer namespace cookies".into(),
            ));
        }
        Ok(Self { host, peer })
    }

    #[must_use]
    pub const fn host(self) -> u64 {
        self.host
    }

    #[must_use]
    pub const fn peer(self) -> u64 {
        self.peer
    }
}

struct NamespaceDescriptors {
    host_namespace: File,
    peer_namespace: File,
}

impl VethObservation {
    pub(super) const fn new(
        plan: VethPlan,
        readback: LinkReadback,
        host_namespace: File,
        peer_namespace: File,
        cookies: NamespaceCookies,
    ) -> Self {
        Self {
            plan,
            readback,
            cookies,
            namespaces: Some(NamespaceDescriptors {
                host_namespace,
                peer_namespace,
            }),
        }
    }

    #[must_use]
    pub const fn readback(&self) -> &LinkReadback {
        &self.readback
    }

    /// Borrowed descriptors cannot outlive this observation. Namespace-relative
    /// IDs must be queried in the corresponding observer, not persisted.
    #[must_use]
    pub fn namespace_descriptors(&self) -> Option<(BorrowedFd<'_>, BorrowedFd<'_>)> {
        self.namespaces.as_ref().map(|namespaces| {
            (
                namespaces.host_namespace.as_fd(),
                namespaces.peer_namespace.as_fd(),
            )
        })
    }

    /// Coordinates come from the same netlink sockets used for strict readback
    /// in the retained descriptor contexts. No extra socket/thread is opened.
    #[must_use]
    pub fn namespace_cookies(&self) -> Option<NamespaceCookies> {
        self.namespaces.as_ref().map(|_| self.cookies)
    }

    /// Rechecks through the retained descriptors, without replacing them from
    /// the pathname. No link, route or attachment state is changed.
    ///
    /// # Errors
    /// Rejects path replacement/removal, a changed calling namespace, failed
    /// strict link readback, or any change to the original snapshot. Any failed
    /// recheck permanently retires this observation and releases its FDs;
    /// restoring a pathname or link does not implicitly rearm it. Cancellation
    /// after the recheck starts also retires the observation.
    pub async fn recheck(&mut self) -> Result<(), LinkError> {
        let namespaces = self.namespaces.take().ok_or_else(retired)?;
        let result = self.recheck_inner(&namespaces).await;
        if result.is_ok() {
            self.namespaces = Some(namespaces);
        }
        result
    }

    async fn recheck_inner(&self, namespaces: &NamespaceDescriptors) -> Result<(), LinkError> {
        self.check_paths_against(namespaces)?;
        let (current, cookies) = self
            .plan
            .readback_with_namespace_cookies(
                &namespaces.peer_namespace,
                &namespaces.host_namespace,
                true,
            )
            .await?;
        if cookies != Some(self.cookies) {
            return Err(LinkError::Readback(
                "observed namespace cookies changed".into(),
            ));
        }
        require_same_readback(&self.readback, &current)?;
        self.check_paths_against(namespaces)
    }

    pub(super) fn check_namespace_paths(&self) -> Result<(), LinkError> {
        let namespaces = self.namespaces.as_ref().ok_or_else(retired)?;
        self.check_paths_against(namespaces)
    }

    fn check_paths_against(&self, namespaces: &NamespaceDescriptors) -> Result<(), LinkError> {
        require_same_namespace(
            &namespaces.host_namespace,
            &peer_identity::open_current_namespace()?,
        )?;
        require_same_namespace(
            &namespaces.peer_namespace,
            &open_namespace(&self.plan.netns)?,
        )
    }
}

fn retired() -> LinkError {
    LinkError::Readback("veth observation has been retired".into())
}

fn require_same_namespace(expected: &File, current: &File) -> Result<(), LinkError> {
    let metadata = |file: &File| {
        file.metadata()
            .map_err(|error| LinkError::Readback(format!("namespace descriptor metadata: {error}")))
    };
    let expected = metadata(expected)?;
    let current = metadata(current)?;
    if (expected.dev(), expected.ino()) != (current.dev(), current.ino()) {
        return Err(LinkError::Readback(
            "observed namespace descriptor identity changed".into(),
        ));
    }
    Ok(())
}

fn require_same_readback(expected: &LinkReadback, current: &LinkReadback) -> Result<(), LinkError> {
    if expected != current {
        return Err(LinkError::Readback("observed veth snapshot changed".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AssignedAddress;
    use std::collections::BTreeSet;

    #[test]
    fn retained_namespace_identity_matches_duplicates_but_not_another_namespace_type() {
        let namespace = peer_identity::open_current_namespace().unwrap();
        let duplicate = namespace.try_clone().unwrap();
        assert!(require_same_namespace(&namespace, &duplicate).is_ok());
        assert!(
            require_same_namespace(
                &namespace,
                &peer_identity::open_current_namespace().unwrap()
            )
            .is_ok()
        );
        let other = File::open("/proc/thread-self/ns/mnt").unwrap();
        assert!(require_same_namespace(&namespace, &other).is_err());
        drop(namespace);
        assert!(
            require_same_namespace(
                &duplicate,
                &peer_identity::open_current_namespace().unwrap()
            )
            .is_ok()
        );
    }

    #[test]
    fn recheck_compares_every_link_snapshot_coordinate() {
        let original = LinkReadback {
            host_index: 101,
            peer_index: 101,
            host_name: "unf-test".into(),
            peer_name: "eth0".into(),
            host_address: [2, 1, 2, 3, 4, 5],
            peer_address: [2, 6, 7, 8, 9, 10],
            mtu: 1500,
            addresses: BTreeSet::from([
                AssignedAddress {
                    address: "192.0.2.2".parse().unwrap(),
                    prefix_len: 32,
                },
                AssignedAddress {
                    address: "2001:db8::2".parse().unwrap(),
                    prefix_len: 128,
                },
            ]),
        };
        assert!(require_same_readback(&original, &original).is_ok());
        for field in 0..8 {
            let mut changed = original.clone();
            match field {
                0 => changed.host_index += 1,
                1 => changed.peer_index += 1,
                2 => changed.host_name.push('x'),
                3 => changed.peer_name.push('x'),
                4 => changed.host_address[5] ^= 1,
                5 => changed.peer_address[5] ^= 1,
                6 => changed.mtu -= 1,
                7 => {
                    changed.addresses.pop_first();
                }
                _ => unreachable!(),
            }
            assert!(
                require_same_readback(&original, &changed).is_err(),
                "field {field}"
            );
        }
    }

    #[tokio::test]
    async fn failed_recheck_retires_descriptors_without_implicit_rearm() {
        let addresses = [
            AssignedAddress {
                address: "192.0.2.2".parse().unwrap(),
                prefix_len: 32,
            },
            AssignedAddress {
                address: "2001:db8::2".parse().unwrap(),
                prefix_len: 128,
            },
        ];
        let plan = VethPlan::new(
            "unf-test".into(),
            "eth0".into(),
            "/proc/unf-observation-test-not-a-process/ns/net".into(),
            1500,
            addresses,
        )
        .unwrap();
        // Synthetic private construction exercises retirement only, not kernel
        // attachment admission. Public construction always requires readback.
        let mut observation = VethObservation::new(
            plan,
            LinkReadback {
                host_index: 101,
                peer_index: 101,
                host_name: "unf-test".into(),
                peer_name: "eth0".into(),
                host_address: [2, 1, 2, 3, 4, 5],
                peer_address: [2, 6, 7, 8, 9, 10],
                mtu: 1500,
                addresses: BTreeSet::from(addresses),
            },
            peer_identity::open_current_namespace().unwrap(),
            peer_identity::open_current_namespace().unwrap(),
            NamespaceCookies::new(1, 2).unwrap(),
        );
        assert!(observation.namespace_descriptors().is_some());
        assert!(observation.namespace_cookies().is_some());
        assert!(observation.recheck().await.is_err());
        assert!(observation.namespace_descriptors().is_none());
        assert!(observation.namespace_cookies().is_none());
        assert!(
            observation
                .recheck()
                .await
                .unwrap_err()
                .to_string()
                .contains("retired")
        );
        assert!(observation.namespace_descriptors().is_none());
    }
}
