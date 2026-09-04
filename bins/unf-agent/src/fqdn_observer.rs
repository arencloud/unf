use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use unf_common::Revision;
use unf_egress::{
    DEFAULT_EGRESS_FQDN_VIEW, EGRESS_FQDN_OBSERVATION_BATCH_SCHEMA_VERSION, EgressDnsAnswer,
    EgressDnsObservation, EgressDnsObservationSource, EgressFqdnObservationBatch,
    MAX_EGRESS_FQDN_CNAME_DEPTH, MAX_EGRESS_FQDN_OBSERVATIONS,
};

const DNS_TIMEOUT: Duration = Duration::from_secs(2);
const DNS_MAX_MESSAGE: usize = 4_096;
const MIN_REFRESH_SECONDS: u64 = 5;
const MAX_REFRESH_SECONDS: u64 = 60;

#[derive(Debug, Clone)]
pub struct FqdnObserver {
    source_epoch: u64,
    batch_revision: Revision,
    targets: BTreeSet<String>,
    next_refresh_unix_seconds: u64,
}

#[derive(Debug)]
struct ParsedDns {
    canonical_chain: Vec<String>,
    answers: Vec<EgressDnsAnswer>,
}

impl FqdnObserver {
    #[must_use]
    pub fn new(source_epoch: u64) -> Self {
        Self {
            source_epoch: source_epoch.max(1),
            batch_revision: Revision::INITIAL,
            targets: BTreeSet::new(),
            next_refresh_unix_seconds: 0,
        }
    }

    /// Produces one complete replacement batch. A failed lookup returns an
    /// error and publishes nothing, preserving the ledger's distinction
    /// between observation loss and authoritative empty DNS data.
    pub async fn observe(
        &mut self,
        observer_node_uid: &str,
        targets: BTreeSet<String>,
        now_unix_seconds: u64,
        resolv_conf: &Path,
    ) -> Result<Option<EgressFqdnObservationBatch>> {
        if targets.len() > MAX_EGRESS_FQDN_OBSERVATIONS {
            bail!("exact FQDN observation target set exceeds its atomic batch bound");
        }
        if targets == self.targets && now_unix_seconds < self.next_refresh_unix_seconds {
            return Ok(None);
        }
        let next_revision = self.batch_revision.next();
        if next_revision == self.batch_revision {
            bail!("FQDN observation revision is exhausted");
        }
        if targets.is_empty() {
            if self.targets.is_empty() {
                return Ok(None);
            }
            self.batch_revision = next_revision;
            self.targets.clear();
            self.next_refresh_unix_seconds = 0;
            return Ok(Some(EgressFqdnObservationBatch {
                schema_version: EGRESS_FQDN_OBSERVATION_BATCH_SCHEMA_VERSION,
                observer_node_uid: observer_node_uid.to_owned(),
                source_epoch: self.source_epoch,
                batch_revision: next_revision,
                view: DEFAULT_EGRESS_FQDN_VIEW.to_owned(),
                collected_at_unix_seconds: now_unix_seconds,
                observations: Vec::new(),
            }));
        }
        let resolver = resolver_from_resolv_conf(resolv_conf)?;
        let mut observations = Vec::with_capacity(targets.len());
        let mut minimum_ttl = u32::MAX;
        for query_name in &targets {
            let parsed = query_dual_stack(resolver, query_name, next_revision.get()).await?;
            for answer in &parsed.answers {
                minimum_ttl = minimum_ttl.min(answer.ttl_seconds);
            }
            observations.push(EgressDnsObservation {
                source: EgressDnsObservationSource {
                    observer_uid: observer_node_uid.to_owned(),
                    resolver: resolver.ip(),
                    view: DEFAULT_EGRESS_FQDN_VIEW.to_owned(),
                    source_epoch: self.source_epoch,
                },
                observation_revision: next_revision,
                query_name: query_name.clone(),
                canonical_chain: parsed.canonical_chain,
                answers: parsed.answers,
                observed_at_unix_seconds: now_unix_seconds,
            });
        }
        let refresh = if minimum_ttl == u32::MAX {
            MIN_REFRESH_SECONDS
        } else {
            (u64::from(minimum_ttl) / 2).clamp(MIN_REFRESH_SECONDS, MAX_REFRESH_SECONDS)
        };
        let batch = EgressFqdnObservationBatch {
            schema_version: EGRESS_FQDN_OBSERVATION_BATCH_SCHEMA_VERSION,
            observer_node_uid: observer_node_uid.to_owned(),
            source_epoch: self.source_epoch,
            batch_revision: next_revision,
            view: DEFAULT_EGRESS_FQDN_VIEW.to_owned(),
            collected_at_unix_seconds: now_unix_seconds,
            observations,
        };
        self.batch_revision = next_revision;
        self.targets = targets;
        self.next_refresh_unix_seconds = now_unix_seconds.saturating_add(refresh);
        Ok(Some(batch))
    }
}

fn resolver_from_resolv_conf(path: &Path) -> Result<SocketAddr> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("read DNS resolver configuration {}", path.display()))?;
    content
        .lines()
        .find_map(|line| {
            let line = line.split('#').next()?.trim();
            let value = line.strip_prefix("nameserver")?.trim();
            value
                .split_ascii_whitespace()
                .next()?
                .parse::<IpAddr>()
                .ok()
        })
        .map(|address| SocketAddr::new(address, 53))
        .context("resolver configuration contains no usable nameserver")
}

async fn query_dual_stack(
    resolver: SocketAddr,
    query_name: &str,
    revision: u64,
) -> Result<ParsedDns> {
    let a = query_dns(
        resolver,
        query_name,
        1,
        transaction_id(query_name, revision, 1),
    )
    .await?;
    let aaaa = query_dns(
        resolver,
        query_name,
        28,
        transaction_id(query_name, revision, 28),
    )
    .await?;
    let canonical_chain = if a.answers.is_empty() {
        aaaa.canonical_chain.clone()
    } else if aaaa.answers.is_empty() || a.canonical_chain == aaaa.canonical_chain {
        a.canonical_chain.clone()
    } else {
        bail!("A and AAAA responses disagree on the canonical CNAME chain");
    };
    let mut answers = a.answers;
    answers.extend(aaaa.answers);
    answers.sort_unstable();
    answers.dedup();
    Ok(ParsedDns {
        canonical_chain,
        answers,
    })
}

async fn query_dns(
    resolver: SocketAddr,
    query_name: &str,
    query_type: u16,
    id: u16,
) -> Result<ParsedDns> {
    let query = encode_query(query_name, query_type, id)?;
    let bind = if resolver.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind)
        .await
        .context("bind DNS observation socket")?;
    socket
        .connect(resolver)
        .await
        .context("connect DNS observation socket")?;
    socket
        .send(&query)
        .await
        .context("send DNS observation query")?;
    let mut response = vec![0_u8; DNS_MAX_MESSAGE];
    let size = timeout(DNS_TIMEOUT, socket.recv(&mut response))
        .await
        .context("DNS observation query timed out")??;
    response.truncate(size);
    if response.get(2).is_some_and(|flags| flags & 0x02 != 0) {
        response = query_dns_tcp(resolver, &query).await?;
    }
    parse_response(&response, query_name, query_type, id)
}

async fn query_dns_tcp(resolver: SocketAddr, query: &[u8]) -> Result<Vec<u8>> {
    let mut stream = timeout(DNS_TIMEOUT, TcpStream::connect(resolver))
        .await
        .context("DNS TCP connection timed out")??;
    let length = u16::try_from(query.len()).context("DNS query exceeds TCP framing")?;
    timeout(DNS_TIMEOUT, async {
        stream.write_all(&length.to_be_bytes()).await?;
        stream.write_all(query).await?;
        let mut header = [0_u8; 2];
        stream.read_exact(&mut header).await?;
        let response_length = usize::from(u16::from_be_bytes(header));
        if response_length > DNS_MAX_MESSAGE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DNS response exceeds bound",
            ));
        }
        let mut response = vec![0_u8; response_length];
        stream.read_exact(&mut response).await?;
        Ok(response)
    })
    .await
    .context("DNS TCP exchange timed out")?
    .context("DNS TCP exchange failed")
}

fn encode_query(name: &str, query_type: u16, id: u16) -> Result<Vec<u8>> {
    let mut message = Vec::with_capacity(512);
    message.extend_from_slice(&id.to_be_bytes());
    message.extend_from_slice(&0x0100_u16.to_be_bytes());
    message.extend_from_slice(&1_u16.to_be_bytes());
    message.extend_from_slice(&[0; 6]);
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            bail!("invalid canonical DNS observation target");
        }
        message.push(u8::try_from(label.len())?);
        message.extend_from_slice(label.as_bytes());
    }
    message.push(0);
    message.extend_from_slice(&query_type.to_be_bytes());
    message.extend_from_slice(&1_u16.to_be_bytes());
    if message.len() > 512 {
        bail!("DNS observation query exceeds the UDP compatibility bound");
    }
    Ok(message)
}

fn parse_response(message: &[u8], query_name: &str, query_type: u16, id: u16) -> Result<ParsedDns> {
    if message.len() < 12 || u16::from_be_bytes([message[0], message[1]]) != id {
        bail!("DNS response has an invalid header or transaction ID");
    }
    let flags = u16::from_be_bytes([message[2], message[3]]);
    let rcode = flags & 0x000f;
    if flags & 0x8000 == 0 || flags & 0x7800 != 0 || !matches!(rcode, 0 | 3) {
        bail!("DNS response is not an authoritative empty or successful answer");
    }
    if u16::from_be_bytes([message[4], message[5]]) != 1 {
        bail!("DNS response question count is not exactly one");
    }
    let answer_count = usize::from(u16::from_be_bytes([message[6], message[7]]));
    if answer_count > 128 {
        bail!("DNS answer section exceeds its parser bound");
    }
    let (question_name, mut offset) = read_name(message, 12)?;
    if offset.checked_add(4).is_none_or(|end| end > message.len()) {
        bail!("DNS question is truncated");
    }
    let response_type = u16::from_be_bytes([message[offset], message[offset + 1]]);
    let response_class = u16::from_be_bytes([message[offset + 2], message[offset + 3]]);
    if question_name != query_name || response_type != query_type || response_class != 1 {
        bail!("DNS response question does not match the issued query");
    }
    offset += 4;
    let mut cnames = BTreeMap::<String, (String, u32)>::new();
    let mut addresses = Vec::<(String, IpAddr, u32)>::new();
    for _ in 0..answer_count {
        let (owner, next) = read_name(message, offset)?;
        offset = next;
        if offset.checked_add(10).is_none_or(|end| end > message.len()) {
            bail!("DNS resource record is truncated");
        }
        let kind = u16::from_be_bytes([message[offset], message[offset + 1]]);
        let class = u16::from_be_bytes([message[offset + 2], message[offset + 3]]);
        let ttl = u32::from_be_bytes(message[offset + 4..offset + 8].try_into()?);
        let rdlen = usize::from(u16::from_be_bytes([
            message[offset + 8],
            message[offset + 9],
        ]));
        let rdata = offset + 10;
        let end = rdata.checked_add(rdlen).context("DNS RDATA overflow")?;
        if end > message.len() {
            bail!("DNS RDATA is truncated");
        }
        if class == 1 && kind == 5 {
            let (target, _) = read_name(message, rdata)?;
            if cnames.insert(owner, (target, ttl)).is_some() {
                bail!("DNS response contains ambiguous CNAME ownership");
            }
        } else if class == 1 && kind == query_type && kind == 1 && rdlen == 4 {
            addresses.push((
                owner,
                IpAddr::V4(Ipv4Addr::new(
                    message[rdata],
                    message[rdata + 1],
                    message[rdata + 2],
                    message[rdata + 3],
                )),
                ttl,
            ));
        } else if class == 1 && kind == query_type && kind == 28 && rdlen == 16 {
            addresses.push((
                owner,
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&message[rdata..end])?)),
                ttl,
            ));
        }
        offset = end;
    }
    let mut chain = vec![query_name.to_owned()];
    let mut canonical = query_name.to_owned();
    let mut chain_ttl = u32::MAX;
    let mut seen = BTreeSet::from([canonical.clone()]);
    for _ in 0..MAX_EGRESS_FQDN_CNAME_DEPTH {
        let Some((next, ttl)) = cnames.get(&canonical) else {
            break;
        };
        if !seen.insert(next.clone()) {
            bail!("DNS response contains a CNAME loop");
        }
        chain_ttl = chain_ttl.min(*ttl);
        canonical = next.clone();
        chain.push(canonical.clone());
    }
    if cnames.contains_key(&canonical) {
        bail!("DNS response exceeds the CNAME depth bound");
    }
    let answers = addresses
        .into_iter()
        .filter(|(owner, _, _)| owner == &canonical)
        .map(|(_, address, ttl)| EgressDnsAnswer {
            address,
            ttl_seconds: ttl.min(chain_ttl),
        })
        .collect();
    Ok(ParsedDns {
        canonical_chain: chain,
        answers,
    })
}

fn read_name(message: &[u8], start: usize) -> Result<(String, usize)> {
    let mut labels = Vec::new();
    let mut offset = start;
    let mut consumed = None;
    let mut jumps = 0;
    loop {
        let length = *message.get(offset).context("DNS name is truncated")?;
        if length & 0xc0 == 0xc0 {
            let low = *message
                .get(offset + 1)
                .context("DNS pointer is truncated")?;
            let pointer = usize::from(u16::from_be_bytes([length & 0x3f, low]));
            consumed.get_or_insert(offset + 2);
            offset = pointer;
            jumps += 1;
            if jumps > MAX_EGRESS_FQDN_CNAME_DEPTH || offset >= message.len() {
                bail!("DNS compression pointer is invalid or cyclic");
            }
            continue;
        }
        if length & 0xc0 != 0 {
            bail!("DNS label uses an unsupported encoding");
        }
        offset += 1;
        if length == 0 {
            let end = consumed.unwrap_or(offset);
            let name = labels.join(".").to_ascii_lowercase();
            if name.is_empty() {
                bail!("DNS root name is not a valid observation target");
            }
            return Ok((name, end));
        }
        let end = offset
            .checked_add(usize::from(length))
            .context("DNS label overflow")?;
        let bytes = message.get(offset..end).context("DNS label is truncated")?;
        let label = std::str::from_utf8(bytes).context("DNS label is not ASCII")?;
        if !label.is_ascii() {
            bail!("DNS label is not ASCII");
        }
        labels.push(label.to_owned());
        offset = end;
    }
}

fn transaction_id(name: &str, revision: u64, query_type: u16) -> u16 {
    let mut hash = revision ^ u64::from(query_type);
    for byte in name.bytes() {
        hash = hash.rotate_left(5) ^ u64::from(byte);
    }
    let folded = (hash ^ (hash >> 16)).to_le_bytes();
    u16::from_le_bytes([folded[0], folded[1]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn removing_the_last_target_publishes_one_authoritative_empty_batch() {
        let mut observer = FqdnObserver::new(17);
        observer.batch_revision = Revision::new(4);
        observer.targets.insert("api.example.test".to_owned());
        observer.next_refresh_unix_seconds = 10_000;

        let batch = observer
            .observe(
                "node-uid-a",
                BTreeSet::new(),
                100,
                Path::new("/path/is/not/read"),
            )
            .await
            .unwrap()
            .expect("last-target removal must be authoritative");
        assert_eq!(batch.batch_revision, Revision::new(5));
        assert!(batch.observations.is_empty());
        assert!(observer.targets.is_empty());
        assert_eq!(observer.next_refresh_unix_seconds, 0);

        assert!(
            observer
                .observe(
                    "node-uid-a",
                    BTreeSet::new(),
                    101,
                    Path::new("/path/is/not/read"),
                )
                .await
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn resolver_parser_accepts_ipv4_and_ipv6_and_rejects_missing_state() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("resolv.conf");
        std::fs::write(&path, "search cluster.local\nnameserver 2001:db8::53\n").unwrap();
        assert_eq!(
            resolver_from_resolv_conf(&path).unwrap(),
            "[2001:db8::53]:53".parse().unwrap()
        );
        std::fs::write(&path, "options ndots:5\n").unwrap();
        assert!(resolver_from_resolv_conf(&path).is_err());
    }

    #[test]
    fn parser_preserves_cname_ttl_as_an_authority_bound() {
        let query = encode_query("api.example.test", 1, 7).unwrap();
        let mut response = query;
        response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        response[6..8].copy_from_slice(&2_u16.to_be_bytes());
        response.extend_from_slice(&[0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 30, 0, 9]);
        response.extend_from_slice(&[6, b't', b'a', b'r', b'g', b'e', b't', 0xc0, 0x10]);
        response.extend_from_slice(&[0xc0, 0x2e, 0, 1, 0, 1, 0, 0, 0, 120, 0, 4, 192, 0, 2, 10]);
        let parsed = parse_response(&response, "api.example.test", 1, 7).unwrap();
        assert_eq!(
            parsed.canonical_chain,
            ["api.example.test", "target.example.test"]
        );
        assert_eq!(
            parsed.answers,
            [EgressDnsAnswer {
                address: "192.0.2.10".parse().unwrap(),
                ttl_seconds: 30
            }]
        );
    }

    #[test]
    fn malformed_compression_and_failure_rcodes_are_observation_loss() {
        let mut response = encode_query("api.example.test", 1, 9).unwrap();
        response[2..4].copy_from_slice(&0x8182_u16.to_be_bytes());
        assert!(parse_response(&response, "api.example.test", 1, 9).is_err());
        response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        response[6..8].copy_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&[0xc0, 0xff, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 1, 1, 1, 1]);
        assert!(parse_response(&response, "api.example.test", 1, 9).is_err());
    }
}
