//! Actual private-namespace sockets. Trusted input is still synthetic; only the
//! forward direction consumes the bank, while replies use private native routes.
use std::io::{ErrorKind, Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::{AsFd as _, OwnedFd};
use std::time::Duration;

use anyhow::{Context as _, Result, ensure};
use aya::{
    Ebpf,
    maps::Array,
    programs::{
        SchedClassifier, TcAttachType,
        tc::{self, NlOptions, TcAttachOptions},
    },
};
use rustix::thread::{LinkNameSpaceType, move_into_link_name_space};
use unf_ebpf_common::locality::PacketInput;
use unf_locality::LeasedLocalityBank;

use super::Input;

const TIMEOUT: Duration = Duration::from_secs(2);

pub struct Delivery {
    source: OwnedFd,
    target: OwnedFd,
    sequence: u32,
    allowed: u32,
    denied: u32,
}

// Namespace changes are contained in a fresh joined OS thread. Returned sockets
// keep their creation namespace; no Tokio worker ever changes namespace.
fn in_namespace<T: Send>(
    namespace: &OwnedFd,
    action: impl FnOnce() -> Result<T> + Send,
) -> Result<T> {
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                move_into_link_name_space(namespace.as_fd(), Some(LinkNameSpaceType::Network))?;
                action()
            })
            .join()
            .map_err(|_| anyhow::anyhow!("socket namespace worker panicked"))?
    })
}

fn address(input: PacketInput, source: bool) -> IpAddr {
    let bytes = if source {
        input.source_address
    } else {
        input.destination_address
    };
    if input.family == 4 {
        Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).into()
    } else {
        Ipv6Addr::from(bytes).into()
    }
}

fn configure(object: &mut Ebpf, input: PacketInput) -> Result<()> {
    let mut map: Array<_, Input> =
        Array::try_from(object.map_mut("UL_FIXTURE_V1").context("fixture input")?)?;
    map.set(0, Input(input), 0)?;
    Ok(())
}

fn timeout(error: &std::io::Error) -> bool {
    matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock)
}

impl Delivery {
    pub fn attach(leased: &LeasedLocalityBank, object: &mut Ebpf) -> Result<Self> {
        let endpoints = leased
            .observed()
            .endpoints()
            .context("retired delivery endpoints")?;
        ensure!(endpoints.len() == 2, "delivery endpoint count");
        let source = endpoints[0]
            .namespace_descriptors()
            .context("source namespaces")?
            .1
            .as_fd()
            .try_clone_to_owned()?;
        let target = endpoints[1]
            .namespace_descriptors()
            .context("target namespaces")?
            .1
            .as_fd()
            .try_clone_to_owned()?;
        let interface = &endpoints[0].readback().context("source links")?.0.host_name;
        // This is the just-created, exact private fixture interface, not a host
        // production interface. Reject any unexpected pre-existing clsact.
        tc::qdisc_add_clsact(interface)?;
        let program: &mut SchedClassifier = object
            .program_mut("unf_locality_fixture")
            .context("fixture classifier")?
            .try_into()?;
        program.attach_with_options(
            interface,
            TcAttachType::Ingress,
            TcAttachOptions::Netlink(NlOptions::default()),
        )?;
        // Aya owns/detaches the link; the outer fixture also verifies all private
        // links are gone. No persistent attachment or forgotten guard.
        Ok(Self {
            source,
            target,
            sequence: 0,
            allowed: 0,
            denied: 0,
        })
    }

    pub fn check(
        &mut self,
        object: &mut Ebpf,
        name: &str,
        input: PacketInput,
        protocol: u8,
        allow: bool,
    ) -> Result<()> {
        self.sequence += 1;
        // Unique bounded application payload; no old packet can satisfy a new
        // observation. Each case uses fresh sockets and a kernel-selected port.
        let mut payload = vec![0x5a; 1200];
        payload[..4].copy_from_slice(&self.sequence.to_be_bytes());
        match protocol {
            17 => self.udp(object, input, &payload, allow)?,
            6 => self.tcp(object, input, &payload, allow)?,
            _ => anyhow::bail!("unsupported socket fixture protocol"),
        }
        if allow {
            self.allowed += 1;
        } else {
            self.denied += 1;
        }
        println!(
            "kernel-locality-delivery: name={name} family={} protocol={protocol} delivered={allow} reply-native={allow} bytes={} production-policy=false",
            input.family,
            if allow { payload.len() } else { 0 }
        );
        Ok(())
    }

    fn udp(
        &self,
        object: &mut Ebpf,
        mut input: PacketInput,
        payload: &[u8],
        allow: bool,
    ) -> Result<()> {
        let receiver = in_namespace(&self.target, || {
            Ok(UdpSocket::bind(SocketAddr::new(address(input, false), 0))?)
        })?;
        let sender = in_namespace(&self.source, || {
            Ok(UdpSocket::bind(SocketAddr::new(address(input, true), 0))?)
        })?;
        receiver.set_read_timeout(Some(TIMEOUT))?;
        sender.set_read_timeout(Some(TIMEOUT))?;
        input.protocol = 17;
        input.source_port = sender.local_addr()?.port().to_be_bytes();
        input.destination_port = receiver.local_addr()?.port().to_be_bytes();
        configure(object, input)?;
        ensure!(
            sender.send_to(payload, receiver.local_addr()?)? == payload.len(),
            "short UDP send"
        );
        let mut buffer = [0; 1500];
        match receiver.recv_from(&mut buffer) {
            Ok((size, source)) => {
                ensure!(
                    allow && &buffer[..size] == payload && source == sender.local_addr()?,
                    "unexpected UDP delivery/source/payload"
                );
                ensure!(
                    receiver.send_to(payload, source)? == payload.len(),
                    "short UDP reply"
                );
                let (size, peer) = sender.recv_from(&mut buffer)?;
                ensure!(
                    &buffer[..size] == payload && peer == receiver.local_addr()?,
                    "UDP reply mismatch"
                );
            }
            Err(error) => ensure!(
                !allow && timeout(&error),
                "unexpected UDP observation: {error}"
            ),
        }
        Ok(())
    }

    fn tcp(
        &self,
        object: &mut Ebpf,
        mut input: PacketInput,
        payload: &[u8],
        allow: bool,
    ) -> Result<()> {
        let listener = in_namespace(&self.target, || {
            Ok(TcpListener::bind(SocketAddr::new(
                address(input, false),
                0,
            ))?)
        })?;
        listener.set_nonblocking(true)?;
        input.protocol = 6;
        input.destination_port = listener.local_addr()?.port().to_be_bytes();
        // The bank intentionally routes using the actual wire source port;
        // original source-port metadata is not a permission in this fixture.
        configure(object, input)?;
        let remote = listener.local_addr()?;
        let connection = in_namespace(&self.source, || {
            Ok(TcpStream::connect_timeout(&remote, TIMEOUT))
        })?;
        match connection {
            Ok(mut sender) => {
                ensure!(
                    allow && sender.local_addr()?.ip() == address(input, true),
                    "unexpected TCP connection/source"
                );
                let (mut receiver, source) = listener.accept()?;
                ensure!(source == sender.local_addr()?, "TCP peer mismatch");
                for stream in [&sender, &receiver] {
                    stream.set_read_timeout(Some(TIMEOUT))?;
                    stream.set_write_timeout(Some(TIMEOUT))?;
                }
                sender.write_all(payload)?;
                let mut buffer = vec![0; payload.len()];
                receiver.read_exact(&mut buffer)?;
                ensure!(buffer == payload, "TCP delivery payload mismatch");
                receiver.write_all(payload)?;
                sender.read_exact(&mut buffer)?;
                ensure!(buffer == payload, "TCP reply payload mismatch");
            }
            Err(error) => {
                ensure!(
                    !allow && timeout(&error),
                    "unexpected TCP connect result: {error}"
                );
                ensure!(
                    matches!(listener.accept(), Err(error) if error.kind() == ErrorKind::WouldBlock),
                    "denied TCP reached listener"
                );
            }
        }
        Ok(())
    }

    pub fn finish(&self) -> Result<()> {
        ensure!(
            self.allowed == 8 && self.denied == 16,
            "incomplete socket matrix: allowed={} denied={}",
            self.allowed,
            self.denied
        );
        println!(
            "kernel-locality-delivery: PASS allowed=8 denied=16 protocols=tcp,udp families=4,6 request-bank=true reply-native=true production-policy=false"
        );
        Ok(())
    }
}

pub fn pair(
    delivery: &mut Option<Delivery>,
    object: &mut Ebpf,
    name: &str,
    inputs: [PacketInput; 2],
    protocols: &[u8],
    allow: bool,
) -> Result<()> {
    if let Some(delivery) = delivery {
        for input in inputs {
            for protocol in protocols {
                delivery
                    .check(object, name, input, *protocol, allow)
                    .with_context(|| {
                        format!(
                            "socket case {name} family={} protocol={protocol}",
                            input.family
                        )
                    })?;
            }
        }
    }
    Ok(())
}
