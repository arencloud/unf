use super::*;
use aya::programs::tc::{NlOptions, TcAttachOptions};
use std::io::{ErrorKind, Read as _, Write as _};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::OwnedFd;

const TIMEOUT: Duration = Duration::from_secs(2);

fn in_namespace<T: Send>(namespace: &OwnedFd, action: impl FnOnce() -> T + Send) -> T {
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                rustix::thread::move_into_link_name_space(
                    namespace.as_fd(),
                    Some(rustix::thread::LinkNameSpaceType::Network),
                )
                .unwrap();
                action()
            })
            .join()
            .unwrap()
    })
}

pub(super) async fn attach(records: &[AttachmentRecord], object: &mut Ebpf) {
    for record in records {
        let links = VethPlan::from_attachment(record)
            .unwrap()
            .readback()
            .await
            .unwrap();
        aya::programs::tc::qdisc_add_clsact(&links.host_name).unwrap();
        let program: &mut SchedClassifier = object
            .program_mut("unf_observe_ingress")
            .unwrap()
            .try_into()
            .unwrap();
        program
            .attach_with_options(
                &links.host_name,
                aya::programs::TcAttachType::Ingress,
                TcAttachOptions::Netlink(NlOptions::default()),
            )
            .unwrap();
    }
}

pub(super) struct Sockets {
    source: OwnedFd,
    target: OwnedFd,
    source_addresses: [IpAddr; 2],
    target_addresses: [IpAddr; 2],
    service_addresses: [IpAddr; 2],
    service_backend_ports: [u16; 2],
    sequence: u32,
    allowed: u32,
    denied: u32,
}

fn timed_out(error: &std::io::Error) -> bool {
    matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock)
}

impl Sockets {
    pub(super) fn new(records: &[AttachmentRecord]) -> Self {
        Self {
            source: fs::File::open(&records[0].spec.netns).unwrap().into(),
            target: fs::File::open(&records[1].spec.netns).unwrap().into(),
            source_addresses: [
                records[0].lease.ipv4.address.into(),
                records[0].lease.ipv6.address.into(),
            ],
            target_addresses: [
                records[1].lease.ipv4.address.into(),
                records[1].lease.ipv6.address.into(),
            ],
            service_addresses: [
                "10.96.0.10".parse().unwrap(),
                "fd00:96::10".parse().unwrap(),
            ],
            service_backend_ports: [8080, 5353],
            sequence: 0,
            allowed: 0,
            denied: 0,
        }
    }

    pub(super) fn matrix(
        &mut self,
        name: &str,
        service: bool,
        allow: bool,
    ) -> std::ops::RangeInclusive<u16> {
        let first_port = self.source_port() + 1;
        for family in 0..2 {
            for protocol in [6, 17] {
                self.sequence += 1;
                let mut payload = vec![0x5a; 1200];
                payload[..4].copy_from_slice(&self.sequence.to_be_bytes());
                if protocol == 6 {
                    self.tcp(family, service, allow, &payload);
                } else {
                    self.udp(family, service, allow, &payload);
                }
                if allow {
                    self.allowed += 1;
                } else {
                    self.denied += 1;
                }
                println!(
                    "main-publisher-socket: case={name} family={} protocol={protocol} service={service} allowed={allow} payload-bytes={}",
                    if family == 0 { 4 } else { 6 },
                    if allow { payload.len() } else { 0 }
                );
            }
        }
        first_port..=self.source_port()
    }

    pub(super) fn dsr_frontends(&mut self) {
        self.service_addresses = [
            "192.0.2.60".parse().unwrap(),
            "2001:db8:ffff::60".parse().unwrap(),
        ];
        self.service_backend_ports = [80, 53];
    }

    fn remote(
        &self,
        family: usize,
        backend: SocketAddr,
        service: bool,
        protocol: u8,
    ) -> SocketAddr {
        if service {
            SocketAddr::new(
                self.service_addresses[family],
                if protocol == 6 { 80 } else { 53 },
            )
        } else {
            backend
        }
    }

    fn udp(&self, family: usize, service: bool, allow: bool, payload: &[u8]) {
        let receiver = in_namespace(&self.target, || {
            UdpSocket::bind(SocketAddr::new(
                self.target_addresses[family],
                if service {
                    self.service_backend_ports[1]
                } else {
                    0
                },
            ))
            .unwrap()
        });
        let sender = in_namespace(&self.source, || {
            UdpSocket::bind(SocketAddr::new(
                self.source_addresses[family],
                self.source_port(),
            ))
            .unwrap()
        });
        receiver.set_read_timeout(Some(TIMEOUT)).unwrap();
        sender.set_read_timeout(Some(TIMEOUT)).unwrap();
        let remote = self.remote(family, receiver.local_addr().unwrap(), service, 17);
        assert_eq!(sender.send_to(payload, remote).unwrap(), payload.len());
        let mut buffer = [0; 1500];
        match receiver.recv_from(&mut buffer) {
            Ok((size, source)) => {
                assert!(allow, "unexpected delivery for denied UDP case");
                assert_eq!(&buffer[..size], payload);
                assert_eq!(source, sender.local_addr().unwrap());
                assert_eq!(receiver.send_to(payload, source).unwrap(), payload.len());
                let (size, peer) = sender.recv_from(&mut buffer).unwrap();
                assert_eq!(&buffer[..size], payload);
                assert_eq!(peer, remote, "UDP reply lost exact Service/PodIP source");
            }
            Err(error) => assert!(
                !allow && timed_out(&error),
                "unexpected UDP observation: {error}"
            ),
        }
    }

    fn tcp(&self, family: usize, service: bool, allow: bool, payload: &[u8]) {
        let listener = in_namespace(&self.target, || {
            let domain = if family == 0 {
                socket2::Domain::IPV4
            } else {
                socket2::Domain::IPV6
            };
            let socket =
                socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))
                    .unwrap();
            socket.set_reuse_address(true).unwrap();
            socket
                .bind(
                    &SocketAddr::new(
                        self.target_addresses[family],
                        if service {
                            self.service_backend_ports[0]
                        } else {
                            0
                        },
                    )
                    .into(),
                )
                .unwrap();
            socket.listen(8).unwrap();
            TcpListener::from(socket)
        });
        listener.set_nonblocking(true).unwrap();
        let remote = self.remote(family, listener.local_addr().unwrap(), service, 6);
        let connection = in_namespace(&self.source, || {
            let domain = if family == 0 {
                socket2::Domain::IPV4
            } else {
                socket2::Domain::IPV6
            };
            let socket =
                socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))
                    .unwrap();
            socket
                .bind(&SocketAddr::new(self.source_addresses[family], self.source_port()).into())
                .unwrap();
            socket
                .connect_timeout(&remote.into(), TIMEOUT)
                .map(|()| TcpStream::from(socket))
        });
        match connection {
            Ok(mut sender) => {
                assert!(allow, "unexpected delivery for denied TCP case");
                assert_eq!(
                    sender.local_addr().unwrap().ip(),
                    self.source_addresses[family]
                );
                assert_eq!(sender.peer_addr().unwrap(), remote);
                let (mut receiver, source) = listener.accept().unwrap();
                assert_eq!(source, sender.local_addr().unwrap());
                for stream in [&sender, &receiver] {
                    stream.set_read_timeout(Some(TIMEOUT)).unwrap();
                    stream.set_write_timeout(Some(TIMEOUT)).unwrap();
                }
                sender.write_all(payload).unwrap();
                let mut buffer = vec![0; payload.len()];
                receiver.read_exact(&mut buffer).unwrap();
                assert_eq!(buffer, payload);
                receiver.write_all(payload).unwrap();
                sender.read_exact(&mut buffer).unwrap();
                assert_eq!(buffer, payload);
            }
            Err(error) => {
                assert!(
                    !allow && timed_out(&error),
                    "unexpected TCP observation: {error}"
                );
                assert!(
                    listener.accept().is_err_and(|error| timed_out(&error)),
                    "denied TCP reached listener"
                );
            }
        }
    }

    pub(super) fn finish(&self) {
        assert_eq!((self.allowed, self.denied), (24, 24));
        println!(
            "main-publisher-sockets: PASS allowed={} denied={} actual-policy=true bidirectional-main=true",
            self.allowed, self.denied
        );
    }

    fn source_port(&self) -> u16 {
        // No earlier live connection can satisfy a later denial check, even
        // when the Service backend port is intentionally fixed across cases.
        40_000 + u16::try_from(self.sequence).unwrap()
    }
}
