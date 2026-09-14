//! Bounded, sequenced UDP observer for private device-lifetime qualification.
use std::{
    io::{self, Write},
    net::{IpAddr, SocketAddr, UdpSocket},
    os::fd::AsRawFd,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use socket2::{Domain, Protocol, Socket, Type};

const MAX_PACKETS: usize = 32_768;
const MAGIC: &[u8; 8] = b"UNFDL001";
const PORT: u16 = 17778;

fn token(value: &str) -> Result<[u8; 16]> {
    ensure!(value.len() == 32 && value.is_ascii(), "invalid run token");
    let mut result = [0_u8; 16];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)?;
    }
    ensure!(result.iter().any(|byte| *byte != 0), "zero run token");
    Ok(result)
}

fn frame(run: &[u8; 16], family: u8, sequence: usize) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..24].copy_from_slice(run);
    bytes[24..28].copy_from_slice(
        &u32::try_from(sequence)
            .expect("bounded fixture sequence")
            .to_be_bytes(),
    );
    bytes[28] = family;
    bytes
}

fn sequence(bytes: &[u8], run: &[u8; 16], family: u8, count: usize) -> Result<usize> {
    ensure!(
        bytes.len() == 32
            && &bytes[..8] == MAGIC
            && &bytes[8..24] == run
            && bytes[28] == family
            && bytes[29..] == [0, 0, 0],
        "foreign or malformed datagram"
    );
    let sequence = u32::from_be_bytes(bytes[24..28].try_into()?) as usize;
    ensure!(sequence < count, "out-of-range sequence");
    Ok(sequence)
}

fn address(family: u8, target: bool) -> Result<SocketAddr> {
    let value = match (family, target) {
        (4, false) => "10.244.45.2:17781",
        (4, true) => "10.244.46.2:17778",
        (6, false) => "[fd45::2]:17781",
        (6, true) => "[fd46::2]:17778",
        _ => bail!("unsupported address family"),
    };
    Ok(value.parse()?)
}

fn udp(family: u8, bind: SocketAddr) -> Result<UdpSocket> {
    let socket = Socket::new(
        if family == 4 {
            Domain::IPV4
        } else {
            Domain::IPV6
        },
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    if family == 6 {
        socket.set_only_v6(true)?;
    }
    socket.set_recv_buffer_size(1024 * 1024)?;
    socket.bind(&bind.into())?;
    Ok(socket.into())
}

// Linux reports receive-queue bytes and the socket's cumulative drop count.
// Inspect the exact live socket inode before closing it; missing/ambiguous
// rows and nonzero residual queues are observation failures, not zero loss.
fn socket_accounting(table: &str, inode: &str) -> Result<(u64, u64)> {
    let rows: Vec<_> = table
        .lines()
        .skip(1)
        .map(|line| line.split_whitespace().collect::<Vec<_>>())
        .filter(|fields| fields.get(9).copied() == Some(inode))
        .collect();
    ensure!(
        rows.len() == 1,
        "missing or ambiguous UDP socket accounting"
    );
    let row = &rows[0];
    ensure!(row.len() == 13, "unexpected UDP socket accounting shape");
    let (_, queue) = row[4].split_once(':').context("missing receive queue")?;
    Ok((u64::from_str_radix(queue, 16)?, row[12].parse()?))
}

fn accounting(socket: &UdpSocket, family: u8) -> Result<(u64, u64)> {
    let descriptor = std::fs::read_link(format!("/proc/self/fd/{}", socket.as_raw_fd()))?;
    let descriptor = descriptor.to_str().context("non-UTF8 socket inode")?;
    let inode = descriptor
        .strip_prefix("socket:[")
        .and_then(|value| value.strip_suffix(']'))
        .context("unexpected socket descriptor")?;
    ensure!(
        !inode.is_empty() && inode.bytes().all(|byte| byte.is_ascii_digit()),
        "invalid socket inode"
    );
    let path = if family == 4 {
        "/proc/self/net/udp"
    } else {
        "/proc/self/net/udp6"
    };
    socket_accounting(&std::fs::read_to_string(path)?, inode)
}

fn receive(run: [u8; 16], family: u8, count: usize, seconds: u64) -> Result<()> {
    ensure!((2..=60).contains(&seconds), "invalid receiver duration");
    let ip: IpAddr = if family == 4 { "0.0.0.0" } else { "::" }.parse()?;
    let socket = udp(family, SocketAddr::new(ip, PORT))?;
    socket.set_nonblocking(true)?;
    ensure!(
        accounting(&socket, family)? == (0, 0),
        "dirty initial socket accounting"
    );
    let mut observed = vec![false; count];
    let mut received = 0_usize;
    let mut buffer = [0_u8; 64];
    let expected_sender = address(family, false)?;
    let deadline = Instant::now() + Duration::from_secs(seconds);
    eprintln!("receiver-ready family={family}");
    io::stderr().flush()?;
    while Instant::now() < deadline {
        match socket.recv_from(&mut buffer) {
            Ok((length, sender)) => {
                ensure!(sender == expected_sender, "unexpected sender");
                let index = sequence(&buffer[..length], &run, family, count)?;
                ensure!(!observed[index], "duplicate sequence");
                observed[index] = true;
                received += 1;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_micros(500));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    let (queued, drops) = accounting(&socket, family)?;
    ensure!(
        queued == 0 && drops == 0,
        "receiver queue loss or undrained data"
    );
    let sequences: Vec<_> = observed
        .iter()
        .enumerate()
        .filter_map(|(index, present)| present.then_some(index))
        .collect();
    println!(
        "{}",
        serde_json::json!({"schemaVersion":1,"role":"receiver",
        "family":family,"runToken":run,"received":received,"sequences":sequences,
        "socketDrops":drops,"queuedBytes":queued,"productionAuthority":false})
    );
    Ok(())
}

fn send(run: [u8; 16], family: u8, count: usize, interval_us: u64) -> Result<()> {
    ensure!(
        (500..=100_000).contains(&interval_us),
        "invalid send interval"
    );
    ensure!(
        (count as u64) * interval_us <= 30_000_000,
        "send window too long"
    );
    let socket = udp(family, address(family, false)?)?;
    let target = address(family, true)?;
    let start = Instant::now();
    let mut next = start;
    for index in 0..count {
        ensure!(
            socket.send_to(&frame(&run, family, index), target)? == 32,
            "short UDP send"
        );
        next += Duration::from_micros(interval_us);
        // No catch-up burst if the qualified environment schedules us late.
        if let Some(wait) = next.checked_duration_since(Instant::now()) {
            std::thread::sleep(wait);
        } else {
            next = Instant::now();
        }
    }
    println!(
        "{}",
        serde_json::json!({"schemaVersion":1,"role":"sender",
        "family":family,"runToken":run,"sent":count,"elapsedNanos":start.elapsed().as_nanos(),
        "productionAuthority":false})
    );
    Ok(())
}

fn main() -> Result<()> {
    ensure!(
        std::env::var("UNF_DEVICE_OBSERVATION_ISOLATED_CONTAINER").as_deref() == Ok("yes"),
        "isolated fixture opt-in required"
    );
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure!(
        args.len() == 5,
        "expected receive|send, token, family, packet count, seconds|interval-us"
    );
    let run = token(&args[1])?;
    let family = args[2].parse()?;
    let count = args[3].parse()?;
    ensure!((1..=MAX_PACKETS).contains(&count), "invalid packet bound");
    address(family, false)?;
    match args[0].as_str() {
        "receive" => receive(run, family, count, args[4].parse()?),
        "send" => send(run, family, count, args[4].parse()?),
        _ => bail!("unknown traffic operation"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_frame_rejects_cross_run_family_padding_and_range() {
        let run = token("0123456789abcdef0123456789abcdef").unwrap();
        for family in [4, 6] {
            let bytes = frame(&run, family, 17);
            assert_eq!(sequence(&bytes, &run, family, 18).unwrap(), 17);
            assert!(sequence(&bytes, &run, family, 17).is_err());
            for index in 0..32 {
                if (24..28).contains(&index) {
                    continue;
                }
                let mut corrupt = bytes;
                corrupt[index] ^= 1;
                assert!(sequence(&corrupt, &run, family, 18).is_err());
            }
            assert!(sequence(&bytes[..31], &run, family, 18).is_err());
        }
        for value in [
            "",
            "00000000000000000000000000000000",
            "zz23456789abcdef0123456789abcdef",
            "é23456789abcdef0123456789abcdef",
        ] {
            assert!(token(value).is_err());
        }
    }

    #[test]
    fn socket_accounting_requires_exact_inode_and_reports_queue_and_loss() {
        let row = "header\n 1: 00000000:4572 00000000:0000 07 00000000:00000080 00:00000000 00000000 0 0 12345 2 0000000000000000 7\n";
        assert_eq!(socket_accounting(row, "12345").unwrap(), (128, 7));
        assert!(socket_accounting(row, "1234").is_err());
        assert!(
            socket_accounting(&format!("{row}{}", row.lines().nth(1).unwrap()), "12345").is_err()
        );
        assert!(socket_accounting(&row.replace(" 7\n", "\n"), "12345").is_err());
    }

    #[test]
    fn live_loopback_socket_accounting_is_readable() {
        for family in [4, 6] {
            let ip: IpAddr = if family == 4 { "127.0.0.1" } else { "::1" }
                .parse()
                .unwrap();
            let socket = udp(family, SocketAddr::new(ip, 0)).unwrap();
            assert_eq!(accounting(&socket, family).unwrap(), (0, 0));
        }
    }
}
