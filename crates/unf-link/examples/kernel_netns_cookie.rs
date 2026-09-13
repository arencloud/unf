//! Isolated Linux qualification helper, not production admission authority.
use std::io;
use std::net::UdpSocket;
use std::os::fd::AsRawFd;

// The current safe socket dependencies do not expose SO_NETNS_COOKIE. Keep
// this fixed-size Linux ABI call in the standalone qualification example.
#[allow(unsafe_code)]
fn cookie(socket: &UdpSocket) -> io::Result<u64> {
    unsafe extern "C" {
        fn getsockopt(fd: i32, level: i32, option: i32, value: *mut u64, length: *mut u32) -> i32;
    }
    let mut value = 0_u64;
    let mut length = 8_u32;
    // SAFETY: a live socket FD and valid writable u64/socklen_t buffers are
    // passed for the documented Linux SOL_SOCKET/SO_NETNS_COOKIE ABI. Both
    // kernel return status and the resulting fixed size are checked.
    let result = unsafe { getsockopt(socket.as_raw_fd(), 1, 71, &raw mut value, &raw mut length) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if length != 8 || value == 0 {
        return Err(io::Error::other("invalid kernel namespace cookie response"));
    }
    Ok(value)
}

fn main() -> io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    let bytes = cookie(&socket)?.to_le_bytes();
    for byte in bytes {
        print!("{byte:02x}");
    }
    println!();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_sockets_report_the_same_nonzero_namespace_cookie() {
        let first = UdpSocket::bind("0.0.0.0:0").unwrap();
        let second = UdpSocket::bind("0.0.0.0:0").unwrap();
        assert_eq!(cookie(&first).unwrap(), cookie(&second).unwrap());
        assert_ne!(cookie(&first).unwrap(), 0);
    }
}
