//! Narrow Linux `SO_NETNS_COOKIE` read on an already owned netlink socket.

use std::os::fd::AsRawFd;

use crate::LinkError;

#[allow(unsafe_code)]
pub(super) fn socket_cookie(socket: &impl AsRawFd) -> Result<u64, LinkError> {
    unsafe extern "C" {
        fn getsockopt(fd: i32, level: i32, option: i32, value: *mut u64, length: *mut u32) -> i32;
    }
    let mut value = 0_u64;
    let mut length = 8_u32;
    // SAFETY: the live borrowed socket and initialized, correctly sized Linux
    // u64/socklen_t buffers outlive this synchronous call. No pointer escapes.
    // SOL_SOCKET=1, SO_NETNS_COOKIE=71. Check status, exact length and nonzero.
    let result = unsafe { getsockopt(socket.as_raw_fd(), 1, 71, &raw mut value, &raw mut length) };
    if result != 0 {
        return Err(LinkError::Readback(format!(
            "read namespace cookie: {}",
            std::io::Error::last_os_error()
        )));
    }
    validate_cookie(value, length)
}

fn validate_cookie(value: u64, length: u32) -> Result<u64, LinkError> {
    if length != 8 || value == 0 {
        return Err(LinkError::Readback(
            "invalid kernel namespace cookie response".into(),
        ));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NamespaceCookies;

    #[test]
    fn cookie_decode_requires_exact_width_and_nonzero_distinct_roles() {
        for length in [0, 4, 7, 9, u32::MAX] {
            assert!(validate_cookie(1, length).is_err());
        }
        assert!(validate_cookie(0, 8).is_err());
        assert_eq!(validate_cookie(u64::MAX, 8).unwrap(), u64::MAX);
        for (host, peer) in [(0, 1), (1, 0), (1, 1)] {
            assert!(NamespaceCookies::new(host, peer).is_err());
        }
        let cookies = NamespaceCookies::new(1, 2).unwrap();
        assert_eq!((cookies.host(), cookies.peer()), (1, 2));
    }

    #[test]
    fn non_socket_cannot_supply_a_namespace_cookie() {
        let file = std::fs::File::open("/dev/null").unwrap();
        assert!(socket_cookie(&file).is_err());
    }
}
