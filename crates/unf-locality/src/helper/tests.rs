use super::*;
use rustix::net::{SocketFlags, socketpair};
use rustix::process::{getgid, getpid, getuid};
use std::fs::File;

fn credentials() -> UCred {
    UCred {
        pid: getpid(),
        uid: getuid(),
        gid: getgid(),
    }
}

fn pair() -> (PrivateMountChannel, PrivateMountChannel) {
    let (left, right) = socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .unwrap();
    (
        PrivateMountChannel::authenticate(left, credentials()).unwrap(),
        PrivateMountChannel::authenticate(right, credentials()).unwrap(),
    )
}

fn request() -> [u8; FRAME_SIZE] {
    let mut frame = [1_u8; FRAME_SIZE];
    frame[..8].copy_from_slice(REQUEST);
    frame
}

#[test]
fn kernel_credentials_and_socket_type_are_mandatory() {
    let (socket, _other) = socketpair(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC,
        None,
    )
    .unwrap();
    assert!(PrivateMountChannel::authenticate(socket, credentials()).is_err());
    let (socket, _other) = socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .unwrap();
    let mut wrong = credentials();
    wrong.pid = rustix::process::Pid::from_raw(getpid().as_raw_pid() + 1).unwrap();
    assert!(PrivateMountChannel::authenticate(socket, wrong).is_err());
    assert!(
        PrivateMountChannel::authenticate(File::open("/dev/null").unwrap().into(), credentials())
            .is_err()
    );
}

#[test]
fn framed_transport_carries_only_owned_close_on_exec_descriptors() {
    let (sender, receiver) = pair();
    let file = File::open("/dev/null").unwrap();
    sender.send(&request(), &[file.as_fd()]).unwrap();
    let (frame, descriptors) = receiver.receive().unwrap();
    assert_eq!(frame, request());
    assert_eq!(descriptors.len(), 1);
    assert!(
        rustix::io::fcntl_getfd(&descriptors[0])
            .unwrap()
            .contains(rustix::io::FdFlags::CLOEXEC)
    );
    assert_eq!(
        fstat(&file).unwrap().st_rdev,
        fstat(&descriptors[0]).unwrap().st_rdev
    );
}

#[test]
fn size_truncation_disconnect_and_unknown_operation_fail_before_allocation() {
    for length in [0, 1, FRAME_SIZE - 1, FRAME_SIZE + 1, 8192] {
        let (sender, receiver) = pair();
        sender.send(&vec![1; length], &[]).unwrap();
        assert!(receiver.receive().is_err(), "accepted length {length}");
    }
    let (sender, receiver) = pair();
    drop(sender);
    assert!(receiver.receive().is_err());
    for frame in [[0; FRAME_SIZE], [1; FRAME_SIZE]] {
        let (sender, receiver) = pair();
        sender.send(&frame, &[]).unwrap();
        let error = receiver.serve().unwrap_err();
        assert!(error.to_string().contains("request version or nonce"));
    }
}

#[test]
fn inbound_fds_and_excess_ancillary_data_are_rejected() {
    let file = File::open("/dev/null").unwrap();
    let (sender, receiver) = pair();
    sender.send(&request(), &[file.as_fd()]).unwrap();
    assert!(
        receiver
            .serve()
            .unwrap_err()
            .to_string()
            .contains("no client descriptors")
    );
    for count in [2, 3, 32] {
        let (sender, receiver) = pair();
        let descriptors = vec![file.as_fd(); count];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(32))];
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        assert!(ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)));
        sendmsg(
            &sender.socket,
            &[IoSlice::new(&request())],
            &mut ancillary,
            SendFlags::NOSIGNAL,
        )
        .unwrap();
        assert!(receiver.receive().is_err(), "accepted {count} descriptors");
    }
}

#[test]
fn per_message_credentials_cannot_be_replaced_by_initial_peer_check() {
    let (sender, mut receiver) = pair();
    receiver.peer.pid = rustix::process::Pid::from_raw(getpid().as_raw_pid() + 1).unwrap();
    sender.send(&request(), &[]).unwrap();
    assert!(
        receiver
            .receive()
            .unwrap_err()
            .to_string()
            .contains("sender credentials changed")
    );
}

#[test]
fn stale_reply_missing_fd_and_non_bpffs_fd_are_rejected() {
    for case in 0..4 {
        let (client, server) = pair();
        std::thread::scope(|scope| {
            let worker = scope.spawn(move || {
                let (mut frame, _) = server.receive().unwrap();
                frame[..8].copy_from_slice(RESPONSE);
                if case == 0 {
                    frame[8] ^= 1;
                }
                let file = File::open(if case == 3 { "/" } else { "/dev/null" }).unwrap();
                let descriptors = if case == 1 {
                    vec![]
                } else {
                    vec![file.as_fd()]
                };
                server.send(&frame, &descriptors).unwrap();
            });
            assert!(client.request().is_err(), "accepted bad reply {case}");
            worker.join().unwrap();
        });
    }
}

#[test]
fn rejected_ancillary_rights_are_closed_and_receive_deadline_is_bounded() {
    use std::io::Read as _;
    for count in [2, 32] {
        let (sender, receiver) = pair();
        let (mut witness, descriptor) = std::os::unix::net::UnixStream::pair().unwrap();
        witness.set_nonblocking(true).unwrap();
        let descriptors = vec![descriptor.as_fd(); count];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(32))];
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        assert!(ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)));
        sendmsg(
            &sender.socket,
            &[IoSlice::new(&request())],
            &mut ancillary,
            SendFlags::NOSIGNAL,
        )
        .unwrap();
        drop(descriptor);
        assert!(receiver.receive().is_err());
        assert_eq!(
            witness.read(&mut [0_u8; 1]).unwrap(),
            0,
            "rejected rights leaked"
        );
    }
    let (_sender, receiver) = pair();
    sockopt::set_socket_timeout(
        &receiver.socket,
        Timeout::Recv,
        Some(Duration::from_millis(10)),
    )
    .unwrap();
    assert!(receiver.receive().is_err());
}

fn restrict_thread(capabilities: rustix::thread::CapabilitySet) {
    use rustix::thread::{CapabilitySets, set_capabilities, set_no_new_privs};
    let desired = CapabilitySets {
        effective: capabilities,
        permitted: capabilities,
        inheritable: rustix::thread::CapabilitySet::empty(),
    };
    set_no_new_privs(true).unwrap();
    set_capabilities(None, desired).unwrap();
    assert_eq!(rustix::thread::capabilities(None).unwrap(), desired);
}

#[test]
#[ignore = "requires isolated cl02-first CAP_SYS_ADMIN/BPF kernel qualification"]
fn privileged_private_mount_descriptor_survives_helper_exit_and_reclaims_pins() {
    let expected = std::env::var("UNF_EXPECT_BUILD_REVISION").unwrap();
    assert_eq!(expected.len(), 40);
    assert_eq!(option_env!("UNF_BUILD_REVISION"), Some(expected.as_str()));
    assert_eq!(
        std::env::var("UNF_LOCALITY_HELPER_ISOLATED").as_deref(),
        Ok("yes")
    );
    let original_mount_namespace = std::fs::read_link("/proc/thread-self/ns/mnt").unwrap();
    let (client, server) = pair();
    let mount = std::thread::scope(|scope| {
        let worker = scope.spawn(move || {
            restrict_thread(rustix::thread::CapabilitySet::SYS_ADMIN);
            server.serve()
        });
        // Join and report the helper first even if the client sees EOF; a
        // transport symptom must not hide the allocator's actual kernel error.
        let mount = client.request();
        worker.join().unwrap().unwrap();
        mount.unwrap()
    });
    assert_eq!(
        std::fs::read_link("/proc/thread-self/ns/mnt").unwrap(),
        original_mount_namespace
    );
    let map = std::thread::spawn(move || {
        use rustix::thread::{CapabilitySet, UnshareFlags, unshare_unsafe};
        restrict_thread(CapabilitySet::BPF | CapabilitySet::NET_ADMIN | CapabilitySet::PERFMON);
        // SAFETY: dedicated disposable leaf thread, FS/NEWNS only. This MUST
        // fail without SYS_ADMIN; never reuse a shared async runtime thread.
        #[allow(unsafe_code)]
        let denied = unsafe { unshare_unsafe(UnshareFlags::FS | UnshareFlags::NEWNS) };
        assert_eq!(denied, Err(rustix::io::Errno::PERM));
        mount
            .with_path(|root| {
                use aya::maps::{MapData, MapType};
                let map = MapData::create(
                    aya_obj::Map::new_from_params(MapType::Array as u32, 4, 8, 1, 0),
                    "UL_HELPER_TEST",
                    None,
                )?;
                map.pin(root.join("UL_HELPER_TEST"))?;
                Ok(map)
            })
            .unwrap()
    })
    .join()
    .unwrap();
    let id = map.info().unwrap().id();
    // Mount and helper are gone, but the independent map FD still works.
    assert!(aya::maps::MapInfo::from_id(id).is_ok());
    drop(map);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match aya::maps::MapInfo::from_id(id) {
            Err(aya::maps::MapError::SyscallError(error))
                if error.io_error.kind() == std::io::ErrorKind::NotFound =>
            {
                break;
            }
            Ok(_) => assert!(
                std::time::Instant::now() < deadline,
                "helper map pin leaked"
            ),
            other => panic!("unexpected map observer error: {other:?}"),
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    println!(
        "locality-helper-mount: PASS fd-transfer=true helper-only-sys-admin=true client-three-caps=true client-unshare-denied=true parent-namespace-unchanged=true map-fd-survives=true pin-reclaimed=true production-integration=false"
    );
}
