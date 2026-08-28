use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use unf_cni_state::{
    AttachmentJournal, JournalError, MAX_TRANSACTION_MESSAGE_BYTES, TransactionErrorCode,
    TransactionRequest, TransactionResponse,
};
use unf_ipam::{IpamError, NodeBlockProvider};

const TRANSACTION_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_UNIX_SOCKET_PATH_BYTES: usize = 107;

pub struct CniTransactionServer {
    listener: UnixListener,
    socket_path: PathBuf,
    socket_device: u64,
    socket_inode: u64,
    journal: Arc<Mutex<AttachmentJournal>>,
}

impl CniTransactionServer {
    /// Opens durable state and binds the opt-in local transaction endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error when the paths are unsafe, durable state is invalid, or
    /// the socket cannot be bound with owner-only permissions.
    pub fn bind(
        socket_path: PathBuf,
        state_path: &Path,
        provider: NodeBlockProvider,
    ) -> Result<Self> {
        validate_socket_path(&socket_path)?;
        let journal = AttachmentJournal::open(state_path, provider)
            .with_context(|| format!("open CNI attachment journal {}", state_path.display()))?;
        prepare_socket_path(&socket_path)?;
        let listener = UnixListener::bind(&socket_path)
            .with_context(|| format!("bind CNI transaction socket {}", socket_path.display()))?;
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("secure CNI transaction socket {}", socket_path.display()))?;
        let metadata = fs::symlink_metadata(&socket_path)
            .with_context(|| format!("inspect bound CNI socket {}", socket_path.display()))?;
        Ok(Self {
            listener,
            socket_path,
            socket_device: metadata.dev(),
            socket_inode: metadata.ino(),
            journal: Arc::new(Mutex::new(journal)),
        })
    }

    /// Serves root-authenticated, bounded one-request connections until shutdown.
    ///
    /// # Errors
    ///
    /// Returns an error if accepting a local connection fails. Per-connection
    /// protocol and I/O errors are contained to that connection.
    pub async fn run(self, cancellation: CancellationToken) -> Result<()> {
        loop {
            tokio::select! {
                () = cancellation.cancelled() => break,
                accepted = self.listener.accept() => {
                    let (stream, _) = accepted.context("accept CNI transaction connection")?;
                    let journal = Arc::clone(&self.journal);
                    let _ = tokio::time::timeout(
                        TRANSACTION_TIMEOUT,
                        serve_connection(stream, journal),
                    )
                    .await;
                }
            }
        }
        remove_owned_socket(&self.socket_path, self.socket_device, self.socket_inode)?;
        Ok(())
    }
}

async fn serve_connection(
    mut stream: UnixStream,
    journal: Arc<Mutex<AttachmentJournal>>,
) -> io::Result<()> {
    let credentials = stream.peer_cred()?;
    let mut input = Vec::new();
    (&mut stream)
        .take(
            u64::try_from(MAX_TRANSACTION_MESSAGE_BYTES)
                .expect("transaction message bound fits u64")
                + 1,
        )
        .read_to_end(&mut input)
        .await?;
    let response = if !authorized_uid(credentials.uid()) {
        TransactionResponse::error(
            TransactionErrorCode::Unauthorized,
            "the CNI transaction API accepts only UID 0 peers",
        )
    } else if input.len() > MAX_TRANSACTION_MESSAGE_BYTES {
        TransactionResponse::error(
            TransactionErrorCode::InvalidRequest,
            format!("request exceeds the {MAX_TRANSACTION_MESSAGE_BYTES}-byte transaction limit"),
        )
    } else {
        handle_request(&input, &journal).await
    };
    write_response(&mut stream, &response).await
}

async fn handle_request(input: &[u8], journal: &Mutex<AttachmentJournal>) -> TransactionResponse {
    let request: TransactionRequest = match serde_json::from_slice(input) {
        Ok(request) => request,
        Err(error) => {
            return TransactionResponse::error(
                TransactionErrorCode::InvalidRequest,
                format!("invalid transaction JSON: {error}"),
            );
        }
    };
    let mut journal = journal.lock().await;
    match journal.apply(request) {
        Ok(response) => response,
        Err(error) => journal_error_response(&error),
    }
}

async fn write_response(stream: &mut UnixStream, response: &TransactionResponse) -> io::Result<()> {
    let mut encoded = serde_json::to_vec(response).map_err(io::Error::other)?;
    if encoded.len() >= MAX_TRANSACTION_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "transaction response exceeds its protocol bound",
        ));
    }
    encoded.push(b'\n');
    stream.write_all(&encoded).await?;
    stream.shutdown().await
}

fn journal_error_response(error: &JournalError) -> TransactionResponse {
    let code = match error {
        JournalError::Invalid(_) | JournalError::Json(_) => TransactionErrorCode::InvalidRequest,
        JournalError::NotFound => TransactionErrorCode::NotFound,
        JournalError::InvalidTransition(_) => TransactionErrorCode::InvalidTransition,
        JournalError::IncompatibleSchema { .. } => TransactionErrorCode::IncompatibleSchema,
        JournalError::Io(_) => TransactionErrorCode::PersistenceFailure,
        JournalError::Ipam(IpamError::Exhausted { .. }) => TransactionErrorCode::Exhausted,
        JournalError::Conflict(_) | JournalError::Ipam(_) => TransactionErrorCode::Conflict,
    };
    TransactionResponse::error(code, error.to_string())
}

const fn authorized_uid(uid: u32) -> bool {
    uid == 0
}

fn validate_socket_path(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!("CNI transaction socket path must be absolute");
    }
    if path.as_os_str().as_encoded_bytes().contains(&0) {
        bail!("CNI transaction socket path cannot contain NUL bytes");
    }
    if path.as_os_str().as_encoded_bytes().len() > MAX_UNIX_SOCKET_PATH_BYTES {
        bail!("CNI transaction socket path exceeds {MAX_UNIX_SOCKET_PATH_BYTES} bytes");
    }
    Ok(())
}

fn prepare_socket_path(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .context("CNI transaction socket must have a parent directory")?;
    reject_symlink_components(parent)?;
    fs::create_dir_all(parent)
        .with_context(|| format!("create CNI socket directory {}", parent.display()))?;
    reject_symlink_components(parent)?;
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("inspect existing CNI socket path"),
    };
    if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
        bail!(
            "refusing to replace non-socket CNI transaction path {}",
            path.display()
        );
    }
    match std::os::unix::net::UnixStream::connect(path) {
        Ok(_) => bail!(
            "CNI transaction socket {} is already active",
            path.display()
        ),
        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
            let current = fs::symlink_metadata(path)
                .with_context(|| format!("reinspect stale CNI socket {}", path.display()))?;
            if !current.file_type().is_socket()
                || current.dev() != metadata.dev()
                || current.ino() != metadata.ino()
            {
                bail!(
                    "CNI transaction socket {} changed during stale-state validation",
                    path.display()
                );
            }
            fs::remove_file(path)
                .with_context(|| format!("remove stale CNI socket {}", path.display()))?;
            Ok(())
        }
        Err(error) => Err(error)
            .with_context(|| format!("probe existing CNI transaction socket {}", path.display())),
    }
}

fn reject_symlink_components(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspect CNI socket path {}", current.display()));
            }
        };
        if metadata.file_type().is_symlink() {
            bail!(
                "CNI transaction socket path cannot contain symlink {}",
                current.display()
            );
        }
    }
    Ok(())
}

fn remove_owned_socket(path: &Path, expected_device: u64, expected_inode: u64) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("inspect owned CNI socket during shutdown"),
    };
    if !metadata.file_type().is_socket()
        || metadata.dev() != expected_device
        || metadata.ino() != expected_inode
    {
        bail!(
            "owned CNI transaction socket changed identity before shutdown: {}",
            path.display()
        );
    }
    fs::remove_file(path)
        .with_context(|| format!("remove CNI transaction socket {}", path.display()))
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use unf_cni_state::{
        AttachmentKey, AttachmentPhase, AttachmentSpec, CNI_TRANSACTION_SCHEMA_VERSION,
        TransactionOperation, TransactionOutcome,
    };

    use super::*;

    fn provider() -> NodeBlockProvider {
        NodeBlockProvider::new(
            "10.42.0.0/24".parse().expect("IPv4 node block"),
            "fd00:42::/120".parse().expect("IPv6 node block"),
        )
    }

    fn request(operation: TransactionOperation) -> Vec<u8> {
        serde_json::to_vec(&TransactionRequest::new(
            CNI_TRANSACTION_SCHEMA_VERSION,
            operation,
        ))
        .expect("encode request")
    }

    fn spec() -> AttachmentSpec {
        AttachmentSpec {
            key: AttachmentKey {
                network: "unf-test".to_owned(),
                container_id: "container-1".to_owned(),
                ifname: "eth0".to_owned(),
            },
            netns: "/run/netns/container-1".to_owned(),
            mtu: 1_500,
        }
    }

    #[tokio::test]
    async fn handler_persists_versioned_state_transitions() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("attachments.json");
        let journal = Mutex::new(AttachmentJournal::open(&path, provider()).expect("open journal"));
        let prepare = handle_request(
            &request(TransactionOperation::Prepare { attachment: spec() }),
            &journal,
        )
        .await;
        let TransactionOutcome::Ok {
            attachment: Some(preparing),
            attachment_count: 1,
        } = prepare.outcome
        else {
            panic!("prepare must return one attachment");
        };
        assert_eq!(preparing.phase, AttachmentPhase::Preparing);

        let commit = handle_request(
            &request(TransactionOperation::Commit { key: spec().key }),
            &journal,
        )
        .await;
        let TransactionOutcome::Ok {
            attachment: Some(ready),
            attachment_count: 1,
        } = commit.outcome
        else {
            panic!("commit must return one attachment");
        };
        assert_eq!(ready.phase, AttachmentPhase::Ready);
        assert_eq!(
            AttachmentJournal::open(path, provider())
                .expect("restart")
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn malformed_and_incompatible_requests_have_machine_readable_errors() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let journal = Mutex::new(
            AttachmentJournal::open(directory.path().join("attachments.json"), provider())
                .expect("open journal"),
        );
        let malformed = handle_request(b"not-json", &journal).await;
        assert!(matches!(
            malformed.outcome,
            TransactionOutcome::Error {
                code: TransactionErrorCode::InvalidRequest,
                ..
            }
        ));
        let incompatible = handle_request(
            &serde_json::to_vec(&TransactionRequest::new(1, TransactionOperation::Status))
                .expect("encode incompatible request"),
            &journal,
        )
        .await;
        assert!(matches!(
            incompatible.outcome,
            TransactionOutcome::Error {
                code: TransactionErrorCode::IncompatibleSchema,
                ..
            }
        ));

        let limited = NodeBlockProvider::new(
            "10.43.0.0/30".parse().unwrap(),
            "fd00:43::/120".parse().unwrap(),
        );
        let limited_journal = Mutex::new(
            AttachmentJournal::open(directory.path().join("limited.json"), limited)
                .expect("open limited journal"),
        );
        handle_request(
            &request(TransactionOperation::Prepare { attachment: spec() }),
            &limited_journal,
        )
        .await;
        let mut second = spec();
        second.key.container_id = "container-2".to_owned();
        second.netns = "/run/netns/container-2".to_owned();
        let exhausted = handle_request(
            &request(TransactionOperation::Prepare { attachment: second }),
            &limited_journal,
        )
        .await;
        assert!(matches!(
            exhausted.outcome,
            TransactionOutcome::Error {
                code: TransactionErrorCode::Exhausted,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn bound_socket_is_owner_only_and_removed_on_shutdown() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let socket = directory.path().join("cni.sock");
        let state = directory.path().join("attachments.json");
        let server =
            CniTransactionServer::bind(socket.clone(), &state, provider()).expect("bind server");
        let mode = fs::metadata(&socket)
            .expect("socket metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        server.run(cancellation).await.expect("stop server");
        assert!(!socket.exists());
    }

    #[tokio::test]
    async fn live_socket_enforces_kernel_peer_credentials() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let socket = directory.path().join("cni.sock");
        let state = directory.path().join("attachments.json");
        let server =
            CniTransactionServer::bind(socket.clone(), &state, provider()).expect("bind server");
        let cancellation = CancellationToken::new();
        let shutdown = cancellation.clone();
        let task = tokio::spawn(server.run(shutdown));

        let mut client = UnixStream::connect(&socket).await.expect("connect client");
        let peer_uid = client.peer_cred().expect("peer credentials").uid();
        client
            .write_all(&request(TransactionOperation::Status))
            .await
            .expect("write request");
        client.shutdown().await.expect("finish request");
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("read response");
        let response: TransactionResponse =
            serde_json::from_slice(&response).expect("decode response");
        if peer_uid == 0 {
            assert!(matches!(response.outcome, TransactionOutcome::Ok { .. }));
        } else {
            assert!(matches!(
                response.outcome,
                TransactionOutcome::Error {
                    code: TransactionErrorCode::Unauthorized,
                    ..
                }
            ));
        }

        cancellation.cancel();
        task.await
            .expect("join transaction server")
            .expect("stop transaction server");
    }

    #[tokio::test]
    async fn shutdown_never_removes_a_replaced_socket_path() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let socket = directory.path().join("cni.sock");
        let state = directory.path().join("attachments.json");
        let server =
            CniTransactionServer::bind(socket.clone(), &state, provider()).expect("bind server");
        fs::remove_file(&socket).expect("unlink original socket name");
        fs::write(&socket, b"replacement").expect("create replacement path");
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        assert!(server.run(cancellation).await.is_err());
        assert_eq!(
            fs::read(&socket).expect("replacement remains"),
            b"replacement"
        );
    }

    #[test]
    fn authentication_and_socket_path_validation_are_fail_closed() {
        assert!(authorized_uid(0));
        assert!(!authorized_uid(1_000));
        assert!(validate_socket_path(Path::new("relative.sock")).is_err());

        let directory = tempfile::tempdir().expect("temporary directory");
        let socket = directory.path().join("cni.sock");
        fs::write(&socket, b"not a socket").expect("write collision");
        assert!(prepare_socket_path(&socket).is_err());
        assert!(socket.is_file());

        let stale = directory.path().join("stale.sock");
        drop(std::os::unix::net::UnixListener::bind(&stale).expect("bind stale socket"));
        prepare_socket_path(&stale).expect("remove exact inactive socket");
        assert!(!stale.exists());
    }
}
