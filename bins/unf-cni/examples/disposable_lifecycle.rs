use std::env;
use std::io::{self, Read};
use std::path::PathBuf;

use serde::Serialize;
use unf_cni::{InvocationEnvironment, Success, TransactionApi, execute_with_transaction};
use unf_cni_state::{
    AttachmentJournal, AttachmentKey, AttachmentSpec, CNI_TRANSACTION_SCHEMA_VERSION,
    TransactionOperation, TransactionRequest, TransactionResponse,
};
use unf_ipam::NodeBlockProvider;

struct JournalTransaction(AttachmentJournal);

impl TransactionApi for JournalTransaction {
    fn transact(&mut self, request: TransactionRequest) -> Result<TransactionResponse, String> {
        self.0.apply(request).map_err(|error| error.to_string())
    }
}

fn provider() -> Result<NodeBlockProvider, Box<dyn std::error::Error>> {
    Ok(NodeBlockProvider::new(
        env::var("UNF_CNI_TEST_IPV4_BLOCK")
            .unwrap_or_else(|_| "10.244.55.0/24".to_owned())
            .parse()?,
        env::var("UNF_CNI_TEST_IPV6_BLOCK")
            .unwrap_or_else(|_| "fd55::/120".to_owned())
            .parse()?,
    ))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let state_path = PathBuf::from(env::var("UNF_CNI_TEST_STATE_PATH")?);
    let mut transaction = JournalTransaction(AttachmentJournal::open(state_path, provider()?)?);
    if env::var_os("UNF_CNI_TEST_PREPARE_ONLY").is_some() {
        let environment = InvocationEnvironment::from_process();
        let attachment = AttachmentSpec {
            key: AttachmentKey {
                network: "unf-lifecycle-test".to_owned(),
                container_id: environment.container_id.ok_or("missing CNI_CONTAINERID")?,
                ifname: environment.ifname.ok_or("missing CNI_IFNAME")?,
            },
            netns: environment.netns.ok_or("missing CNI_NETNS")?,
            mtu: 1_400,
        };
        transaction.0.apply(TransactionRequest::new(
            CNI_TRANSACTION_SCHEMA_VERSION,
            TransactionOperation::Prepare { attachment },
        ))?;
        return Ok(());
    }

    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    let environment = InvocationEnvironment::from_process();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    match runtime.block_on(execute_with_transaction(
        &environment,
        &input,
        &mut transaction,
    )) {
        Ok(Success::Empty) => Ok(()),
        Ok(Success::Add(result)) => emit(&result),
        Ok(Success::Version(result)) => emit(&result),
        Err(error) => {
            emit(&error)?;
            std::process::exit(1);
        }
    }
}

fn emit(value: &impl Serialize) -> Result<(), Box<dyn std::error::Error>> {
    serde_json::to_writer(io::stdout(), value)?;
    println!();
    Ok(())
}
