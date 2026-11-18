//! `vtyctl config-db`: the two calls of the writer of CONFIG_DB on a
//! SONiC device (`proto/configdb.proto`), for a writer that is a script.
//!
//! `wait` prints the next order as one line of JSON, `{"id": 7, "patch":
//! [...]}`, or nothing when none came in time; the script applies the
//! patch with SONiC's `config apply-patch` and says what became of it
//! with `done`.

use anyhow::Result;
use std::process::exit;
use tonic::Request;

use pb::writer_service_client::WriterServiceClient;

pub mod pb {
    tonic::include_proto!("zebra.configdb.v1");
}

async fn client(host: &str) -> WriterServiceClient<tonic::transport::Channel> {
    let uri = crate::endpoint::host_uri(host);
    match crate::endpoint::connect(&uri).await {
        Ok(channel) => WriterServiceClient::new(channel),
        Err(e) => {
            eprintln!("Can't connect to {uri}: {e}");
            exit(3);
        }
    }
}

/// Wait for an order and print it. Exits 0 with nothing printed when
/// none came within `timeout` seconds.
pub async fn wait(host: &str, timeout: u32) -> Result<()> {
    let mut client = client(host).await;
    let request = pb::WaitRequest {
        timeout_seconds: timeout,
    };
    let order = client.wait(Request::new(request)).await?.into_inner();
    if order.id != 0 {
        // The patch is JSON already: it goes in as it is.
        println!("{{\"id\": {}, \"patch\": {}}}", order.id, order.patch);
    }
    Ok(())
}

/// Report on order `id`: written, or not and why.
pub async fn done(host: &str, id: u64, error: Option<String>) -> Result<()> {
    let mut client = client(host).await;
    let result = pb::Result {
        id,
        ok: error.is_none(),
        message: error.unwrap_or_default(),
    };
    if let Err(status) = client.done(Request::new(result)).await {
        eprintln!("{}", status.message());
        exit(1);
    }
    Ok(())
}
