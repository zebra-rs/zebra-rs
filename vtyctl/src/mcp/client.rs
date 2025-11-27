use anyhow::Result;
use tokio_stream::StreamExt;
use tonic::Request;
use tracing::{debug, error};

use crate::vtysh::show_client::ShowClient;
use crate::vtysh::{CommandPath, ShowRequest, YangMatch};

/// Client for communicating with zebra-rs daemon via gRPC
#[derive(Clone)]
pub struct ZebraClient {
    pub base_url: String,
    pub port: u32,
}

impl ZebraClient {
    pub fn new(base_url: String, port: u32) -> Self {
        Self { base_url, port }
    }

    /// Execute a show command and return the result as JSON
    pub async fn show_command(&self, command: &str, json: bool) -> Result<String> {
        let endpoint = format!("{}:{}", self.base_url, self.port);
        debug!("Connecting to zebra-rs at {}", endpoint);

        let mut client = ShowClient::connect(endpoint).await?;

        let mut paths = Vec::new();
        let cmds: Vec<&str> = command.split_whitespace().collect();
        let len = cmds.len();
        for (pos, cmd) in cmds.iter().enumerate() {
            let ymatch = if pos != len - 1 {
                YangMatch::Dir
            } else {
                YangMatch::Leaf
            };
            let path = CommandPath {
                name: cmd.to_string(),
                key: "".to_string(),
                ymatch: ymatch.into(),
                mandatory: vec![],
                sort_priority: 0,
            };
            paths.push(path);
        }

        let request = Request::new(ShowRequest {
            json,
            line: command.to_string(),
            paths,
        });

        debug!("Executing show command: {}", command);
        let mut stream = client.show(request).await?.into_inner();

        let mut result = String::new();
        while let Some(reply) = stream.next().await {
            match reply {
                Ok(response) => {
                    result.push_str(&response.str);
                }
                Err(e) => {
                    error!("Error receiving response: {}", e);
                    return Err(anyhow::anyhow!("gRPC error: {}", e));
                }
            }
        }

        debug!("Show command completed, received {} bytes", result.len());
        Ok(result)
    }

    /// Execute ISIS-specific show commands
    pub async fn show_isis_command(&self, subcommand: &str, json: bool) -> Result<String> {
        let command = format!("show isis {}", subcommand);
        self.show_command(&command, json).await
    }

    /// Test connectivity to the zebra-rs daemon
    pub async fn test_connection(&self) -> Result<()> {
        match self.show_command("show version", false).await {
            Ok(_) => {
                debug!("Successfully connected to zebra-rs");
                Ok(())
            }
            Err(e) => {
                error!("Failed to connect to zebra-rs: {}", e);
                Err(e)
            }
        }
    }
}
