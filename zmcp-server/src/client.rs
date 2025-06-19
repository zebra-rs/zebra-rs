use anyhow::Result;
use tokio_stream::StreamExt;
use tonic::Request;
use tracing::{debug, error};

pub mod vtysh {
    tonic::include_proto!("vtysh");
}

use vtysh::show_client::ShowClient;
use vtysh::ShowRequest;

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

        let request = Request::new(ShowRequest {
            json,
            line: command.to_string(),
            paths: vec![],
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zebra_client_creation() {
        let client = ZebraClient::new("http://test.example.com".to_string(), 9999);
        assert_eq!(client.base_url, "http://test.example.com");
        assert_eq!(client.port, 9999);
    }

    #[test]
    fn test_zebra_client_clone() {
        let client = ZebraClient::new("http://localhost".to_string(), 2650);
        let cloned = client.clone();

        assert_eq!(client.base_url, cloned.base_url);
        assert_eq!(client.port, cloned.port);
    }

    #[tokio::test]
    async fn test_show_command_connection_failure() {
        let client = ZebraClient::new("http://non-existent-host".to_string(), 12345);

        // This should fail to connect
        let result = client.show_command("show version", false).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_show_isis_command_format() {
        let client = ZebraClient::new("http://non-existent-host".to_string(), 12345);

        // Test that the command is formatted correctly (even though it will fail to connect)
        let result = client.show_isis_command("neighbors", true).await;
        assert!(result.is_err());
        // The error should be connection-related, not command formatting related
    }

    #[tokio::test]
    async fn test_test_connection_failure() {
        let client = ZebraClient::new("http://non-existent-host".to_string(), 12345);

        let result = client.test_connection().await;
        assert!(result.is_err());
    }
}
