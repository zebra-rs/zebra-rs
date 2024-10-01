use anyhow::Result;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::exit;
use tonic::Request;
use vtysh::apply_client::ApplyClient;
use vtysh::ApplyRequest;

pub mod vtysh {
    tonic::include_proto!("vtysh");
}

pub async fn apply(host: &String, filename: &String) -> Result<()> {
    println!("apply host: {} filename: {}", host, filename);
    if filename.is_empty() {
        println!("Please specify filename");
        exit(1);
    }
    let path = Path::new(filename);
    let file = match File::open(path) {
        Ok(file) => file,
        Err(err) => panic!("Can not open {}: {}", filename, err),
    };

    let mut client = ApplyClient::connect(format!("{}:{}", "http://127.0.0.1", 2650)).await?;

    let mut vec = Vec::new();
    for line in BufReader::new(file).lines() {
        vec.push(ApplyRequest {
            line: line.unwrap(),
        });
    }

    let requests = tokio_stream::iter(vec);

    let response = client.apply(Request::new(requests)).await?;

    let reply = response.into_inner();

    println!("Response received: {:?}", reply);

    Ok(())
}
