use anyhow::Result;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::exit;
use tonic::Request;
use vtysh::ApplyRequest;
use vtysh::apply_client::ApplyClient;

pub mod vtysh {
    tonic::include_proto!("vtysh");
}

fn print_help() {
    eprintln!("vtyctl apply must specify -f or --filename.");
}

pub async fn apply(host: &String, filename: &String) -> Result<()> {
    if filename.is_empty() {
        print_help();
        exit(1);
    }
    let path = Path::new(filename);
    let file = match File::open(path) {
        Ok(file) => file,
        Err(err) => {
            eprintln!("Can't open file {}: {}", filename, err);
            exit(2);
        }
    };

    let client = ApplyClient::connect(format!("http://{}:{}", host, 2666)).await;
    let Ok(mut client) = client else {
        eprintln!("Can't connect to {}", host);
        exit(3);
    };

    let mut vec = Vec::new();
    for line in BufReader::new(file).lines() {
        vec.push(ApplyRequest {
            line: line.unwrap() + "\n",
        });
    }

    let requests = tokio_stream::iter(vec);

    let response = client.apply(Request::new(requests)).await?;

    let reply = response.into_inner();

    println!("Response received: {:?}", reply);

    Ok(())
}
