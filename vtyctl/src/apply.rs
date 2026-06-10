use anyhow::Result;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::exit;
use tonic::Request;
use vty::apply_client::ApplyClient;
use vty::{ApplyCode, ApplyRequest};

pub mod vty {
    tonic::include_proto!("vty");
}

fn print_help() {
    eprintln!("vtyctl apply must specify -f or --filename.");
}

pub async fn apply(host: &str, filename: &str, command: Option<&String>) -> Result<()> {
    let mut vec = Vec::new();
    if let Some(cmd) = command {
        // The shell hands us the two-character literal `\n` (not a
        // real newline) for the common
        //   vtyctl apply -c "set ... \n set ..."
        // invocation. Normalise the escape into a real newline so
        // callers don't have to reach for $'...' quoting, then
        // forward each line as one ApplyRequest — same shape as
        // the file-mode path below. `str::lines()` matches
        // `BufReader::lines()`: it splits on `\n`/`\r\n`, strips
        // the terminator, and doesn't emit a trailing empty line
        // when the input ends with one.
        let normalised = cmd.replace("\\n", "\n");
        for line in normalised.lines() {
            // `-c` is the command surface: a bare line is a `set`
            // line. Without the explicit prefix the server's format
            // sniffer would classify the payload as a YAML *document*,
            // clear the candidate, and REPLACE the entire running
            // config with whatever that one line parses to.
            let line = if line.trim().is_empty()
                || line.starts_with("set ")
                || line.starts_with("delete ")
            {
                line.to_string()
            } else {
                format!("set {}", line)
            };
            println!("line:{}", line);
            vec.push(ApplyRequest { line: line + "\n" });
        }
    } else if !filename.is_empty() {
        let path = Path::new(filename);
        let file = match File::open(path) {
            Ok(file) => file,
            Err(err) => {
                eprintln!("Can't open file {}: {}", filename, err);
                exit(2);
            }
        };
        for line in BufReader::new(file).lines() {
            vec.push(ApplyRequest {
                line: line.unwrap() + "\n",
            });
        }
    } else {
        print_help();
        exit(1);
    }

    let uri = crate::endpoint::host_uri(host);
    let channel = match crate::endpoint::connect(&uri).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Can't connect to {uri}: {e}");
            exit(3);
        }
    };
    let mut client = ApplyClient::new(channel);

    let requests = tokio_stream::iter(vec);

    let response = client.apply(Request::new(requests)).await?;

    let reply = response.into_inner();

    if reply.apply_code == ApplyCode::Applied as i32 {
        println!("applied");
    } else {
        println!("error reply: {}", reply.description)
    }

    Ok(())
}
