use anyhow::Result;
use clap::Parser;
use std::env;
use tokio::io::{self, AsyncWriteExt};
use tokio_stream::StreamExt;
use vtysh::exec_client::ExecClient;
use vtysh::show_client::ShowClient;
use vtysh::{CommandPath, ExecCode, ExecReply, ExecRequest, ExecType, ShowRequest};

pub mod vtysh {
    tonic::include_proto!("vtysh");
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(short, long, help = "Completion of the command")]
    completion: bool,

    #[arg(short, long, help = "First commands list")]
    first: bool,

    #[arg(short, long, help = "Command has trailing space")]
    trailing: bool,

    #[arg(short, long, help = "Current mode", default_value = "exec")]
    mode: String,

    #[arg(short, long, help = "Show command flag")]
    show: bool,

    #[arg(short, long, help = "Show command port", default_value = "2650")]
    port: u32,

    #[arg(short, long, help = "Show output in JSON format")]
    json: bool,

    #[arg(
        short,
        long,
        help = "Base URL of the server",
        default_value = "http://127.0.0.1"
    )]
    base: String,

    commands: Vec<String>,
}

fn privilege_get() -> u32 {
    match env::var("CLI_PRIVILEGE") {
        Ok(val) => val.parse::<u32>().unwrap_or(1),
        Err(_) => 1,
    }
}

fn output(reply: ExecReply) {
    if reply.code == ExecCode::Show as i32 {
        println!("Show");
    }
    println!("{:}", reply.lines);
}

fn command_string(commands: &[String]) -> String {
    if !commands.is_empty() {
        commands.join(" ")
    } else {
        String::from("")
    }
}

fn commands_trim_run(commands: &[String]) -> Vec<String> {
    let mut commands = commands.to_owned();
    if !commands.is_empty() && commands[0] == "run" {
        commands.remove(0);
    }
    commands
}

fn exec_request(exec_type: i32, mode: &String, commands: &Vec<String>) -> ExecRequest {
    ExecRequest {
        r#type: exec_type,
        privilege: privilege_get(),
        mode: mode.to_owned(),
        line: command_string(commands),
        args: commands.to_owned(),
    }
}

async fn show(cli: Cli, port: Option<u32>, paths: Vec<CommandPath>) -> Result<()> {
    let port = port.unwrap_or(cli.port);
    let mut client = ShowClient::connect(format!("{}:{}", cli.base, port)).await?;

    let commands = commands_trim_run(&cli.commands);
    let request = tonic::Request::new(ShowRequest {
        json: cli.json,
        line: command_string(&commands),
        paths,
    });

    let mut stdout = io::stdout();
    let mut stream = client.show(request).await?.into_inner();
    println!("Show");
    while let Some(reply) = stream.next().await {
        let reply = reply.unwrap();
        stdout.write_all(reply.str.as_bytes()).await.unwrap();
    }

    Ok(())
}

async fn completion(cli: Cli) -> Result<()> {
    let mut client = ExecClient::connect(format!("{}:{}", cli.base, cli.port)).await?;

    let exec_type: i32 = if cli.completion {
        ExecType::Complete as i32
    } else if cli.trailing {
        ExecType::CompleteTrailingSpace as i32
    } else if cli.first {
        ExecType::CompleteFirstCommands as i32
    } else {
        ExecType::Exec as i32
    };

    let request = tonic::Request::new(exec_request(exec_type, &cli.mode, &cli.commands));
    let reply = client.do_exec(request).await?.into_inner();
    println!("{:}", reply.lines);

    Ok(())
}

async fn redirect(cli: Cli, port: u32) -> Result<()> {
    let mut client = ExecClient::connect(format!("{}:{}", cli.base, port)).await?;

    let commands = commands_trim_run(&cli.commands);
    let request = tonic::Request::new(exec_request(ExecType::Exec as i32, &cli.mode, &commands));
    let reply = client.do_exec(request).await?.into_inner();

    output(reply);

    Ok(())
}

async fn exec(cli: Cli) -> Result<()> {
    let mut client = ExecClient::connect(format!("{}:{}", cli.base, cli.port)).await?;

    let request = tonic::Request::new(exec_request(
        ExecType::Exec as i32,
        &cli.mode,
        &cli.commands,
    ));

    let reply = client.do_exec(request).await?.into_inner();
    match reply.code {
        _ if reply.code == ExecCode::Redirect as i32 => {
            redirect(cli, reply.port).await?;
        }
        _ if reply.code == ExecCode::RedirectShow as i32 => {
            show(cli, Some(reply.port), reply.paths).await?;
        }
        _ => output(reply),
    }
    Ok(())
}

async fn run(cli: Cli) -> Result<()> {
    if cli.show {
        show(cli, None, Vec::new()).await?;
    } else if cli.completion || cli.trailing || cli.first {
        completion(cli).await?;
    } else {
        exec(cli).await?;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut cli = Cli::parse();
    if let Ok(val) = env::var("CLI_SERVER_URL") {
        cli.base = val;
    }
    if let Err(_err) = run(cli).await {
        println!("dummy\ncommands\n\n");
    }
    Ok(())
}
