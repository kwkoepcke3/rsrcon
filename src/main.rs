use std::{net::Ipv4Addr, str::FromStr};

use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about=None)]
struct CliArgs {
    cmd: Vec<String>,
    #[arg(long, short)]
    password: Option<String>,
    #[arg(long, short)]
    address: Option<String>,
}

async fn run() -> rsrcon::rcon::RconResult<()> {
    let args = CliArgs::parse();

    let ip_string = args
        .address
        .or_else(|| std::env::var("RCON_ADDRESS").ok())
        .unwrap_or_else(|| "127.0.0.1:25575".to_owned());
    let (ip, port) = ip_string.split_once(":").unwrap_or((&ip_string, "25575"));

    let ip =
        Ipv4Addr::from_str(ip).map_err(|e| rsrcon::rcon::RconError::GenericError(e.to_string()))?;

    let mut rcon = rsrcon::rcon::Rcon::from(ip, port).await?;

    let password = &args
        .password
        .or_else(|| std::env::var("RCON_PASSWORD").ok())
        .unwrap_or_default();

    rcon.authenticate(password).await?;

    let resp_parts = rcon.exec_cmd(&args.cmd.join(" ")).await?;

    let resp = resp_parts
        .into_iter()
        .map(|packet| packet.body)
        .collect::<Vec<Vec<u8>>>()
        .concat();

    let resp_string = std::str::from_utf8(&resp)
        .map_err(|e| rsrcon::rcon::RconError::GenericError(e.to_string()))?;

    println!("{resp_string}");

    return Ok(());
}

#[tokio::main]
async fn main() {
    let result = run().await;
    match result {
        Ok(()) => {}
        Err(e) => println!("{e}"),
    }
}
