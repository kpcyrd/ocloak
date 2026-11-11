use clap::{ArgAction, Parser};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Parser)]
pub struct Args {
    /// Increase logging output (can be used multiple times)
    #[arg(short, long, global = true, action(ArgAction::Count))]
    pub verbose: u8,
    #[command(subcommand)]
    pub subcommand: Subcommand,
}

#[derive(Debug, Parser)]
pub enum Subcommand {
    Daemon(Daemon),
    #[command(subcommand)]
    Plumbing(Plumbing),
}

#[derive(Debug, Parser)]
pub struct Daemon {
    #[arg(short = 'B', long, default_value = "127.0.0.1:3000", env = "HTTP_ADDR")]
    pub bind_addr: SocketAddr,
    #[arg(short = 'c', long)]
    pub config: PathBuf,
}

#[derive(Debug, Parser)]
pub enum Plumbing {
    /// Check DNS records for RFC 9540 OHTTP discovery
    CheckDns(CheckDns),
}

#[derive(Debug, Parser)]
pub struct CheckDns {
    #[arg(required = true)]
    pub names: Vec<String>,
}
