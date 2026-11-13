pub mod args;
pub mod config;
pub mod daemon;
pub mod dns;
pub mod errors;
pub mod http;
pub mod plumbing;
pub mod rules;
pub mod server;

use crate::args::{Args, Subcommand};
use crate::config::Config;
use crate::daemon::Daemon;
use crate::errors::*;
use clap::Parser;
use env_logger::Env;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let log_level = match args.verbose {
        0 => "ocloak=info,httpd=info",
        1 => "ocloak=debug,httpd=debug,info",
        2 => "ocloak=trace,httpd=trace,info",
        3 => "debug",
        _ => "trace",
    };
    env_logger::init_from_env(Env::default().default_filter_or(log_level));

    match args.subcommand {
        Subcommand::Daemon(daemon) => {
            let config = Config::load(&daemon.config).await?;
            let bind_addr = daemon.bind_addr.unwrap_or(config.daemon.bind_addr);

            daemon::run(Daemon { bind_addr, config }).await?;
        }
        Subcommand::Plumbing(plumbing) => plumbing::run(&plumbing).await?,
    }

    Ok(())
}
