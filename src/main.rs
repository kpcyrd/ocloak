pub mod args;
pub mod config;
pub mod daemon;
pub mod dns;
pub mod errors;
pub mod http;
pub mod plumbing;
pub mod rules;

use crate::args::{Args, Subcommand};
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
        2 => "debug",
        3 => "ocloak=trace,httpd=trace,debug",
        _ => "trace",
    };
    env_logger::init_from_env(Env::default().default_filter_or(log_level));

    match args.subcommand {
        Subcommand::Daemon(daemon) => {
            daemon::run(&Daemon {
                bind_addr: daemon.bind_addr,
                config: daemon.config,
            })
            .await?;
        }
        Subcommand::Plumbing(plumbing) => plumbing::run(&plumbing).await?,
    }

    Ok(())
}
