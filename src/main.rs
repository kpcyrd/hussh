pub(crate) mod args;
pub(crate) mod config;
pub(crate) mod errors;
pub(crate) mod honeypot;
pub(crate) mod keygen;
pub(crate) mod relay;
pub(crate) mod shared;
pub(crate) mod signals;
pub(crate) mod ssh;

use crate::args::Args;
use crate::errors::*;
use crate::shared::Shared;
use clap::Parser;
use env_logger::Env;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

// "[::]:2";
const DEFAULT_SSHD_BIND_ADDR: SocketAddr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 2);

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let log_level = match args.verbose {
        0 => "hussh=info",
        1 => "hussh=debug",
        2 => "debug",
        3 => "hussh=trace,debug",
        _ => "trace",
    };
    env_logger::init_from_env(Env::default().default_filter_or(log_level));

    if args.keygen {
        let key = keygen::keygen_str()?;
        println!("{}", key.as_str().trim_end());
        Ok(())
    } else {
        let config = args.config().await?;

        let bind_addr = config
            .sshd
            .bind_addr(&args)
            .unwrap_or(DEFAULT_SSHD_BIND_ADDR);

        let (shared, relay_rx, honeypot_rx) = Shared::from_config(config);
        let key = keygen::init_from_path(&args.data_dir.join("sshd.key")).await?;

        let shared = Arc::new(shared);
        let mut server = ssh::server::SshServer::new(shared.clone());

        let sighup = signals::sighup(shared.clone(), args);

        tokio::select! {
            res = relay::run(relay_rx) => res,
            res = server.run(key, bind_addr) => res,
            // This task does nothing unless configured
            res = honeypot::logger(shared, honeypot_rx) => Ok(res),
            // Signal handling
            res = sighup => Ok(res),
            res = signals::sigterm() => Ok(res),
        }
    }
}
