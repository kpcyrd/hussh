pub(crate) mod args;
pub(crate) mod config;
pub(crate) mod errors;
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
use russh::keys::{Algorithm, PrivateKey, ssh_key::LineEnding};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

// "[::]:20";
const DEFAULT_SSHD_BIND_ADDR: SocketAddr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 20);

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
        let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)?;
        let key = key.to_openssh(LineEnding::LF)?;
        println!("{}", key.as_str().trim_end());
        Ok(())
    } else {
        let config = args.config().await?;

        let bind_addr = config
            .sshd
            .bind_addr(&args)
            .unwrap_or(DEFAULT_SSHD_BIND_ADDR);

        let (shared, rx) = Shared::from_config(config);
        let key = keygen::init_from_path(&args.data_dir.join("sshd.key")).await?;

        let shared = Arc::new(shared);
        let mut server = ssh::server::SshServer::new(shared.clone());

        let sighup = signals::sighup(shared, args);

        tokio::select! {
            res = relay::run(rx) => res,
            res = server.run(key, bind_addr) => res,
            res = sighup => Ok(res),
            res = signals::sigterm() => Ok(res),
        }
    }
}
