pub(crate) mod args;
pub(crate) mod config;
pub(crate) mod errors;
pub(crate) mod keygen;
pub(crate) mod relay;
pub(crate) mod shared;
pub(crate) mod ssh;

use crate::args::Args;
use crate::errors::*;
use crate::shared::Shared;
use clap::Parser;
use env_logger::Env;
use russh::keys::{Algorithm, PrivateKey, ssh_key::LineEnding};
use std::path::Path;

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

        let (shared, rx) = Shared::from_config(config);
        let key = keygen::init_from_path(Path::new("sshd.key")).await?;

        let mut server = ssh::server::SshServer::new(shared);
        tokio::try_join!(relay::run(rx), server.run(key, args.bind))?;
        Ok(())
    }
}
