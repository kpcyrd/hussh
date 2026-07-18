use crate::config::Config;
use crate::errors::*;
use clap::ArgAction;
use std::net::SocketAddr;
use std::path::PathBuf;
use tokio::fs;

#[derive(clap::Parser)]
#[command(version)]
pub struct Args {
    /// Increase logging output (can be used multiple times)
    #[arg(short, long, global = true, action(ArgAction::Count))]
    pub verbose: u8,
    /// Generate an ssh private key
    #[arg(short = 'K', long)]
    pub keygen: bool,
    /// The address to bind the daemon to
    #[arg(short = 'B', long, default_value = "[::]:2222")]
    pub bind: SocketAddr,
    /// Path to daemon config file
    #[arg(short = 'c', long)]
    pub config: Option<PathBuf>,
}

impl Args {
    pub async fn config(&self) -> Result<Config> {
        let path = self
            .config
            .as_ref()
            .context("Missing -c option for configuration file")?;
        let config = fs::read_to_string(&path)
            .await
            .with_context(|| format!("Failed to read file: {path:?}"))?;
        Config::parse(&config).with_context(|| format!("Failed to parse config file: {path:?}"))
    }
}
