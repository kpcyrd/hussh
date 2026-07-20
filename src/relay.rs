use crate::errors::*;
use futures_util::{StreamExt, stream::FuturesUnordered, task::SpawnExt};
use russh::{
    ChannelStream,
    server::Msg,
};
use std::fmt;
use tokio::io;
use tokio::net;
use tokio::sync::mpsc;

pub struct Relay {
    pub host: String,
    pub port: u16,
    pub stream: ChannelStream<Msg>,
}

impl fmt::Display for Relay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // We may improve this in the future
        write!(f, "{:?}:{}", self.host, self.port)
    }
}

async fn relay(mut relay: Relay) -> Result<()> {
    let mut sock = match net::TcpStream::connect((relay.host.as_str(), relay.port)).await {
        Ok(sock) => sock,
        Err(err) => {
            error!("Failed to connect to {relay}: {err:#}");
            return Ok(());
        }
    };
    info!("Connected to {relay}");

    io::copy_bidirectional(&mut sock, &mut relay.stream).await?;

    Ok(())
}

pub async fn run(mut rx: mpsc::Receiver<Relay>) -> Result<()> {
    let mut set = FuturesUnordered::new();

    loop {
        tokio::select! {
            req = rx.recv() => if let Some(req) = req {
                debug!("Received relay request: {req}");
                set.spawn(async {
                    if let Err(err) = relay(req).await {
                        error!("Relay error: {err}");
                    }
                })?;
            } else {
                info!("Relay channel closed");
                break;
            },
            Some(_) = set.next() => {
                debug!("Forwarding completed");
            }
        }
    }

    Ok(())
}
