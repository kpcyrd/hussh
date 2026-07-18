use crate::config::{Config, Destination, Rule};
use crate::errors::*;
use crate::relay::Relay;
use russh::keys::PublicKey;
use std::net::IpAddr;
use tokio::sync::mpsc;

const BACKLOG: usize = 32;

#[derive(Debug)]
pub struct Shared {
    config: Config,
    relay_tx: mpsc::Sender<Relay>,
}

impl Shared {
    pub fn from_config(config: Config) -> (Self, mpsc::Receiver<Relay>) {
        let (relay_tx, relay_rx) = mpsc::channel(BACKLOG);
        (Self { config, relay_tx }, relay_rx)
    }

    fn matching_rules(
        &self,
        username: &str,
        public_key: &PublicKey,
    ) -> impl Iterator<Item = &Rule> {
        self.config.rules.iter().filter(|rule| {
            (rule.username.is_none() || rule.username.as_deref() == Some(username))
                && rule.ssh_keys.contains(public_key)
                && !rule.permit.is_empty()
        })
    }

    pub fn may_auth(&self, username: &str, public_key: &PublicKey) -> bool {
        self.matching_rules(username, public_key).next().is_some()
    }

    pub fn auth(&self, username: &str, public_key: &PublicKey) -> Vec<Destination> {
        self.matching_rules(username, public_key)
            .flat_map(|rule| rule.permit.iter())
            .cloned()
            .collect()
    }

    pub fn relay(&self, relay: Relay, permitted: &[Destination]) {
        // Check if allowed
        let permitted = if let Ok(ip) = relay.host.parse::<IpAddr>() {
            permitted.iter().any(|dest| dest.permits_ip(ip, relay.port))
        } else {
            permitted
                .iter()
                .any(|dest| dest.permits_host(&relay.host, relay.port))
        };

        if !permitted {
            error!("Relay request not permitted: {relay}");
            return;
        }

        // Queue the request for relaying
        if let Err(err) = self.relay_tx.try_send(relay) {
            error!("Failed to queue relay request: {err:#}");
        }
    }
}
