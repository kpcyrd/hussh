use crate::errors::*;
use crate::shared::Shared;
use crate::ssh::session::SshSession;
use russh::{MethodKind, MethodSet, SshId, keys::PrivateKey, server::*};
use std::borrow::Cow;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::time::Duration;

const SERVER_ID: &str = "SSH-2.0-flowers-are-blooming-in-antarctica";

pub struct SshServer {
    shared: Arc<Shared>,
}

impl SshServer {
    pub fn new(shared: Arc<Shared>) -> Self {
        Self { shared }
    }

    pub async fn run(&mut self, key: PrivateKey, bind: SocketAddr) -> Result<()> {
        let config = self.shared.config();

        // Replace the standard SSH banner if one is configured
        let server_id = config
            .honeypot
            .spoof_server_id
            .clone()
            .map(Cow::Owned)
            .unwrap_or(Cow::Borrowed(SERVER_ID));

        // Make incorrect claims about password authentication if configured to do so
        let methods = MethodSet::from(if config.honeypot.bait_password_bruteforce {
            [MethodKind::Password, MethodKind::PublicKey].as_slice()
        } else {
            [MethodKind::PublicKey].as_slice()
        });

        let config = russh::server::Config {
            server_id: SshId::Standard(server_id),
            methods,
            /*
            keepalive_interval: Some(KEEPALIVE_INTERVAL),
            keepalive_max: KEEPALIVE_MAX as usize,
            */
            auth_rejection_time: Duration::from_millis(250),
            auth_rejection_time_initial: Some(Duration::from_secs(0)),
            keys: vec![key],
            nodelay: true,
            ..Default::default()
        };

        info!("Starting SSH server on {bind}");
        self.run_on_address(Arc::new(config), bind).await?;
        bail!("SSH server has stopped unexpectedly")
    }
}

impl Server for SshServer {
    type Handler = SshSession;

    fn new_client(&mut self, addr: Option<SocketAddr>) -> Self::Handler {
        SshSession::new(addr, self.shared.clone())
    }
}
