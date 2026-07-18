use crate::errors::*;
use crate::shared::Shared;
use crate::ssh::session::SshSession;
use russh::{MethodKind, MethodSet, SshId, keys::PrivateKey, server::*};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::time::Duration;

pub struct SshServer {
    shared: Arc<Shared>,
}

impl SshServer {
    pub fn new(shared: Shared) -> Self {
        Self {
            shared: Arc::new(shared),
        }
    }

    pub async fn run(&mut self, key: PrivateKey, bind: SocketAddr) -> Result<()> {
        let config = russh::server::Config {
            server_id: SshId::Standard("SSH-2.0-flowers-are-blooming-in-antarctica".into()),
            methods: MethodSet::from([MethodKind::PublicKey].as_slice()),
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
