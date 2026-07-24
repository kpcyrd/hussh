use crate::config::Destination;
use crate::errors::*;
use crate::relay::Relay;
use crate::shared::Shared;
use russh::{
    Channel, ChannelId,
    keys::PublicKey,
    server::{Auth, ChannelOpenHandle, Msg, Session},
};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

pub struct SshSession {
    /// For logging purposes, currently unused
    #[allow(unused)]
    addr: Option<SocketAddr>,
    shared: Arc<Shared>,
    permitted: Vec<Destination>,
    pending_channels: BTreeMap<ChannelId, Channel<Msg>>,
}

impl SshSession {
    pub fn new(addr: Option<SocketAddr>, shared: Arc<Shared>) -> Self {
        Self {
            addr,
            shared,
            permitted: vec![],
            pending_channels: Default::default(),
        }
    }

    pub fn take_pending_channel(&mut self, channel_id: ChannelId) -> Option<Channel<Msg>> {
        self.pending_channels.remove(&channel_id)
    }
}

struct PasswordAttempt<'a> {
    username: Cow<'a, str>,
    password: Cow<'a, str>,
    src: Option<SocketAddr>,
}

impl fmt::Display for PasswordAttempt<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "password attempt")?;
        if let Some(src) = self.src {
            write!(f, " from {src}")?;
        }
        write!(
            f,
            " for user {:?} with password {:?}",
            self.username, self.password
        )
    }
}

impl russh::server::Handler for SshSession {
    type Error = anyhow::Error;

    async fn auth_publickey_offered(
        &mut self,
        username: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        // The client asks if this username and public key combination would be allowed to authenticate
        // The key has not been challenged yet
        if self.shared.may_auth(username, public_key) {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        if self.shared.config().honeypot.log_bruteforce_passwords {
            let auth = PasswordAttempt {
                username: Cow::Borrowed(user),
                password: Cow::Borrowed(password),
                src: self.addr,
            };
            debug!("Rejected {auth}");
        }
        Ok(Auth::reject())
    }

    async fn auth_publickey(
        &mut self,
        username: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        let permitted = self.shared.auth(username, public_key);
        if !permitted.is_empty() {
            info!(
                "Authenticated user {username:?} with public key: {}",
                public_key.to_string()
            );
            self.permitted = permitted;
            Ok(Auth::Accept)
        } else {
            debug!("Rejected authentication for user {username:?} with public key {public_key:?}");
            Ok(Auth::reject())
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        open: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        debug!("Channel open session: {channel:?}");
        self.pending_channels.insert(channel.id(), channel);
        open.accept().await;
        Ok(())
    }

    async fn channel_close(&mut self, channel_id: ChannelId, _session: &mut Session) -> Result<()> {
        debug!("Client closed channel: {channel_id:?}");
        self.pending_channels.remove(&channel_id);
        // TODO: maybe shutdown active task (currently we use ChannelStream everywhere anyway)
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel_id: ChannelId,
        _session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        // After a client has sent an EOF, indicating that they don't want
        // to send more data in this session, the channel can be closed.
        trace!("Client sent channel EOF");
        self.pending_channels.remove(&channel_id);
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel_id: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        info!("Requested PTY for channel {channel_id:?}");
        self.take_pending_channel(channel_id);
        session.channel_failure(channel_id)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel_id: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        info!("Requested shell session for channel {channel_id:?}");
        let Some(_channel) = self.take_pending_channel(channel_id) else {
            session.channel_failure(channel_id)?;
            return Ok(());
        };

        let handle = session.handle();

        let error_msg = "Shell access disabled.\n";
        let _ = handle.extended_data(channel_id, 1, error_msg).await;
        let _ = handle.exit_status_request(channel_id, 1).await;
        let _ = handle.eof(channel_id).await;
        let _ = handle.close(channel_id).await;

        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel_id: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let cmd = String::from_utf8_lossy(data);
        debug!("Requested exec for channel {channel_id:?}: {cmd:?}");
        self.take_pending_channel(channel_id);
        session.channel_failure(channel_id)?;
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        open: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.shared.relay(
            Relay {
                host: host_to_connect.to_string(),
                port: port_to_connect as u16,
                stream: channel.into_stream(),
                open,
            },
            &self.permitted,
        );
        Ok(())
    }
}
