use crate::errors::*;
use crate::shared::Shared;
use serde::Serialize;
use std::fmt;
use std::future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time;

pub const BACKLOG: usize = 256;
const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const READ_TIMEOUT: Duration = Duration::from_secs(30);

const MAX_SUBMIT_ATTEMPTS: usize = 2;
const SUBMIT_RETRY_DELAY: Duration = Duration::from_secs(3);

#[derive(Serialize)]
pub struct PasswordAttempt {
    pub username: String,
    pub password: String,
    pub src: Option<SocketAddr>,
}

impl fmt::Display for PasswordAttempt {
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

async fn submit(http: &reqwest::Client, report_url: &str, attempt: &PasswordAttempt) {
    for i in 0..MAX_SUBMIT_ATTEMPTS {
        if i > 0 {
            // Briefly delay before retry
            time::sleep(SUBMIT_RETRY_DELAY).await;
        }

        if let Ok(res) = http
            .post(report_url)
            .json(attempt)
            .send()
            .await
            .inspect_err(|err| {
                error!("Failed to report password attempt: {err:#}");
            })
            && let Ok(_) = res.error_for_status().inspect_err(|err| {
                error!("Failed to report password attempt, server error: {err:#}");
            })
        {
            // Successfully submitted report
            return;
        }
    }

    warn!("Exceeded maximum attempts to report login attempt, giving up");
}

pub async fn logger(shared: Arc<Shared>, mut rx: mpsc::Receiver<PasswordAttempt>) {
    let http = reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .connect_timeout(CONNECT_TIMEOUT)
        .read_timeout(READ_TIMEOUT)
        .build();

    let http = match http {
        Ok(http) => http,
        Err(err) => {
            error!("Failed to setup http client, turning off reporting: {err:#}");
            drop(rx);
            return future::pending().await;
        }
    };

    while let Some(attempt) = rx.recv().await {
        let config = shared.config();

        // Unless explicitly configured otherwise, we just discard these login events

        if config.honeypot.log_bruteforce_passwords {
            debug!("Rejected {attempt}");
        }

        if let Some(report_url) = &config.honeypot.report_url_bruteforce_passwords {
            submit(&http, report_url, &attempt).await;
        }
    }
}
