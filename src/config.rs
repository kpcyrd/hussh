use crate::args::Args;
use crate::errors::*;
use russh::keys::PublicKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub sshd: Sshd,
    #[serde(default)]
    pub honeypot: Honeypot,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

impl Config {
    pub fn parse(config: &str) -> Result<Self> {
        let mut config = toml::from_str::<Config>(config)?;

        // Remove comments from keys, so we can do efficient .contains() BTreeSet operations
        config.rules.iter_mut().for_each(|rule| {
            rule.ssh_keys = mem::take(&mut rule.ssh_keys)
                .into_iter()
                .map(|mut key| {
                    key.set_comment("");
                    key
                })
                .collect();
        });

        Ok(config)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Sshd {
    bind_addr: Option<SocketAddr>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Honeypot {
    pub spoof_server_id: Option<String>,
    #[serde(default)]
    pub log_bruteforce_passwords: bool,
    pub report_url_bruteforce_passwords: Option<String>,
    #[serde(default)]
    pub bait_password_bruteforce: bool,
}

impl Sshd {
    pub fn bind_addr(&self, args: &Args) -> Option<SocketAddr> {
        args.bind.or(self.bind_addr)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Rule {
    pub username: Option<String>,
    pub ssh_keys: BTreeSet<PublicKey>,
    pub permit: Vec<Destination>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Destination {
    ExactAddr(SocketAddr),
    ExactHost((String, u16)),
    IpAnyPort(IpAddr),
    HostAnyPort(String),
    PortAnywhere(u16),
    Anything,
}

impl Destination {
    pub fn permits_ip(&self, ip: IpAddr, port: u16) -> bool {
        match self {
            Destination::ExactAddr(addr) => *addr == SocketAddr::new(ip, port),
            Destination::ExactHost(_) => false,
            Destination::IpAnyPort(dest_ip) => *dest_ip == ip,
            Destination::HostAnyPort(_) => false,
            Destination::PortAnywhere(dest_port) => *dest_port == port,
            Destination::Anything => true,
        }
    }

    pub fn permits_host(&self, host: &str, port: u16) -> bool {
        match self {
            Destination::ExactAddr(_) => false,
            Destination::ExactHost((dest_host, dest_port)) => {
                dest_host == host && *dest_port == port
            }
            Destination::IpAnyPort(_) => false,
            Destination::HostAnyPort(dest_host) => dest_host == host,
            Destination::PortAnywhere(dest_port) => *dest_port == port,
            Destination::Anything => true,
        }
    }
}

impl FromStr for Destination {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(if s == "*" || s == "*:*" {
            Destination::Anything
        } else if let Some(s) = s.strip_suffix(":*") {
            if let Some(ip) = s.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
                let ip = IpAddr::V6(ip.parse::<Ipv6Addr>()?);
                Destination::IpAnyPort(ip)
            } else if let Ok(ip) = s.parse::<Ipv4Addr>() {
                let ip = IpAddr::V4(ip);
                Destination::IpAnyPort(ip)
            } else {
                Destination::HostAnyPort(s.to_string())
            }
        } else if let Some(port) = s.strip_prefix("*:") {
            let port = port.parse::<u16>()?;
            Destination::PortAnywhere(port)
        } else if let Ok(addr) = s.parse::<SocketAddr>() {
            Destination::ExactAddr(addr)
        } else if let Some((host, port)) = s.rsplit_once(':') {
            let port = port.parse::<u16>()?;
            Destination::ExactHost((host.to_string(), port))
        } else {
            bail!("Invalid destination: {s:?}")
        })
    }
}

impl fmt::Display for Destination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Destination::ExactAddr(addr) => write!(f, "{addr}"),
            Destination::ExactHost((host, port)) => write!(f, "{host}:{port}"),
            Destination::IpAnyPort(ip) => write!(f, "{ip}:*"),
            Destination::HostAnyPort(host) => write!(f, "{host}:*"),
            Destination::PortAnywhere(port) => write!(f, "*:{port}"),
            Destination::Anything => write!(f, "*"),
        }
    }
}

impl Serialize for Destination {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = self.to_string();
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for Destination {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::{de, de::Visitor};

        struct DestinationVisitor;

        impl<'de> Visitor<'de> for DestinationVisitor {
            type Value = Destination;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a string representing a Destination")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                FromStr::from_str(v).map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_str(DestinationVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::fs;

    #[test]
    fn test_empty() {
        let config = Config::parse("").unwrap();
        assert_eq!(config, Default::default());
    }

    #[tokio::test]
    async fn test_example() {
        let config = fs::read_to_string("contrib/hussh.conf").await.unwrap();

        // Remove leading pound/comment markers, otherwise there won't be any settings
        let config = config
            .lines()
            .map(|line| line.strip_prefix('#').unwrap_or(line))
            .fold(String::new(), |mut acc, line| {
                acc.push_str(line);
                acc.push('\n');
                acc
            });

        // Parse and compare
        let config = Config::parse(&config).unwrap();
        assert_eq!(config, Config {
            sshd: Sshd { bind_addr: Some("[::]:2".parse().unwrap()) },
            honeypot: Honeypot {
                spoof_server_id: Some("SSH-2.0-anything".to_string()),
                log_bruteforce_passwords: true,
                report_url_bruteforce_passwords: Some("https://example.com/report".to_string()),
                bait_password_bruteforce: true,
            },
            rules: vec![
                Rule {
                    username: None,
                    ssh_keys: [
                        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbVfiAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".parse().unwrap(),
                    ].into_iter().collect(),
                    permit: vec![
                        Destination::Anything,
                    ],
                },
                Rule {
                    username: None,
                    ssh_keys: [
                        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbVfiAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".parse().unwrap(),
                    ].into_iter().collect(),
                    permit: vec![
                        Destination::ExactAddr("127.0.0.1:22".parse().unwrap()),
                    ],
                },
                Rule {
                    username: Some("proxy".to_string()),
                    ssh_keys: [
                        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbVfiAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".parse().unwrap(),
                    ].into_iter().collect(),
                    permit: vec![
                        Destination::PortAnywhere(80),
                        Destination::PortAnywhere(443),
                    ],
                },
            ],
        });
    }

    #[test]
    fn test_basic() {
        let config = Config::parse(
            r#"
[[rules]]
ssh_keys = [
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbVfiAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA asdf"
]
permit = []

[[rules]]
username = "foo"
ssh_keys = [
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbVfiBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
]
permit = ["127.0.0.1:22", "[2001:db8::1]:*"]
"#,
        )
        .unwrap();
        assert_eq!(
            config,
            Config {
                sshd: Default::default(),
                honeypot: Default::default(),
                rules: vec![
                    Rule {
                        username: None,
                        ssh_keys: [
                            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbVfiAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".parse().unwrap(),
                        ].into_iter().collect(),
                        permit: vec![],
                    },
                    Rule {
                        username: Some("foo".to_string()),
                        ssh_keys: [
                            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbVfiBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".parse().unwrap(),
                        ].into_iter().collect(),
                        permit: vec![
                            "127.0.0.1:22".parse().unwrap(),
                            "[2001:db8::1]:*".parse().unwrap(),
                        ],
                    },
                ],
            }
        );
    }

    #[test]
    fn test_destination_anything() {
        assert_eq!(Destination::from_str("*").unwrap(), Destination::Anything);
        assert_eq!(Destination::from_str("*:*").unwrap(), Destination::Anything);

        assert!(Destination::Anything.permits_host("example.com", 443));
        assert!(Destination::Anything.permits_ip("127.0.0.1".parse().unwrap(), 22));
        assert!(Destination::Anything.permits_ip("2001:db8::1".parse().unwrap(), 22));
    }

    #[test]
    fn test_destination_port_anywhere() {
        let dest = Destination::from_str("*:22").unwrap();
        assert_eq!(dest, Destination::PortAnywhere(22));

        assert!(dest.permits_host("example.com", 22));
        assert!(!dest.permits_host("example.com", 443));

        assert!(dest.permits_ip("127.0.0.1".parse().unwrap(), 22));
        assert!(!dest.permits_ip("127.0.0.1".parse().unwrap(), 443));

        assert!(dest.permits_ip("2001:db8::1".parse().unwrap(), 22));
        assert!(!dest.permits_ip("2001:db8::1".parse().unwrap(), 443));
    }

    #[test]
    fn test_destination_ipv4_any_port() {
        let dest = Destination::from_str("192.0.2.99:*").unwrap();
        assert_eq!(dest, Destination::IpAnyPort("192.0.2.99".parse().unwrap()));

        assert!(!dest.permits_host("example.com", 22));
        assert!(!dest.permits_host("example.com", 443));

        assert!(!dest.permits_ip("127.0.0.1".parse().unwrap(), 22));
        assert!(!dest.permits_ip("127.0.0.1".parse().unwrap(), 443));

        assert!(dest.permits_ip("192.0.2.99".parse().unwrap(), 22));
        assert!(dest.permits_ip("192.0.2.99".parse().unwrap(), 443));

        assert!(!dest.permits_ip("2001:db8::1".parse().unwrap(), 22));
        assert!(!dest.permits_ip("2001:db8::1".parse().unwrap(), 443));
    }

    #[test]
    fn test_destination_ipv6_any_port() {
        let dest = Destination::from_str("[2001:db8::1]:*").unwrap();
        assert_eq!(dest, Destination::IpAnyPort("2001:db8::1".parse().unwrap()));

        assert!(!dest.permits_host("example.com", 22));
        assert!(!dest.permits_host("example.com", 443));

        assert!(!dest.permits_ip("127.0.0.1".parse().unwrap(), 22));
        assert!(!dest.permits_ip("127.0.0.1".parse().unwrap(), 443));

        assert!(dest.permits_ip("2001:db8::1".parse().unwrap(), 22));
        assert!(dest.permits_ip("2001:db8::1".parse().unwrap(), 443));

        assert!(dest.permits_ip(
            "2001:0db8:0000:0000:0000:0000:0000:0001".parse().unwrap(),
            22
        ));
        assert!(dest.permits_ip(
            "2001:0db8:0000:0000:0000:0000:0000:0001".parse().unwrap(),
            443
        ));

        assert!(!dest.permits_ip("2001:db8::2".parse().unwrap(), 22));
        assert!(!dest.permits_ip("2001:db8::2".parse().unwrap(), 443));
    }

    #[test]
    fn test_destination_host_any_port() {
        let dest = Destination::from_str("example.com:*").unwrap();
        assert_eq!(dest, Destination::HostAnyPort("example.com".to_string()));

        assert!(dest.permits_host("example.com", 22));
        assert!(dest.permits_host("example.com", 443));

        assert!(!dest.permits_host(".com", 22));
        assert!(!dest.permits_host(".com", 443));

        assert!(!dest.permits_host("www.example.com", 22));
        assert!(!dest.permits_host("www.example.com", 443));

        assert!(!dest.permits_ip("127.0.0.1".parse().unwrap(), 22));
        assert!(!dest.permits_ip("127.0.0.1".parse().unwrap(), 443));

        assert!(!dest.permits_ip("192.0.2.99".parse().unwrap(), 22));
        assert!(!dest.permits_ip("192.0.2.99".parse().unwrap(), 443));

        assert!(!dest.permits_ip("2001:db8::1".parse().unwrap(), 22));
        assert!(!dest.permits_ip("2001:db8::1".parse().unwrap(), 443));
    }

    #[test]
    fn test_destination_exact_ipv4_port() {
        let dest = Destination::from_str("127.0.0.1:22").unwrap();
        assert_eq!(
            dest,
            Destination::ExactAddr("127.0.0.1:22".parse().unwrap())
        );

        assert!(!dest.permits_host("example.com", 22));
        assert!(!dest.permits_host("example.com", 443));

        assert!(dest.permits_ip("127.0.0.1".parse().unwrap(), 22));
        assert!(!dest.permits_ip("127.0.0.1".parse().unwrap(), 443));
        assert!(!dest.permits_ip("127.0.0.2".parse().unwrap(), 22));

        assert!(!dest.permits_ip("2001:db8::1".parse().unwrap(), 22));
        assert!(!dest.permits_ip("2001:db8::1".parse().unwrap(), 443));
    }

    #[test]
    fn test_destination_exact_ipv6_port() {
        let dest = Destination::from_str("[2001:db8::1]:22").unwrap();
        assert_eq!(
            dest,
            Destination::ExactAddr("[2001:db8::1]:22".parse().unwrap())
        );

        assert!(!dest.permits_host("example.com", 22));
        assert!(!dest.permits_host("example.com", 443));

        assert!(!dest.permits_ip("127.0.0.1".parse().unwrap(), 22));
        assert!(!dest.permits_ip("127.0.0.1".parse().unwrap(), 443));

        assert!(dest.permits_ip("2001:db8::1".parse().unwrap(), 22));
        assert!(dest.permits_ip(
            "2001:0db8:0000:0000:0000:0000:0000:0001".parse().unwrap(),
            22
        ));
        assert!(!dest.permits_ip("2001:db8::1".parse().unwrap(), 443));
        assert!(!dest.permits_ip("2001:db8::2".parse().unwrap(), 22));
    }

    #[test]
    fn test_destination_exact_host_port() {
        let dest = Destination::from_str("example.com:443").unwrap();
        assert_eq!(
            dest,
            Destination::ExactHost(("example.com".to_string(), 443))
        );

        assert!(!dest.permits_host("example.com", 22));
        assert!(dest.permits_host("example.com", 443));
        assert!(!dest.permits_host("com", 443));
        assert!(!dest.permits_host("www.example.com", 443));

        assert!(!dest.permits_ip("127.0.0.1".parse().unwrap(), 22));
        assert!(!dest.permits_ip("127.0.0.1".parse().unwrap(), 443));

        assert!(!dest.permits_ip("2001:db8::1".parse().unwrap(), 22));
        assert!(!dest.permits_ip("2001:db8::1".parse().unwrap(), 443));
    }
}
