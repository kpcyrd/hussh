# hussh

A minimal SSH server that only implements TCP forwarding ("direct-tcpip"). It is
intended for use as a restricted SSH tunnel, proxy or jump host where
interactive login sessions and remote command execution are not required or
desired. Only public-key authentication is supported, password logins are never
accepted. An optional low-interaction honeypot mode can log or report
unsolicited password authentication attempts.

- No password authentication, only public keys
- No shell access or command execution, only TCP forwarding
- No log noise from failed login attempts
- Memory-safe and based on [russh](https://github.com/Eugeny/russh)
- Optional low-interaction honeypot, record usernames and passwords used in bruteforce attacks

## Usage

```sh
# Start the server on port 20 (assuming 192.0.2.37 in the following examples)
hussh -c /etc/hussh.conf -D /var/lib/hussh -B '[::]:20'

# Set it up as a jump host for a 2nd, localhost-only SSH daemon
cat >> ~/.ssh/config <<EOF
Host example.com
Hostname 192.0.2.37
ProxyCommand ssh -p 20 -W 127.0.0.1:%p -o ProxyCommand=none %h
EOF

# Forward a TCP connection through ssh, connect it to stdin/stdout
ssh -p 20 -W example.com:80 192.0.2.37

# Start a socks5 proxy server on localhost:1080
# All connections are forwarded through the ssh server
ssh -p 20 -ND 1080 192.0.2.37

# Listen for incoming connections on localhost:1337 and forward
# them to localhost:8080 of the ssh server
ssh -p 20 -NL 127.0.0.1:1337:127.0.0.1:8080 192.0.2.37
```

## Configuration

A minimal configuration would look like this (allow any destination):

```toml
# /etc/hussh.conf
[[rules]]
ssh_keys = [
    "ssh-ed25519 AAAAC3Nyourkeyhere",
]
# Allowed destinations to connect to
permit = ["*"]
```

A more elaborate configuration could look like this:

```toml
# /etc/hussh.conf
[sshd]
# Change the ssh bind address (port 22 on ipv4 + ipv6)
bind_addr = "[::]:22"

[[rules]]
# Instead of allowing any username, require a specific value
username = "proxy"
ssh_keys = [
    "ssh-ed25519 AAAAC3Nyourkeyhere",
    "ssh-ed25519 AAAAC3Nanotherkey",
]
# Allowed destinations to connect to
permit = [
    # All ports on specific destinations
    "example.com:*",
    "127.0.0.1:*",
    # Filter by port
    "*:443",
]

# If the previous rule didn't match, try this one next:
[[rules]]
ssh_keys = [
    "ssh-ed25519 AAAAC3Nyourkeyhere",
]
permit = [
    # Allow specific locations only
    "127.0.0.1:8080",
    "[::1]:8080",
]
```

## Honeypot usage

In addition to operating as a network proxy, `hussh` can also be used as a
low-interaction SSH honeypot, to passively build combolists from internet
noise. When enabled, it records unsolicited password authentication attempts,
including the username, password and source address. This information can
either be logged or forwarded as json to a remote HTTP endpoint:

```toml
# /etc/hussh.conf
[honeypot]
# Change the SSH server banner to a custom string
# Note that invalid values may confuse or break clients
spoof_server_id = "SSH-2.0-anything"
# Log unsolicited password authentication attempts (including the password) to stderr
log_bruteforce_passwords = true
# Report unsolicited password authentication attempts to a remote server via http json post:
# {"username":"root","password":"123456","src":"192.0.2.34:56789"}
report_url_bruteforce_passwords = "https://example.com/report"
# In addition to unsolicited password authentication attempts,
# advertise that password authentication is supported/enabled
bait_password_bruteforce = true
```

## Installation

### Build from source

```sh
git clone https://github.com/kpcyrd/hussh.git
cd hussh
cargo build --release

install -Dm755 target/release/hussh /usr/bin/hussh
install -Dm644 contrib/hussh.conf /etc/hussh.conf
```

## License

`GPL-3.0-or-later`
