# hussh

Memory-safe SSH daemon for restricted TCP forwarding.

## Usage

```sh
# Start the server (assuming 192.0.2.37)
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

## Installation

### Build from source

```sh
git clone https://github.com/kpcyrd/hussh.git
cd hussh
cargo build --release

install -Dm755 target/release/hussh /usr/bin/hussh
install -Dm644 contrib/hussh.conf /etc/hussh.conf
```
