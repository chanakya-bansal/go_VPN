# govpn: An Encrypted VPN Built from Scratch in Go

A working VPN written in Go for the Computer Networks course. A client captures raw IP packets from a virtual network interface (TUN), encrypts them, and sends them over UDP to a server. The server decrypts them and forwards them to the internet using NAT. Keys are agreed using an **X25519 Diffie-Hellman handshake**, and traffic is protected with **ChaCha20-Poly1305**.

The server is deployed on an AWS EC2 instance in Tokyo (`ap-northeast-1`). Websites therefore see a Japanese IP address instead of the user's real one.

## Table of Contents

1. [Features](#features)
2. [How It Works](#how-it-works)
3. [Repository Structure](#repository-structure)
4. [Software Requirements](#software-requirements)
5. [Installation](#installation)
6. [Execution Steps](#execution-steps)
7. [Expected Results](#expected-results)
8. [Testing Results](#testing-results)
9. [Security Design](#security-design)
10. [Limitations and Future Work](#limitations-and-future-work)
11. [Team](#team)

## Features

- Layer 3 VPN using a TUN device and UDP transport
- Ephemeral X25519 key exchange with forward secrecy
- HKDF-SHA256 key derivation, giving a separate key for each direction
- Handshake authentication with an HMAC under a pre-shared key (PSK)
- Per-packet encryption and integrity with ChaCha20-Poly1305, with the header authenticated
- Full-tunnel routing: all IPv4 traffic goes through the VPN, with an exception for the tunnel's own packets
- Server-side NAT (MASQUERADE) and TCP MSS clamping, so clients get real internet access
- Retransmission-safe handshake: a repeated ClientHello gets the same reply instead of resetting the session
- Server runs as a `systemd` service on EC2

## How It Works

```
 WSL machine (client)                                        AWS EC2, Tokyo (server)
┌───────────────────────────────────┐                      ┌──────────────────────────────────┐
│ vpnclient namespace               │                      │                                  │
│  app -> vpn-c0 (TUN) 10.8.0.2     │                      │  vpn-s0 (TUN) 10.8.0.1           │
│       -> client: encrypt          │                      │     ^                            │
│       -> UDP ---------------------┼── internet (UDP 5555)┼─> server: verify + decrypt       │
│                                   │   encrypted          │     |                            │
└───────────────────────────────────┘                      │  ip_forward + NAT -> ens5 -> web │
                                                           └──────────────────────────────────┘
```

The full diagram is in [`docs/vpn_architecture.png`](docs/vpn_architecture.png).

### Handshake

| Step | Sender | Content |
|---|---|---|
| 1 | Client | `ClientHello = header \| clientPub \| HMAC(psk, header \| clientPub)` |
| 2 | Server | Verifies the HMAC, generates its own key pair, computes the shared secret |
| 3 | Both | `HKDF-SHA256(shared, salt = clientPub \| serverPub)` produces 64 bytes: the first 32 are the client→server key, the last 32 the server→client key |
| 4 | Server | `ServerHello = header(session ID) \| serverPub \| HMAC(psk, header \| serverPub \| clientPub)` |
| 5 | Client | Verifies the HMAC, derives the same keys |

### Data packet format

```
 0        1        4              8                  16                      16+n          16+n+16
 +--------+--------+--------------+------------------+------------------------+--------------+
 | type=3 | zeros  | session ID   | counter (nonce)  | ChaCha20 ciphertext    | Poly1305 tag |
 +--------+--------+--------------+------------------+------------------------+--------------+
 |<------- 16-byte header (authenticated as AAD) --->|<-- encrypted IP packet -->|
```

### Packet journey

1. An app sends a packet. The kernel's routing table (`0.0.0.0/1` and `128.0.0.0/1`) sends it into `vpn-c0`.
2. The client reads the raw IP packet, encrypts it in place, and sends it as a UDP datagram.
3. The server authenticates and decrypts it, then writes it into `vpn-s0`.
4. The server's kernel forwards the packet, and NAT rewrites its source address to the server's own address.
5. Replies come back the same way: NAT reverses the rewrite, the server encrypts with the other direction's key, and the client decrypts and delivers the packet to the app.

## Repository Structure

```
go_VPN/
├── client/
│   ├── main.go            # TUN <-> UDP loops, flags, shutdown
│   ├── session.go         # client side of the handshake
│   ├── routes_linux.go    # full-tunnel routing setup and cleanup
│   └── tun.go             # TUN device creation
├── server/
│   ├── main.go            # UDP listener, packet loops
│   ├── handshake.go       # server side of the handshake, session state
│   ├── sessions.go        # session handling (multi-client table planned)
│   ├── tun.go             # TUN device creation
│   └── deploy/
│       ├── setup.sh       # IP forwarding, NAT, MSS clamp (up/down)
│       └── vpn-server.service   # systemd unit
├── shared/
│   ├── crypto/            # X25519, HKDF, HMAC, ChaCha20-Poly1305
│   └── protocol/          # header and message formats, packet parsing/logging
├── scripts/
│   └── netns-test.sh      # creates the fake client machine (network namespace)
├── docs/                  # diagrams
├── screenshots/           # test evidence
├── go.mod / go.sum
├── Makefile
└── README.md
```

## Software Requirements

| Component | Requirement |
|---|---|
| OS (client and server) | Linux (tested on Ubuntu under WSL2, and Ubuntu 24.04 on EC2) |
| Language | Go (the version in `go.mod`) |
| Libraries | `golang.zx2c4.com/wireguard/tun` (TUN device), `golang.org/x/crypto` (ChaCha20-Poly1305) |
| Tools | `iproute2` (`ip`), `iptables`, `git`, `tcpdump` (for verification) |
| Privileges | `root` / `sudo` (creating TUN devices and changing routes needs it) |
| Cloud (for deployment) | AWS account, EC2 `t3.micro` in `ap-northeast-1`, security group allowing **UDP 5555** |
| Optional | Firefox with WSLg, to watch YouTube through the tunnel |

The client currently runs on Linux only. A native Windows client is future work.

## Installation

```bash
git clone https://github.com/<your-user>/<repo>.git
cd <repo>

go mod tidy
mkdir -p bin
go build -o bin/server ./server
go build -o bin/client ./client

chmod +x scripts/netns-test.sh server/deploy/setup.sh
```

## Execution Steps

All commands run from the project root. Use a pre-shared key of your own in place of `secret123`.

### A. Local test (client and server on one machine)

The client runs in a Linux network namespace so that it behaves like a separate computer.

**Terminal 1: network setup**
```bash
sudo ./scripts/netns-test.sh up        # namespace "vpnclient": veth-c 192.168.100.2 <-> veth-h 192.168.100.1
sudo ./server/deploy/setup.sh up       # IP forwarding + NAT + MSS clamp
```

**Terminal 2: server**
```bash
sudo ./bin/server -psk secret123
```

**Terminal 3: client**
```bash
sudo ip netns exec vpnclient ./bin/client -server 192.168.100.1:5555 -psk secret123 -route
```

**Terminal 4: tests**
```bash
sudo ip netns exec vpnclient ping -c 3 10.8.0.1                  # tunnel endpoint
sudo ip netns exec vpnclient ping -c 3 1.1.1.1                   # internet through the tunnel
sudo ip netns exec vpnclient curl -sI https://example.com | head -3
```

**Terminal 5: prove the traffic is encrypted**
```bash
sudo tcpdump -i veth-h -n -X udp port 5555    # unreadable ciphertext
sudo tcpdump -i vpn-s0 -n                     # readable ICMP (after decryption)
```

**Cleanup**
```bash
# Ctrl+C the client and the server, then:
sudo ./server/deploy/setup.sh down
sudo ./scripts/netns-test.sh down
```

### B. Deployment on AWS EC2 (Tokyo)

**1. Launch the instance.** Region `ap-northeast-1`, Ubuntu 24.04, `t3.micro`. Security group: TCP 22 from your IP, UDP 5555 from anywhere.

**2. Build and install on the instance.**
```bash
sudo apt update && sudo apt install -y git golang-go
git clone https://github.com/<your-user>/<repo>.git && cd <repo>
go build -o govpn-server ./server

sudo mkdir -p /opt/govpn
sudo cp govpn-server /opt/govpn/server
sudo cp server/deploy/setup.sh /opt/govpn/setup.sh
sudo chmod +x /opt/govpn/server /opt/govpn/setup.sh

echo "GOVPN_PSK=$(openssl rand -hex 24)" | sudo tee /etc/govpn.env
sudo chmod 600 /etc/govpn.env

sudo cp server/deploy/vpn-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vpn-server
systemctl status vpn-server --no-pager      # expect: active (running)
```

The PSK is stored only in `/etc/govpn.env`. It is never committed to the repository. If your Go version is older than the one in `go.mod`, install a current Go from <https://go.dev/dl>.

**3. Prepare the client machine (WSL).** The namespace now reaches the server over the real internet, so it needs a default route and NAT through the WSL host.
```bash
sudo ./scripts/netns-test.sh up
sudo ip netns exec vpnclient ip route add default via 192.168.100.1
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -s 192.168.100.0/24 -o eth0 -j MASQUERADE
```

**4. Run the client.**
```bash
sudo ip netns exec vpnclient ./bin/client -server <EC2_PUBLIC_IP>:5555 -psk <PSK> -route -v=false
```

**5. Keep the tunnel's NAT mapping alive** (there is no built-in keepalive yet):
```bash
sudo ip netns exec vpnclient ping -i 15 10.8.0.1 > /dev/null &
```

**6. Verify.**
```bash
sudo ip netns exec vpnclient curl -s https://ipinfo.io/country     # JP
sudo ip netns exec vpnclient curl -s https://ifconfig.me           # the EC2 address
```

**7. (Optional) Open YouTube through the tunnel with Firefox in the namespace.**
```bash
mkdir -p /tmp/ff-japan
sudo ip netns exec vpnclient sudo -u $USER env \
  HOME=$HOME DISPLAY=$DISPLAY WAYLAND_DISPLAY=$WAYLAND_DISPLAY \
  XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR PULSE_SERVER=$PULSE_SERVER \
  firefox --no-remote --profile /tmp/ff-japan
```
This needs the non-snap build of Firefox (the snap version fails inside a network namespace).

### Command-line flags

| Program | Flag | Default | Meaning |
|---|---|---|---|
| both | `-psk` | `$GOVPN_PSK` | Pre-shared key (required) |
| both | `-name` | `vpn-c0` / `vpn-s0` | TUN interface name |
| both | `-addr` | `10.8.0.2/24` / `10.8.0.1/24` | TUN address (CIDR) |
| both | `-v` | `true` | Log every packet (use `-v=false` for deployment) |
| client | `-server` | none (required) | Server address, `IP:port` |
| client | `-route` | `false` | Send all IPv4 traffic through the tunnel |
| server | `-listen` | `:5555` | UDP address to listen on |

### Stop and restart notes

- Start the server first, then the client.
- Restart the client whenever the server restarts (no automatic reconnect yet).
- A stopped EC2 instance gets a new public IP unless an Elastic IP is attached.

## Expected Results

| Check | Expected outcome |
|---|---|
| Client start | `handshake OK, session <id>` and `all IPv4 traffic now goes through vpn-c0` |
| Server start | `listening on UDP [::]:5555`, then `handshake OK with <client>:<port>, session <id>` |
| `ping 10.8.0.1` | 0% loss, replies from the server's tunnel address |
| `ping 1.1.1.1` | Replies through the tunnel and NAT |
| `curl https://example.com` | `HTTP/2 200` |
| `tcpdump` on the physical link | UDP packets with a 16-byte header followed by random bytes. No readable ICMP or HTTP |
| `tcpdump` on `vpn-s0` | Readable ICMP, because this is after decryption |
| Wrong PSK | Server logs `bad MAC (wrong PSK?)`. Client prints `handshake failed` after about 10 s and changes no routes |
| Tokyo deployment | `ipinfo.io` reports country `JP`, and YouTube shows Japan's regional homepage |

## Testing Results

Screenshots are in [`screenshots/`](screenshots/).

### Local test (client in a namespace, server on the host)

| Test | Result |
|---|---|
| Handshake | Client and server both reported session `594117996`, so the derived keys match |
| `ping 10.8.0.1` | 3/3 replies, about 0.5 to 1.2 ms |
| `ping 1.1.1.1` through the tunnel | Replies at about 8 to 17 ms. One of the first three-packet runs lost one packet (WSL upstream NAT, not the tunnel). Later runs showed 0% loss |
| `curl https://example.com` | `HTTP/2 200` |
| Packet capture on `veth-h` | 116-byte UDP datagrams for each 84-byte ICMP packet (16 header + 84 payload + 16 tag). Data type byte is `03`, the session ID is constant, and the counter increases by one per packet. The payload is unreadable |
| Packet capture on `vpn-s0` | Plain ICMP echo request and reply, confirming correct decryption |
| Wrong PSK | Five handshake attempts rejected with `bad MAC`. Client exited after about 10 s |

### Tokyo deployment

Fill in after running on EC2:

| Measurement | Without VPN | With VPN (Tokyo) |
|---|---|---|
| Public IP (`ifconfig.me`) |  |  |
| Country (`ipinfo.io/country`) |  | JP |
| `ping 1.1.1.1` average (ms) |  |  |
| YouTube region | | Japan |

Screenshots to add: `systemctl status vpn-server` showing `active (running)`, the `ipinfo.io` result with the Tokyo IP, and Firefox playing YouTube through the tunnel.

## Security Design

| Concern | Mechanism |
|---|---|
| Eavesdropping | ChaCha20-Poly1305 encryption of every packet |
| Tampering | Poly1305 tag over the ciphertext and the header |
| Key agreement without sending the key | X25519 Diffie-Hellman |
| Forward secrecy | Ephemeral key pairs, discarded after the handshake |
| Man-in-the-middle during the handshake | HMAC under the PSK on both hello messages |
| Replayed ServerHello | The server's MAC covers the client's public key |
| Nonce reuse | The counter is the nonce, and each direction has its own key |
| Session hijack | The client's address is updated only after a packet authenticates |
| Port scanning | Messages without a valid HMAC are dropped silently |

## Limitations and Future Work

- **Replay protection:** nothing rejects a replayed data packet yet. A sliding window of counters is planned.
- **Hello replay:** an old ClientHello can be replayed, which can reset the session (a denial of service, but it reveals no keys). Timestamp checks are planned.
- **Single client:** the server holds one session. A session table with per-client virtual IPs is planned.
- **No keepalive, rekeying or reconnect:** the tunnel stalls if idle for too long, and the client must be restarted after a server restart.
- **IPv4 only:** IPv6 traffic is not tunnelled, which can leak if the client has IPv6.
- **Linux client only:** a native Windows client (Wintun) is planned.
- **Pre-shared key authentication:** a leaked PSK lets an attacker impersonate the server in future handshakes (past traffic stays safe thanks to ephemeral keys).
- **Benchmarks:** `iperf3` throughput tests with the tunnel off and on are still to do.

## Team

| Name | Registration No. | Contribution |
|---|---|---|
|  |  |  |
|  |  |  |
|  |  |  |

Course: Computer Networks. Institution: VIT Vellore.
