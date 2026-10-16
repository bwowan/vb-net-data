# NetData Project

A Rust project for network packet capture and visualization consisting of two applications:
- `net_listener`: Console application for packet capture and analysis
- `net_visualizator`: 3D visualization application using Bevy

## Protocols parsed by `net_listener`

The capture loop hands each frame to the parser. Ethernet II is dispatched by EtherType. Frames with a length field (≤ 0x05DC) are read as LLC/SNAP. Inside IPv4 and IPv6, one L4 protocol is stored on the packet.

A non-first IP fragment is recorded as a fragment and is not parsed as TCP, UDP, or ICMP. The first fragment (offset 0) is. IPv6 Hop-by-Hop, Routing, Destination Options, Fragment, and AH are skipped so the next header can be read. Checksums are not verified.

### Ethernet

| EtherType | What is kept |
|---|---|
| IPv4 (`0x0800`), IPv6 (`0x86DD`) | Addresses and the L4 message below. Payload length comes from the IP header, so Ethernet padding is not counted. |
| ARP (`0x0806`), RARP (`0x8035`) | Ethernet + IPv4 only: operation, sender and target MAC and IPv4. |
| MPLS (`0x8847`), MPLS multicast (`0x8848`) | The top label: label, traffic class, bottom-of-stack, TTL. Further labels are not read. |
| LLDP (`0x88CC`) | TTL, system capabilities, management addresses, and other TLVs (value truncated). |
| ECTP (`0x9003`) | Skip count, function code, and the MAC that should receive the reply. |

### LLC/SNAP

| OUI | What is kept |
|---|---|
| Cisco `00:00:0C`, protocol `0x2000` | CDP: version, TTL, addresses, capabilities, and other TLVs (value truncated). |
| DEC `08:00:2B` | SNAP header only (DSAP/SSAP, control, OUI, protocol id). The DEC payload is not decoded. |

Other Cisco SNAP ids (CGMP, VTP, DTP, PAgP, PVST+, UDLD) and any other OUI are reported as an error, not as a decoded protocol.

### IPv4 / IPv6 transport

| Protocol | What is kept |
|---|---|
| TCP | Source and destination ports. |
| UDP | Ports, plus an application label taken from either port. The more specific label wins: DHCP / mDNS / SSDP, then DNS / LLMNR / NTP, then QUIC / WireGuard / ESP-over-UDP. |
| ICMPv4 | Echo (id, sequence), Destination Unreachable (code, and next-hop MTU when the code is 4), Time Exceeded, Parameter Problem, Redirect (code and gateway), Timestamp, Router Advertisement / Solicitation. The embedded original datagram and the RA address list are not read. |
| ICMPv6 | Echo, Destination Unreachable, Packet Too Big, Time Exceeded, Parameter Problem, NDP (Router Solicitation/Advertisement, Neighbor Solicitation/Advertisement, Redirect), MLD Query/Report/Done, and MLDv2 Report. NDP options and MLDv2 records are not read. |
| IGMP | v1 and v2 Query, Report, and Leave. v3 Query and Report, with at most 16 source addresses and 8 group records. |
| ESP (protocol 50) | SPI and the payload length. Sequence, ciphertext, and ICV are not read. |

UDP labels that stay on the port alone: DHCPv6 (546/547), SSDP (1900), NTP (123), QUIC (443), WireGuard (51820), ESP-over-UDP (4500).

Two of those labels are checked against the payload:

- **DNS, mDNS, and LLMNR** (53, 5353, 5355) must look like a DNS message. The first question name is kept, up to 64 characters, including compressed names. If the name is broken, the packet stays UDP without the DNS label. mDNS also keeps the `_service._proto` labels and the name from the first PTR record.
- **DHCPv4** (67/68) must carry magic cookie `0x63825363`. Option 53 supplies Discover, Offer, Request, Decline, Ack, Nak, Release, or Inform. Without the cookie the packet stays plain UDP.

Anything else above IP (GRE, SCTP, AH as the final header, and the rest of the IANA numbers) is an unsupported L4 protocol.

## TODO: more LAN protocols

Next parses for a local network, in this order:

1. Neighbor MAC from NDP options on Neighbor Solicitation and Neighbor Advertisement.
2. DHCPv4 hostname (option 12) and the requested IP address.
3. SSDP (UDP 1900): the start line plus `NT`, `USN`, and `LOCATION`.
4. DHCPv6 (546/547): message type from the first byte.

Only when that traffic is on the LAN: NetBIOS Name Service (UDP 137); STP/RSTP BPDUs (LLC DSAP/SSAP `0x42`, not SNAP); a WireGuard header check on UDP 51820.

## Prerequisites

### Ubuntu/Debian

Install the required system dependencies:

```bash
sudo apt-get update
sudo apt-get install -y \
    libpcap-dev \
    build-essential \
    pkg-config
```

### Fedora/RHEL/CentOS

```bash
sudo dnf install -y \
    libpcap-devel \
    gcc \
    pkg-config
```

### Arch Linux

```bash
sudo pacman -S --needed \
    libpcap \
    base-devel \
    pkgconf
```

## Building

Build all projects:

```bash
cargo build --workspace
```

Build individual projects:

```bash
# Build net_listener
cargo build --bin net_listener

# Build net_visualizator
cargo build --bin net_visualizator
```

## Running

### Running net_listener

**Important:** `net_listener` requires elevated privileges to capture packets.

Option 1: Run with sudo (not recommended for production)
```bash
sudo cargo run --bin net_listener
```

Option 2: Set capabilities (recommended)
```bash
# Build first
cargo build --bin net_listener

# Set capabilities
sudo setcap cap_net_raw,cap_net_admin=eip target/debug/net_listener

# Run without sudo
./target/debug/net_listener
```

### Running net_visualizator

```bash
cargo run --bin net_visualizator
```

**Note:** Start `net_visualizator` before `net_listener` to ensure the Unix Domain Socket is available.

## Troubleshooting

### Error: `cannot find -lpcap: No such file or directory`

This means the libpcap development package is not installed. Install it using:

**Ubuntu/Debian:**
```bash
sudo apt-get install libpcap-dev
```

**Fedora/RHEL:**
```bash
sudo dnf install libpcap-devel
```

**Arch Linux:**
```bash
sudo pacman -S libpcap
```

### Permission denied when capturing packets

Set the required capabilities:
```bash
sudo setcap cap_net_raw,cap_net_admin=eip target/debug/net_listener
```

See [DEBUGGING.md](DEBUGGING.md) for more debugging information.
