# NetData Project

A Rust project for network packet capture and visualization consisting of two applications:
- `net_listener`: captures packets, parses them, shows a terminal UI, and sends `NetData` frames on a Unix datagram socket
- `net_visualizator`: native egui window that reads those frames

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
| UDP | Ports, plus an application label taken from either port. The more specific label wins: DHCP / DHCPv6 / mDNS / SSDP, then DNS / LLMNR / NBNS / NTP, then QUIC / WireGuard / ESP-over-UDP. |
| ICMPv4 | Echo (id, sequence), Destination Unreachable (code, and next-hop MTU when the code is 4), Time Exceeded, Parameter Problem, Redirect (code and gateway), Timestamp, Router Advertisement / Solicitation. The embedded original datagram and the RA address list are not read. |
| ICMPv6 | Echo, Destination Unreachable, Packet Too Big, Time Exceeded, Parameter Problem, NDP (Router Solicitation/Advertisement, Neighbor Solicitation/Advertisement, Redirect), MLD Query/Report/Done, and MLDv2 Report. Neighbor Solicitation keeps the source link-layer address, Neighbor Advertisement the target one. Other NDP options and MLDv2 records are not read. |
| IGMP | v1 and v2 Query, Report, and Leave. v3 Query and Report, with at most 16 source addresses and 8 group records. |
| ESP (protocol 50) | SPI and the payload length. Sequence, ciphertext, and ICV are not read. |

These UDP labels are checked against the payload. A body that does not match drops the label and leaves plain UDP:

- **DNS, mDNS, and LLMNR** (53, 5353, 5355). The first question name is kept, up to 64 characters, including compressed names. Answers may keep the first SRV record (port and target host). mDNS also keeps the `_service._proto` labels and the name from the first PTR record.
- **DHCPv4** (67/68) must carry magic cookie `0x63825363`. Option 53 is the message type (Discover, Offer, Request, Decline, Ack, Nak, Release, Inform). Option 12 is the hostname (up to 64 characters). Option 50 is the requested IPv4, and only when it is exactly 4 bytes.
- **SSDP** (1900). The start line is `M-SEARCH`, `NOTIFY`, or `HTTP/1.x`. Headers kept: `NT`, `USN`, `LOCATION` (up to 128 characters).
- **DHCPv6** (546/547). The message type is the first byte, types 1–13, when the message is long enough (at least 4 bytes, relay types 12–13 at least 34). Transaction id and options are not read.
- **NBNS** (137). The first label is 32 characters `A`–`P`. Kept: the name, suffix, NB or NBSTAT, and the opcode. A reply also keeps the result code and the IPv4 of the first complete NB record.

Labels that stay on the port alone: NTP (123), QUIC (443), WireGuard (51820), ESP-over-UDP (4500).

Anything else above IP (GRE, SCTP, AH as the final header, and the rest of the IANA numbers) is an unsupported L4 protocol.

## Not parsed yet

Left for later. Do not start these without a request.

On the LAN, when that traffic is present:

- STP/RSTP BPDUs (LLC DSAP/SSAP `0x42`, not SNAP).
- A WireGuard header check on UDP 51820. Today the label is the port alone.

Still unread inside messages that are already recognized:

- Other NDP options on Router Advertisement, Neighbor Solicitation, and Neighbor Advertisement (prefixes, DNS). The neighbor MAC on NS and NA is already kept.
- The ICMPv4 Router Advertisement address list.
- MLDv2 Report records and their source lists. The `MldV2Report` variant is empty.
- IGMP v3 source lists past 16 addresses, and group records past 8.
- QUIC beyond the port label.

Checksums, fragment reassembly, AH, GRE, and SCTP are not implemented.

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

### Native (desktop)

Build the whole workspace:

```bash
cargo build --workspace
```

Build individual binaries:

```bash
cargo build --bin net_listener
cargo build --bin net_visualizator
```

Release build for the visualizer:

```bash
cargo build --release --bin net_visualizator
```

`net_listener` needs the libpcap development package (see Prerequisites). The GUI binary only needs a normal Rust toolchain.

### WASM (browser)

The UI library uses `web-time`, so `Instant::now` will not panic on wasm32. There is no browser entry: no `eframe::WebRunner`, `index.html`, `Trunk.toml`, or WebSocket source.

## Running

### Running net_listener

**Important:** `net_listener` requires elevated privileges to capture packets.

Option 1: Run with sudo (not recommended for production)
```bash
sudo cargo run --bin net_listener
```

Option 2: Set capabilities (recommended)
```bash
# Build first. .cargo/config.toml sets target-dir to /tmpu/NetData.
cargo build --bin net_listener

# Set capabilities
sudo setcap cap_net_raw,cap_net_admin=eip /tmpu/NetData/debug/net_listener

# Run without sudo
/tmpu/NetData/debug/net_listener
```

### Running net_visualizator (native)

```bash
cargo run --bin net_visualizator
```

Optional socket paths:

```bash
cargo run --bin net_visualizator -- \
  --listener /tmpu/net_listener_stats2.sock \
  --socket /tmpu/net_visualizator.sock
```

Either process can start first. The visualizer binds `/tmpu/net_visualizator.sock` and sends a hello to `/tmpu/net_listener_stats2.sock` once a second until frames arrive. The listener binds its own socket and sends frames to whoever sent that hello.

Logs: `/tmpu/net_listener.log`, `/tmpu/net_visualizator.log`.

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
sudo setcap cap_net_raw,cap_net_admin=eip /tmpu/NetData/debug/net_listener
```

See [DEBUGGING.md](DEBUGGING.md) for more debugging information.
