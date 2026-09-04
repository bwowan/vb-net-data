# NetData Project

A Rust project for network packet capture and visualization consisting of two applications:
- `net_listener`: Console application for packet capture and analysis
- `net_visualizator`: 3D visualization application using Bevy

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
