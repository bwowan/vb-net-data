# Debugging Guide for NetData

Cargo writes binaries to `/tmpu/NetData` (`.cargo/config.toml`, `target-dir`), not to `target/`.

- Listener: `/tmpu/NetData/debug/net_listener`
- Visualizer: `/tmpu/NetData/debug/net_visualizator`

The listener needs `cap_net_raw` and `cap_net_admin`. The visualizer does not.

```bash
cargo build --bin net_listener
sudo setcap cap_net_raw,cap_net_admin=eip /tmpu/NetData/debug/net_listener
```

Logs, because the listener's terminal is the ratatui screen:

- `/tmpu/net_listener.log`
- `/tmpu/net_visualizator.log`

## Launch configs

Open the workspace root `/mnt/DevData/Rust/NetData`. Configs are in `.vscode/launch.json` (CodeLLDB, `"type": "lldb"`):

- `Debug executable 'net_listener'` — build, then setcap on `/tmpu/NetData/debug/net_listener`
- `Debug executable 'net_listener' (built binary)` — same binary path
- `Debug executable 'net_visualizator'`
- unit tests for `common`, `net_listener`, and `net_visualizator`

Open the `net_listener` folder and the configs in `net_listener/.vscode/launch.json` are different. `Debug as Root (via lldb-server)` expects a server that is already running:

```bash
sudo lldb-server platform --listen "*:1234" --server
```

The setcap tasks in that nested folder still name `target/debug`. Cargo does not write the binary there. Set the capability on `/tmpu/NetData/debug/net_listener`, or use the root task `Build-net_listener-setCap`.

## Command line

```bash
cargo build --bin net_listener
sudo setcap cap_net_raw,cap_net_admin=eip /tmpu/NetData/debug/net_listener
lldb /tmpu/NetData/debug/net_listener
```

`sudo lldb` also works. Setcap is the usual path.

## Troubleshooting

### `cannot find -lpcap`

The libpcap development package is missing.

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

Then rebuild. The binary appears under `/tmpu/NetData/debug/`.

### Check the toolchain

```bash
which lldb
pkg-config --modversion libpcap
ldconfig -p | grep pcap
```

CodeLLDB: Extensions, search "CodeLLDB". The root launch configs use it.
