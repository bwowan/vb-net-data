# Debugging Guide for NetData Project

## Common Issues and Solutions

### Issue: Cannot start debugging net_listener

#### Possible Causes:

1. **Missing CodeLLDB Extension**
   - Install the "CodeLLDB" extension in VS Code
   - Or use the native lldb debugger if available

2. **Permission Issues (CAP_NET_RAW required)**
   - `net_listener` requires CAP_NET_RAW capability to capture packets
   - Try running with sudo:
     ```bash
     sudo ./target/debug/net_listener
     ```
   - Or set capabilities:
     ```bash
     sudo setcap cap_net_raw,cap_net_admin=eip target/debug/net_listener
     ```

3. **Workspace Configuration**
   - Make sure you're in the workspace root directory
   - The `cwd` should be set to `${workspaceFolder}`

4. **Binary Not Built**
   - Build the project first:
     ```bash
     cargo build --bin net_listener
     ```
   - Or use the "Debug executable 'net_listener' (built binary)" configuration

### How to Debug:

1. **Using VS Code Debugger:**
   - Press F5 or go to Run and Debug
   - Select "Debug executable 'net_listener'"
   - Set breakpoints in the code
   - The debugger should attach and stop at breakpoints

2. **Using Command Line:**
   ```bash
   # Build with debug symbols
   cargo build --bin net_listener
   
   # Run with lldb
   lldb target/debug/net_listener
   (lldb) breakpoint set -f main.rs -l 33
   (lldb) run
   ```

3. **If Permission Issues:**
   ```bash
   # Option 1: Run with sudo (not recommended for debugging)
   sudo lldb target/debug/net_listener
   
   # Option 2: Set capabilities (recommended)
   sudo setcap cap_net_raw,cap_net_admin=eip target/debug/net_listener
   ./target/debug/net_listener
   ```

### Troubleshooting:

- **Linker Error: `cannot find -lpcap: No such file or directory`**
  
  This means the libpcap development package is not installed. Install it:
  
  **Ubuntu/Debian:**
  ```bash
  sudo apt-get install libpcap-dev
  ```
  
  **Fedora/RHEL/CentOS:**
  ```bash
  sudo dnf install libpcap-devel
  ```
  
  **Arch Linux:**
  ```bash
  sudo pacman -S libpcap
  ```
  
  After installation, rebuild the project:
  ```bash
  cargo clean
  cargo build --bin net_listener
  ```

- **Check if lldb is installed:**
  ```bash
  which lldb
  ```

- **Check if CodeLLDB extension is installed in VS Code**
  - Go to Extensions (Ctrl+Shift+X)
  - Search for "CodeLLDB"
  - Install if not present

- **Verify Cargo.toml workspace configuration:**
  - Make sure `net_listener` is listed in workspace members
  - Check that the package name matches

- **Check build output:**
  ```bash
  cargo build --bin net_listener --verbose
  ```

- **Verify libpcap installation:**
  ```bash
  # Check if libpcap-dev is installed (Ubuntu/Debian)
  dpkg -l | grep libpcap-dev
  
  # Check if library is available
  ldconfig -p | grep pcap
  
  # Check pkg-config
  pkg-config --modversion libpcap
  ```
