# tcp-stack · Isolated Setup on Windows

> A complete, fully isolated development environment using Docker Desktop + WSL2 — with every command explained so you understand what it does and why.

**Tags:** Docker · Rust 1.78+ · Windows · WSL2 · TUN/TAP

---

## 0 · Isolation Strategy

This project needs `CAP_NET_ADMIN` (root-level network privileges) to create a TUN virtual network interface. On Windows, the recommended approach is Docker Desktop with WSL2 as the backend. The Linux container runs inside WSL2, so TUN/TAP access works the same as on a native Linux host.

| Method | Isolation | TUN/TAP support | Overhead | Verdict |
|---|---|---|---|---|
| Run on host (WSL2 directly) | ❌ None | ✓ Yes | ✓ Zero | ❌ Contaminates WSL2 env |
| Hyper-V VM | ✓ Full | ✓ Yes | ❌ High (GBs of RAM) | Overkill |
| Network namespace only | ~ Partial | ✓ Yes | ✓ Near zero | No filesystem isolation |
| **Docker Desktop + WSL2 + NET_ADMIN** | ✓ Strong | ✓ Yes (with --device) | ✓ Low | ✓ **Recommended** |

> **Concept — What CAP_NET_ADMIN is**
> Linux uses "capabilities" instead of all-or-nothing root. `CAP_NET_ADMIN` is the specific capability that lets a process create network interfaces, set IP addresses, and manage routes — exactly what your TUN stack needs. Docker lets you grant this one capability to a container without giving it full root on the host.
> You'll also need `/dev/net/tun` — the Linux character device that backs TUN/TAP interfaces. We pass it into the container explicitly with `--device`.

---

## 01 · Prerequisites — WSL2 + Docker Desktop

### Enable WSL2

Open **PowerShell as Administrator** and run:

```powershell
# Enable WSL and Virtual Machine Platform features
wsl --install

# After reboot, set WSL2 as the default version
wsl --set-default-version 2

# Install Ubuntu (if not already installed)
wsl --install -d Ubuntu
```

Restart your machine when prompted.

### Install Docker Desktop

1. Download Docker Desktop from [https://www.docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop)
2. Run the installer. Make sure **"Use WSL2 instead of Hyper-V"** is checked.
3. After installation, open Docker Desktop → **Settings → Resources → WSL Integration** and enable integration for your Ubuntu distro.

### Verify Docker is working

Open a **WSL2 Ubuntu terminal** (or Windows Terminal with Ubuntu profile) and run:

```bash
docker run --rm hello-world
# Should print: Hello from Docker!
```

> ⚠ **If you get "permission denied"**: Run `sudo usermod -aG docker $USER` inside WSL2, then close and reopen the terminal.

---

## 02 · Create the Dockerfile

This defines the isolated build environment — Rust + all the network tools the project needs.

Open your **WSL2 Ubuntu terminal** and create the project folder:

```bash
# Run inside WSL2 Ubuntu terminal
mkdir ~/tcp-stack && cd ~/tcp-stack
```

> **Tip:** Your Windows files are accessible from WSL2 at `/mnt/c/Users/<YourName>/`. You can also access your WSL2 home from Windows Explorer at `\\wsl$\Ubuntu\home\<username>\`.

Create the `Dockerfile` (use VS Code, neovim, or any editor):

**`~/tcp-stack/Dockerfile`**

```dockerfile
# ── Base image ───────────────────────────────────────────────────────────────
# We use debian:bookworm-slim (small ~30MB base).
# Slim = fewer pre-installed packages = smaller attack surface = faster builds.
FROM debian:bookworm-slim

# ── System dependencies ───────────────────────────────────────────────────────
# Explanation of each package:
#   build-essential  → gcc, make, linker — Rust's proc-macro crates need a C linker
#   pkg-config       → helps Rust find system libraries
#   iproute2         → the 'ip' command (ip link, ip addr, ip route)
#   tcpdump          → CLI packet capture — you'll use this constantly to debug
#   netcat-openbsd   → 'nc' for raw TCP/UDP testing
#   curl             → to send HTTP requests to your stack
#   iperf3           → bandwidth benchmarking (Week 12)
#   git              → clone packetdrill and other tools
#   wget ca-certificates → fetch rustup installer securely
#   iputils-ping     → ping command
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    iproute2 \
    tcpdump \
    netcat-openbsd \
    curl \
    iperf3 \
    git \
    wget \
    ca-certificates \
    iputils-ping \
    wireshark-common \
    tshark \
    strace \
    linux-perf \
    bison \
    flex \
    && rm -rf /var/lib/apt/lists/*

# ── Install Rust via rustup ───────────────────────────────────────────────────
# We install Rust INSIDE the container so it's completely isolated.
# -y = non-interactive, --no-modify-path = don't touch shell configs
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --no-modify-path

# Add cargo/rustup to PATH for all subsequent RUN commands and at runtime
ENV PATH="/root/.cargo/bin:${PATH}"

# ── Verify Rust installed correctly ──────────────────────────────────────────
RUN rustc --version && cargo --version

# ── Install packetdrill (Google's TCP test tool) ──────────────────────────────
# packetdrill lets you write scripted packet-level TCP tests (used in Week 11).
# It needs to be built from source.
RUN git clone --depth=1 https://github.com/google/packetdrill /tmp/packetdrill \
    && cd /tmp/packetdrill/gtests/net/packetdrill \
    && ./configure \
    && make -j$(nproc) \
    && mv packetdrill /usr/local/bin/ \
    && rm -rf /tmp/packetdrill

# ── Working directory ─────────────────────────────────────────────────────────
# /workspace is where we'll mount your project from the host
WORKDIR /workspace

# ── Default command ───────────────────────────────────────────────────────────
# Drop into bash when you 'docker run' without a command
CMD ["/bin/bash"]
```

**Why build packetdrill from source?**
packetdrill is Google's tool for writing TCP-level test scripts — you describe a precise sequence of packets and ACKs and it verifies your stack behaves correctly. It's not in Debian's apt repos, so source build is the only option. `--depth=1` does a shallow clone (just the latest commit) — much faster.

**Why `rm -rf /var/lib/apt/lists/*` after apt-get?**
Docker builds images in layers. After `apt-get install`, the package index cache is no longer needed and can be tens of megabytes. Deleting it in the same RUN command (not a separate layer) keeps your image smaller.

---

## 03 · Build the Docker Image

This is a one-time build. Takes ~5–10 min while it downloads and compiles Rust.

Run from inside your **WSL2 terminal** in `~/tcp-stack/`:

```bash
# -t tcp-stack-env  = tag (name) the image "tcp-stack-env"
# .                 = build context is the current directory (where Dockerfile is)
docker build -t tcp-stack-env .

# Confirm the image exists
docker images tcp-stack-env
```

> **What is a "build context"?**
> The `.` tells Docker to send the current directory's contents to the Docker daemon. Any `COPY` or `ADD` instructions refer to files relative to this context. Always run from your project folder.

> **Why does Rust take so long to install?**
> rustup downloads the Rust toolchain (rustc compiler, cargo, std library) plus metadata — ~300MB+. This only happens once. Docker caches each layer, so rebuilding won't reinstall Rust as long as you haven't changed the lines above it.

---

## 04 · Run the Container (with TUN access)

The magic flags that give your container the network capabilities it needs.

Run this from your **WSL2 Ubuntu terminal**:

```bash
docker run -it \
  --cap-add=NET_ADMIN \            # allow creating TUN interfaces, setting IP routes
  --device=/dev/net/tun \          # pass the TUN char device into the container
  --name tcp-stack-dev \            # give container a stable name
  -v "$HOME/tcp-stack:/workspace" \ # mount your project folder as /workspace (live sync)
  --rm \                             # delete container on exit (keeps things clean)
  tcp-stack-env
```

**What each flag does:**

- **`-it`**: Interactive + pseudo-TTY. Without this, stdin is disconnected and you can't type commands.
- **`--cap-add=NET_ADMIN`**: Grants the Linux `CAP_NET_ADMIN` capability. The exact minimum needed — not full root. Without this, `ioctl(TUNSETIFF)` will fail with `EPERM`.
- **`--device=/dev/net/tun`**: Passes the TUN kernel device into the container's filesystem. Without this, `open("/dev/net/tun")` returns `ENOENT`.
- **`-v "$HOME/tcp-stack:/workspace"`**: Bind-mount. Your WSL2 `~/tcp-stack/` directory is the same as `/workspace` inside the container. Edit files with VS Code on Windows, compile inside the container — no file copying needed.

> ⚠ **If you exit the container and want to re-enter:** Because we used `--rm`, the container is deleted on exit. Just run the same `docker run` command again — your code is safe in `~/tcp-stack/`. For a persistent container, remove `--rm` and use `docker start -ai tcp-stack-dev` to reconnect.

**Optional — save as a helper script:**

```bash
# Save this to ~/tcp-stack/dev.sh and chmod +x it
cat > ~/tcp-stack/dev.sh <<'EOF'
#!/bin/bash
docker run -it \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun \
  --name tcp-stack-dev \
  -v "$HOME/tcp-stack:/workspace" \
  --rm \
  tcp-stack-env
EOF
chmod +x ~/tcp-stack/dev.sh
# Now you can just run: ./dev.sh
```

> **VS Code tip:** Install the **Remote - WSL** extension and the **Dev Containers** extension. You can open `~/tcp-stack/` directly in VS Code from WSL2 with `code .`, and even attach VS Code to the running container for in-container editing.

---

## 05 · Initialise the Rust Project (inside container)

After entering the container via Step 4, run these inside it.

```bash
# You're now inside the container at /workspace
# Verify Rust is available
rustc --version    # should print: rustc 1.78+ (or newer)
cargo --version

# Initialise a new binary crate
cargo init --name tcp-stack

# Confirm the structure was created
ls -la
# You should see: Cargo.toml  src/

# Verify your WSL2 host also sees these files in ~/tcp-stack/
# (open another WSL2 terminal: ls ~/tcp-stack)
```

**Why `cargo init` instead of `cargo new`?**
`cargo new tcp-stack` creates a new subdirectory. `cargo init` initialises a Cargo project in the *current* directory. Since we're already in `/workspace` (which maps to our project root), `cargo init` is correct.

Now set up the initial dependencies in `Cargo.toml`:

**`/workspace/Cargo.toml` (initial version)**

```toml
[package]
name = "tcp-stack"
version = "0.1.0"
edition = "2021"

[dependencies]
# tun-tap: safe Rust wrapper around Linux's TUN/TAP ioctl interface
tun-tap = "0.1"

# etherparse: parse/build Ethernet, IP, TCP, ICMP headers without boilerplate
# Use it to VERIFY your hand-written parser, not as a crutch
etherparse = "0.14"

# tracing: structured async-friendly logging (better than println! for debugging)
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

# rand: random number generation (for ISN — use OsRng, not thread_rng)
rand = "0.8"

[profile.release]
opt-level = 3
debug = true    # keep debug symbols even in release (useful for perf/gdb)
```

```bash
# Inside container — do a first build to cache dependencies
cargo build
# This downloads and compiles all dependencies.
# Subsequent builds only recompile YOUR code — very fast.
```

---

## 06 · Verify TUN Device Access

Before writing any protocol code, confirm you can open and configure a TUN interface.

Replace the contents of `src/main.rs` with this smoke test (edit from VS Code on Windows or inside WSL2):

**`/workspace/src/main.rs` — TUN smoke test**

```rust
use tun_tap::{Iface, Mode};

fn main() -> std::io::Result<()> {
    // Open /dev/net/tun and create a TUN interface named "tun0"
    // Mode::Tun = IP packets (no Ethernet header)
    // Mode::Tap = Ethernet frames (includes MAC headers) — we want Tun for this project
    let iface = Iface::new("tun0", Mode::Tun)?;

    println!("✓ TUN interface created: {}", iface.name());
    println!("  Now run in another terminal:");
    println!("  ip addr add 192.168.0.1/24 dev {}", iface.name());
    println!("  ip link set {} up", iface.name());
    println!("  ping 192.168.0.2   # our stack's address");

    // Read packets in a loop — just print their length for now
    let mut buf = [0u8; 1504];
    loop {
        let n = iface.recv(&mut buf)?;
        println!("Received {} bytes: {:02x?}", n, &buf[..n.min(20)]);
    }
}
```

**Inside container — Terminal 1:**

```bash
cargo build
# Give the binary CAP_NET_ADMIN so it can open /dev/net/tun without sudo at runtime
sudo setcap cap_net_admin=eip target/debug/tcp-stack
./target/debug/tcp-stack
# Should print: ✓ TUN interface created: tun0
```

**Inside container — Terminal 2** (open with: `docker exec -it tcp-stack-dev bash`):

```bash
# Configure the host side of the TUN link
ip addr add 192.168.0.1/24 dev tun0
ip link set tun0 up

# Send a ping to 192.168.0.2 — your stack will receive it
ping -c 3 192.168.0.2
# Terminal 1 should print hex bytes of the ARP/ICMP packets!
```

> ✓ **Expected outcome:** Terminal 1 prints something like: `Received 28 bytes: [00 01 08 00 06 04 00 01 ...]`. Those are real ARP packets from the kernel's IP stack asking "who is 192.168.0.2?" — and your code is receiving them. This is Week 1's milestone.

**What is `setcap cap_net_admin=eip`?**
This sets a file capability on the binary so it can open TUN devices without being run as root. The three letters mean:
- **e** (effective) — the capability is active when the binary runs
- **i** (inheritable) — child processes may also have it
- **p** (permitted) — the binary is allowed to acquire it

Alternative: run with `sudo ./tcp-stack` — but using capabilities is the correct production approach.

**Why does ping send ARP first instead of ICMP?**
ARP (Address Resolution Protocol) is Layer 2 — it maps an IP address to a MAC address. Before the kernel can send an ICMP echo request to `192.168.0.2`, it needs to know the MAC address for that IP on the local subnet. Your stack needs to reply to this ARP before ping will work — that's exactly what Week 2 implements.

---

## 07 · Essential Tools Inside the Container

Commands you'll use constantly while debugging your stack.

**Packet capture — tcpdump:**

```bash
# Watch all traffic on your TUN interface in real time
tcpdump -i tun0 -n -v

# Capture to a file — open the .pcap in Wireshark on Windows
tcpdump -i tun0 -w /workspace/capture.pcap
# Then open in Wireshark on Windows:
# Navigate to \\wsl$\Ubuntu\home\<username>\tcp-stack\capture.pcap

# Filter by protocol
tcpdump -i tun0 -n 'arp'           # ARP only
tcpdump -i tun0 -n 'icmp'          # ping only
tcpdump -i tun0 -n 'tcp port 8080' # HTTP traffic
```

> **Wireshark on Windows:** Install [Wireshark for Windows](https://www.wireshark.org/download.html). Access your capture files via `\\wsl$\Ubuntu\home\<username>\tcp-stack\capture.pcap` in the file picker.

**Interface inspection:**

```bash
# See all interfaces and their IPs
ip addr show

# See routing table (useful to understand how packets reach your TUN)
ip route show

# See ARP cache (what MACs the kernel knows)
ip neigh show

# Simulate packet loss for congestion control testing (Week 8)
tc qdisc add dev tun0 root netem loss 10%    # 10% drop
tc qdisc del dev tun0 root                    # restore
```

**Testing your stack:**

```bash
# Week 2: ICMP
ping -c 5 192.168.0.2

# Week 5: TCP handshake
nc -v 192.168.0.2 8080       # netcat as TCP client

# Week 10: HTTP
curl -v http://192.168.0.2:8080/

# Week 12: throughput benchmark
iperf3 -c 192.168.0.2 -p 5001 -t 10

# strace — see every syscall your binary makes (great for debugging TUN fd)
strace -e trace=read,write,ioctl ./target/debug/tcp-stack 2>&1 | head -50
```

---

## 08 · Your Day-to-Day Workflow

How to iterate efficiently between Windows editor and container.

```
Windows Host / WSL2                    Docker Container (tcp-stack-dev)
─────────────────────────────────      ──────────────────────────────────────

~/tcp-stack/ (WSL2)       ←─bind─→    /workspace/
  src/main.rs               mount        src/main.rs   (same file, instantly)
  src/ethernet.rs                        src/ethernet.rs
  Cargo.toml                             Cargo.toml
  capture.pcap  ←────────────────────  tcpdump -w /workspace/capture.pcap

VS Code (Windows, Remote-WSL)          cargo build
(edit files here)                      ./target/debug/tcp-stack
                                       tcpdump / ping / curl

Wireshark (Windows)                    tshark / ip / strace
(open \\wsl$\Ubuntu\...\capture.pcap)
```

**Open a second terminal into running container:**

```bash
# While your stack is running in terminal 1, open a second shell in the SAME container
docker exec -it tcp-stack-dev bash

# From here you can run ping, tcpdump, ip commands, etc.
# Both terminals share the same network namespace — so the TUN interface
# created by your Rust binary is visible here too
```

**Enable verbose logging in your stack:**

```bash
# Set log level via environment variable (once you add tracing to your code)
RUST_LOG=trace ./target/debug/tcp-stack   # maximum detail
RUST_LOG=debug ./target/debug/tcp-stack   # medium detail
RUST_LOG=info  ./target/debug/tcp-stack   # normal

# Filter to just TCP-related logs
RUST_LOG=tcp_stack::tcp=trace ./target/debug/tcp-stack
```

---

## Setup Checklist

- [ ] WSL2 installed and Ubuntu distro running
- [ ] Docker Desktop installed with WSL2 backend enabled
- [ ] Docker Desktop WSL Integration enabled for your Ubuntu distro
- [ ] Docker works inside WSL2 (`docker run hello-world` succeeds)
- [ ] `~/tcp-stack/Dockerfile` created inside WSL2
- [ ] `docker build -t tcp-stack-env .` completed successfully
- [ ] `./dev.sh` drops you into container shell
- [ ] `cargo init --name tcp-stack` run inside container
- [ ] `cargo build` succeeds with no errors
- [ ] TUN smoke test: binary starts and prints "✓ TUN interface created: tun0"
- [ ] `ping 192.168.0.2` from second terminal causes bytes to appear in first terminal
- [ ] You understand what each `docker run` flag does

---

## Common Errors and Fixes

- **"Cannot connect to the Docker daemon"** → Make sure Docker Desktop is running (check the system tray icon). Inside WSL2, Docker Desktop manages the daemon automatically.
- **"open /dev/net/tun: no such file or directory"** → You forgot `--device=/dev/net/tun` in the docker run command.
- **"ioctl TUNSETIFF: operation not permitted"** → You forgot `--cap-add=NET_ADMIN`. Both flags are required.
- **"setcap: command not found"** → `sudo apt install libcap2-bin` inside the container.
- **Ping sends ARP but gets no reply** → Expected at Week 1 — your stack isn't responding yet. You'll implement the ARP handler in Week 2.
- **Docker Desktop won't start / WSL2 backend error** → Open PowerShell as Admin and run `wsl --update`, then restart Docker Desktop.
- **Files not syncing between Windows and WSL2** → Always keep your project in `~/` inside WSL2 (e.g. `~/tcp-stack/`), not in `/mnt/c/...`. Bind mounts to Windows NTFS paths have significant I/O overhead and can cause `cargo build` to be very slow.

---

## Summary

You now have a fully isolated Rust development environment on Windows via Docker Desktop + WSL2. The container has `CAP_NET_ADMIN` and access to `/dev/net/tun`, but nothing else from your host is exposed. Your source code lives in WSL2 and is instantly visible inside the container via a bind mount. You can edit files in VS Code on Windows (using the Remote-WSL extension), compile inside the container, and inspect captures in Wireshark on Windows. Start Week 1 of the curriculum: open `src/main.rs` in VS Code, and run `cargo build` inside the container.
