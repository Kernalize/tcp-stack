# Doc 1 — TUN Device + Reading Your First Raw Network Packet

> **The big picture:** You are building a TCP/IP network stack from scratch in Rust — in userspace. No kernel modules. No magic libraries doing the work. By the end of 12 weeks, running `curl http://192.168.0.2:8080/` will get a response served entirely by code you wrote, from raw bytes up. Doc 1 is where it starts: opening a virtual network interface and reading the raw bytes of real network packets.

---

## How to Use This Guide

This guide is structured as a **learning loop**:

```
LEARN a concept (read and understand)
  ↓
VERIFY you understood it (answer the question / inspect the thing)
  ↓
DO the task (run the command / write the code)
  ↓
CHECK it worked (see the expected output)
  ↓
repeat
```

Do not skip ahead. If a section says "make sure you see X before continuing", do not continue until you see X. The whole point of Doc 1 is to build a solid mental model of what is happening at the byte level. Every week after this depends on that model.

**Time estimate:** 2–4 hours for a first-timer.

---

## Part 1 — The Mental Model: What Are We Actually Doing?

Before you write a single line of code, you need to understand the fundamental mechanism you are working with. Spend 10 minutes here. It will save you hours of confusion later.

### 1.1 — How Network Stacks Normally Work

When you type `curl https://example.com` on a normal Linux machine, the following happens:

```
Your app (curl)
    ↓  write("GET / HTTP/1.1...")
Linux kernel socket layer
    ↓  TCP layer adds headers
Linux kernel IP layer
    ↓  IP layer adds headers
Linux kernel ethernet/NIC driver
    ↓  Physical bytes sent
Your network card (hardware)
    ↓
The internet
```

The kernel handles everything from the TCP layer downward. Your app just calls `write()` on a socket file descriptor and the kernel does the rest. You never see the raw bytes.

### 1.2 — What This Project Does Instead

This project intercepts packets **before the kernel processes them** using a mechanism called a **TUN device**. When the kernel would normally hand a packet to a NIC driver, it instead hands it to a file descriptor that your Rust process reads:

```
Your Rust process (tcp-stack)
    ↓  reads raw IP packets from fd
/dev/net/tun  ← the interception point
    ↓
Linux kernel routing
    ↓
Network
```

**What this means in practice:** When something on your machine sends a packet to IP address `192.168.0.2`, the Linux kernel says "that's the TUN interface's address" and delivers the packet bytes directly to your Rust code's `read()` call. Your code is the first thing that sees those bytes. There is no TCP stack, no IP stack, no ARP. Just a buffer full of bytes and you.

### 1.3 — TUN vs TAP: What is the Difference?

There are two types of virtual interfaces:

**TUN (Network TUNnel) — Layer 3 device**
- Delivers raw **IP packets** to your process
- The bytes you receive start directly with the IP header
- First 4 bits of first byte = `4` (for IPv4) or `6` (for IPv6)
- Does NOT include Ethernet headers (no MAC addresses)

**TAP (Network TAP) — Layer 2 device**
- Delivers raw **Ethernet frames** to your process
- The bytes you receive start with the Ethernet header (6-byte dest MAC, 6-byte src MAC, 2-byte EtherType)
- The actual IP packet comes AFTER the 14-byte Ethernet header
- You can see ARP packets (which are Layer 2)

**The project uses TAP** (look at `Cargo.toml` — `tun-tap = "0.1"` supports both Layer-2 TAP and Layer-3 TUN). However, the current `main.rs` uses `Mode::Tun` for simplicity. **Doc 1 uses Tun.** Later you will switch to Tap to implement ARP.

**Quick memory aid:**
- TUN → Tunnel → IP packets (no Ethernet)
- TAP → wiretap → Ethernet frames (full Layer 2)

### 1.4 — Verify You Understood Section 1

Before moving on, make sure you can answer these without looking:

1. When your Rust code is running, what happens when another process pings `192.168.0.2`?
2. With `Mode::Tun`, what is the first byte you receive? What does it tell you?
3. Why does this project need a TUN/TAP device instead of just using regular sockets?

**Answers:**
1. The kernel routes the ping's IP packet to the TUN interface, which delivers it to your `iface.recv()` call
2. The first byte has the IP version (top 4 bits = `0x4` for IPv4) and the IP Header Length (bottom 4 bits)
3. We want to implement TCP/IP ourselves. A regular socket is above the TCP/IP layer — we'd be on top of the kernel's TCP, not writing our own.

---

## Part 2 — Environment Setup

You have two options. Use Docker unless you have a strong reason not to — the `Dockerfile` in the repo is already configured with everything you need.

### 2.1 — Option A: Docker (Recommended)

**Why Docker:** The `Dockerfile` pre-installs Rust, `iproute2`, `tcpdump`, `packetdrill`, and everything else you need. It also avoids any conflict with your Kali system's Rust version or packages.

**Step 1: Make sure Docker is installed**

```bash
docker --version
```

Expected output: `Docker version 24.x.x` or similar. If Docker is not installed:

```bash
sudo apt-get install -y docker.io
sudo systemctl start docker
sudo systemctl enable docker
# Add yourself to the docker group so you don't need sudo
sudo usermod -aG docker $USER
# Log out and back in for the group change to take effect
```

**Step 2: Navigate to your repo**

```bash
cd ~/tcp-stack   # or wherever you cloned it
ls
```

You should see: `Cargo.lock  Cargo.toml  Dockerfile  LICENSE  README.md  src/  docs/  scripts/  ...`

**Step 3: Build the Docker image**

```bash
docker build -t tcp-stack-env .
```

This will take 3–8 minutes the first time (it downloads and compiles the Rust toolchain). You will see a lot of output ending with something like:

```
Successfully built abc123def456
Successfully tagged tcp-stack-env:latest
```

**If the build fails** with a network error (can't download packages), check your internet connection. If it fails at the `rustup` step, try again — it is sometimes flaky.

**Step 4: Run the container**

```bash
docker run -it \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun:/dev/net/tun \
  -v "$(pwd):/workspace" \
  --name tcp-stack-dev \
  tcp-stack-env
```

**What these flags mean (important — understand each one):**

- `--cap-add=NET_ADMIN` — Grants the container permission to create network interfaces. Without this, `Iface::new("tun0", Mode::Tun)` will fail with "Operation not permitted". The `CAP_NET_ADMIN` Linux capability is required for any process that creates TUN/TAP devices.
- `--device=/dev/net/tun:/dev/net/tun` — Makes the host's `/dev/net/tun` device file visible inside the container. Without this, the container has no TUN device to open.
- `-v "$(pwd):/workspace"` — Mounts your current directory (the repo) into `/workspace` inside the container. Changes you make on the host appear inside the container and vice versa.
- `--name tcp-stack-dev` — Names the container so you can attach to it from another terminal easily.
- `-it` — Interactive + TTY: keeps stdin open and allocates a pseudo-terminal so you get a shell prompt.

**You should now be inside the container with a shell prompt like:**

```
root@a1b2c3d4e5f6:/workspace#
```

**Step 5: Open a second terminal tab for the same container**

You will need two terminals simultaneously — one to run your stack, one to send test packets. Open a new terminal tab/window on your host and run:

```bash
docker exec -it tcp-stack-dev bash
```

This gives you a second shell inside the same running container. Keep both terminal windows open side by side.

---

### 2.2 — Option B: Kali Linux Directly (No Docker)

Use this if you cannot use Docker or prefer to work directly on the system.

**Step 1: Install Rust**

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

When the installer asks, choose option `1` (default installation). After it finishes:

```bash
source "$HOME/.cargo/env"
```

Verify:

```bash
rustc --version
cargo --version
```

Expected: `rustc 1.78.0` or newer, `cargo 1.78.0` or newer.

**Step 2: Install system tools**

```bash
sudo apt-get update
sudo apt-get install -y \
  iproute2 \
  tcpdump \
  netcat-openbsd \
  curl \
  iputils-ping \
  wireshark-common \
  tshark
```

**Step 3: Verify TUN support**

```bash
ls -la /dev/net/tun
```

Expected: `crw-rw-rw- 1 root root 10, 200 ... /dev/net/tun`

If you get "No such file or directory":

```bash
sudo modprobe tun
ls -la /dev/net/tun
```

**Step 4: Navigate to the repo**

```bash
cd ~/tcp-stack
ls
```

---

## Part 3 — Understanding the Project Files

Before writing any code, read through the key files to understand what you have.

### 3.1 — Read `Cargo.toml`

```bash
cat Cargo.toml
```

You will see:

```toml
[package]
name = "tcp-stack"
version = "0.1.0"
edition = "2021"

[dependencies]
tun-tap = "0.1"
etherparse = "0.14"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
rand = "0.8"
```

**What each dependency does:**

- `tun-tap = "0.1"` — A Rust crate that wraps the Linux TUN/TAP `ioctl` calls. Instead of writing raw unsafe C-style `ioctl` calls, you call `Iface::new("tun0", Mode::Tun)`. This is the only Linux-specific dependency.

- `etherparse = "0.14"` — A zero-copy Ethernet/IP/TCP/UDP header parser. **You will NOT use this to do the parsing work for you.** You will write your own parsers. You CAN use it to verify your parsers are correct by comparing output. Think of it as a "reference answer" tool.

- `tracing` + `tracing-subscriber` — Structured logging. Better than `println!` for a network stack because you can attach metadata (connection id, packet direction, sequence number) to each log line and filter them.

- `rand = "0.8"` — Random number generation. Needed in Week 5 for generating cryptographically random Initial Sequence Numbers (ISNs) for TCP connections.

### 3.2 — Read `src/main.rs` Carefully

```bash
cat src/main.rs
```

```rust
use tun_tap::{Iface, Mode};

fn main() -> std::io::Result<()> {
    let iface = Iface::new("tun0", Mode::Tun)?;

    println!("✓ TUN interface created: {}", iface.name());
    println!("  Now run in another terminal:");
    println!("  ip addr add 192.168.0.1/24 dev {}", iface.name());
    println!("  ip link set {} up", iface.name());
    println!("  ping 192.168.0.2   # our stack's address");

    let mut buf = [0u8; 1504];
    loop {
        let n = iface.recv(&mut buf)?;
        println!("Received {} bytes: {:02x?}", n, &buf[..n.min(20)]);
    }
}
```

**Deep dive — every single line:**

---

**`use tun_tap::{Iface, Mode};`**

Brings `Iface` (the interface handle struct) and `Mode` (the enum `Mode::Tun` or `Mode::Tap`) into scope from the `tun-tap` crate.

---

**`fn main() -> std::io::Result<()>`**

`main` returns a `Result`. In Rust, this means if something goes wrong (file not found, permission denied, etc.), the error propagates up and gets printed as "Error: ..." to stderr when the program exits. Without this return type, you would have to manually `unwrap()` or `match` every fallible call.

---

**`let iface = Iface::new("tun0", Mode::Tun)?;`**

This is where the magic happens. Under the hood, `Iface::new` does:

1. Opens the file `/dev/net/tun` — this is a special kernel device file that lets you create virtual network interfaces
2. Calls `ioctl(fd, TUNSETIFF, &ifr)` where `ifr` is a struct with the interface name `"tun0"` and flags `IFF_TUN | IFF_NO_PI`
   - `IFF_TUN` — creates a TUN (Layer 3) device, not TAP
   - `IFF_NO_PI` — don't prepend a 4-byte "packet info" header to each packet. Without this flag, each packet would start with `[flags: u16][proto: u16]` before the actual IP bytes. You don't want that.
3. Returns an `Iface` struct wrapping the open file descriptor

The `?` at the end means: if this returns `Err(...)`, immediately exit `main` with that error. This is equivalent to:

```rust
let iface = match Iface::new("tun0", Mode::Tun) {
    Ok(iface) => iface,
    Err(e) => return Err(e),
};
```

**Common failure:** If you see `Error: Os { code: 1, kind: PermissionDenied, message: "Operation not permitted" }`, you don't have `CAP_NET_ADMIN`. Run `sudo setcap cap_net_admin=eip target/debug/tcp-stack` or run the binary with `sudo`.

---

**`let mut buf = [0u8; 1504];`**

Allocates a fixed 1504-byte array on the stack, initialized to zero. `[0u8; 1504]` means "array of 1504 `u8` values, all zero".

Why 1504? Ethernet MTU (Maximum Transmission Unit) is 1500 bytes. The extra 4 bytes are headroom for the `struct tun_pi` packet info header (even though we disabled it with `IFF_NO_PI` — it's defensive sizing).

`mut` because `iface.recv(&mut buf)` writes into this buffer and Rust requires mutability to allow that.

---

**`loop { ... }`**

An infinite loop. A network stack runs forever — it should never stop reading packets unless the process is killed or an unrecoverable error occurs.

---

**`let n = iface.recv(&mut buf)?;`**

**This is a blocking call.** The OS suspends your thread here until a packet arrives. When a packet arrives:

1. The kernel writes the raw bytes into `buf`
2. `recv` returns `Ok(n)` where `n` is the number of bytes written

`n` is critical — the buffer is 1504 bytes, but the packet might only be 84 bytes (a ping). Only `buf[0..n]` contains valid packet data. `buf[n..1504]` contains whatever was there before (zeroes on first call, old packet data on subsequent calls).

---

**`println!("Received {} bytes: {:02x?}", n, &buf[..n.min(20)]);`**

- `n` — total bytes received
- `&buf[..n.min(20)]` — a slice of at most the first 20 bytes. `n.min(20)` is safe even if `n < 20` (e.g., for a malformed tiny packet)
- `{:02x?}` — Rust's `Debug` format for a byte slice in hex. `02x` means each byte is printed as exactly 2 lowercase hex digits with a leading zero if needed

Example output: `Received 84 bytes: [45, 00, 00, 54, 00, 01, 40, 00, 40, 01, ...]`

---

### 3.3 — Quick Look at the Dockerfile

```bash
head -40 Dockerfile
```

The Dockerfile sets up a Debian-based image with: gcc/make (for Rust's proc-macro compilation), Rust via rustup, iproute2, tcpdump, netcat, curl, iperf3, and packetdrill. It is the exact environment you need.

---

## Part 4 — Build and First Run

### 4.1 — Build the Project

Inside your Docker container (or on Kali directly):

```bash
cd /workspace
cargo build
```

`cargo build` compiles a **debug build** (fast to compile, slow to run, includes debug symbols). For a network stack, debug builds are fine during development — you want the debug symbols.

Expected output (first build, takes 30–60 seconds while downloading crates):

```
   Compiling proc-macro2 v1.0.x
   Compiling unicode-ident v1.0.x
   ...
   Compiling tun-tap v0.1.x
   Compiling tcp-stack v0.1.0 (/workspace)
    Finished dev [unoptimized + debuginfo] target(s) in 45.23s
```

If you see errors, they will be in red with the file and line number. Read the error message carefully — Rust's error messages are very detailed and usually tell you exactly what is wrong.

**Common build error:**

```
error[E0432]: unresolved import `tun_tap`
```

This means the `tun-tap` crate is not in `Cargo.toml`. Check `cat Cargo.toml` and make sure `tun-tap = "0.1"` is listed under `[dependencies]`.

### 4.2 — Grant Capability (if not using sudo)

After building, grant the binary permission to create TUN devices without needing `sudo`:

```bash
sudo setcap cap_net_admin=eip target/debug/tcp-stack
```

**Breaking down this command:**
- `setcap` — set Linux file capabilities
- `cap_net_admin` — the specific capability needed to create network interfaces
- `=eip` — grant this capability in all three modes: effective (e), inheritable (i), permitted (p)
- `target/debug/tcp-stack` — the binary you just built

**Important:** You must re-run this command every time you `cargo build`, because building creates a new binary file and capabilities are not preserved across file replacements.

Alternatively, run with `sudo`:

```bash
sudo ./target/debug/tcp-stack
```

### 4.3 — Run the Binary

```bash
./target/debug/tcp-stack
```

Expected output:

```
✓ TUN interface created: tun0
  Now run in another terminal:
  ip addr add 192.168.0.1/24 dev tun0
  ip link set tun0 up
  ping 192.168.0.2   # our stack's address
```

The program is now **blocked** on `iface.recv()`, waiting for packets. It will appear to hang — that is correct. Leave it running.

**If you see:** `Error: Os { code: 1, kind: PermissionDenied, ... }`
→ You need `sudo` or `setcap`. See 4.2 above.

**If you see:** `Error: Os { code: 16, kind: ResourceBusy, ... }`
→ An interface named `tun0` already exists. Run `sudo ip link delete tun0` and try again.

**If you see:** `Error: Os { code: 2, kind: NotFound, ... }`
→ `/dev/net/tun` doesn't exist. Run `sudo modprobe tun`.

### 4.4 — Configure the TUN Interface

**Switch to your second terminal** (the one connected to the same container).

The TUN interface `tun0` exists now, but it has no IP address and is not "up". You need to configure it:

```bash
# Step 1: Assign an IP to the HOST side of the TUN link
# 192.168.0.1 = host's end
# /24 = this is a /24 subnet (192.168.0.0 to 192.168.0.255)
sudo ip addr add 192.168.0.1/24 dev tun0

# Step 2: Bring the interface up (set it to "active" state)
sudo ip link set tun0 up
```

**Verify the interface is configured correctly:**

```bash
ip addr show tun0
```

Expected output:

```
5: tun0: <POINTOPOINT,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 500
    link/none
    inet 192.168.0.1/24 scope global tun0
       valid_lft forever preferred_lft forever
```

Key things to verify:
- `UP` appears in the angle brackets `<...>`
- `inet 192.168.0.1/24` appears — this is the IP you assigned
- `mtu 1500` — the maximum packet size

**Also verify the route was added:**

```bash
ip route show | grep 192.168
```

Expected: `192.168.0.0/24 dev tun0 proto kernel scope link src 192.168.0.1`

This means: "packets to anything in the 192.168.0.0/24 subnet should go through tun0". Since `192.168.0.2` is in this subnet, any packet to `192.168.0.2` will be delivered to your Rust process.

### 4.5 — Send Your First Packet

Still in the second terminal:

```bash
ping -c 3 192.168.0.2
```

The `-c 3` flag sends exactly 3 pings and stops (without it, ping runs forever).

**In your first terminal (where the stack is running)**, you should see:

```
Received 84 bytes: [45, 00, 00, 54, ab, cd, 40, 00, 40, 01, ...]
Received 84 bytes: [45, 00, 00, 54, ab, ce, 40, 00, 40, 01, ...]
Received 84 bytes: [45, 00, 00, 54, ab, cf, 40, 00, 40, 01, ...]
```

**In your second terminal**, `ping` will report:

```
PING 192.168.0.2 (192.168.0.2) 56(84) bytes of data.
--- 192.168.0.2 ping statistics ---
3 packets transmitted, 0 received, 100% packet loss, time 2002ms
```

100% packet loss is **correct and expected**. Your stack receives the ping packets but does not respond to them yet. The ping tool sees no reply, so it reports 100% loss. Implementing ICMP echo reply is Week 2.

**✅ Checkpoint: If you see bytes appearing in Terminal 1 when you ping from Terminal 2, the core mechanism works. You are receiving real network packets in your Rust code.**

### 4.6 — Observe with tcpdump in a Third Terminal

Open another terminal to the container:

```bash
docker exec -it tcp-stack-dev bash
```

Run tcpdump:

```bash
sudo tcpdump -i tun0 -n -v
```

Then in your second terminal, run another ping:

```bash
ping -c 1 192.168.0.2
```

You will see tcpdump output like:

```
11:23:45.123456 IP 192.168.0.1 > 192.168.0.2: ICMP echo request, id 1234, seq 1, length 64
```

Notice: tcpdump sees only the ICMP **request**. There is no reply. When you implement ICMP echo reply in Week 2, you will see both:

```
11:23:45.123456 IP 192.168.0.1 > 192.168.0.2: ICMP echo request, ...
11:23:45.123460 IP 192.168.0.2 > 192.168.0.1: ICMP echo reply, ...
```

Cross-reference the hex bytes in Terminal 1 with tcpdump's decoded output. tcpdump is telling you exactly what those bytes mean. This is an essential debugging skill you will use every single day.

---

## Part 5 — Understanding the Raw Bytes: The IP Header

Now that you can receive bytes, you need to learn to read them. This section teaches you the IPv4 header format so that when you see `[45, 00, 00, 54, ...]`, you can decode it in your head.

### 5.1 — IPv4 Header Layout

The IPv4 header is defined in RFC 791. It is a minimum of 20 bytes. Here is the layout:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├───────────────────────────────────────────────────────────────────┤
│ Ver=4 │  IHL  │    DSCP     │ECN│         Total Length            │
├───────┴───────┴─────────────┴───┴─────────────────────────────────┤
│           Identification              │Flags │  Fragment Offset    │
├───────────────────────────────────────┴──────┴────────────────────┤
│      TTL      │   Protocol  │            Header Checksum          │
├───────────────┴─────────────┴────────────────────────────────────┤
│                        Source IP Address                           │
├───────────────────────────────────────────────────────────────────┤
│                     Destination IP Address                         │
├───────────────────────────────────────────────────────────────────┤
│               Options (if IHL > 5) ...                            │
└───────────────────────────────────────────────────────────────────┘
```

### 5.2 — Every Field, Byte by Byte

Here is exactly which bytes correspond to which fields:

| Bytes | Field | How to read it |
|---|---|---|
| `buf[0]` | Version + IHL | Top 4 bits = version, bottom 4 bits = IHL (header length in 32-bit words) |
| `buf[1]` | DSCP + ECN | Ignore for now |
| `buf[2..4]` | Total Length | `u16::from_be_bytes([buf[2], buf[3]])` — total packet size in bytes |
| `buf[4..6]` | Identification | Fragment group ID — needed for reassembly (Week 3) |
| `buf[6..8]` | Flags + Fragment Offset | Top 3 bits = flags, remaining 13 bits = offset |
| `buf[8]` | TTL | Time To Live — starts at 64 or 128, decremented at each router hop |
| `buf[9]` | Protocol | `1` = ICMP, `6` = TCP, `17` = UDP |
| `buf[10..12]` | Header Checksum | One's complement checksum of the header |
| `buf[12..16]` | Source IP | `[buf[12], buf[13], buf[14], buf[15]]` — the sender's IP |
| `buf[16..20]` | Destination IP | `[buf[16], buf[17], buf[18], buf[19]]` — your IP (`192.168.0.2`) |

**The critical ones for today:** `buf[0]`, `buf[9]`, `buf[12..16]`, `buf[16..20]`.

### 5.3 — Decode a Real Packet

When you ran ping, you saw output like:

```
Received 84 bytes: [45, 00, 00, 54, ab, cd, 40, 00, 40, 01, e2, 3f, c0, a8, 00, 01, c0, a8, 00, 02]
```

Let's decode this together, byte by byte:

```
buf[0]  = 0x45
  → top 4 bits:    0x4 = 4  ← IP version 4 (IPv4)
  → bottom 4 bits: 0x5 = 5  ← IHL = 5 words = 5 × 4 = 20 bytes (no options)

buf[1]  = 0x00  → DSCP=0, ECN=0 (best effort, no congestion notification)

buf[2]  = 0x00
buf[3]  = 0x54  → Total Length = 0x0054 = 84 bytes (the whole packet)

buf[4]  = 0xab
buf[5]  = 0xcd  → Identification = 0xabcd = 43981 (fragment group ID)

buf[6]  = 0x40
buf[7]  = 0x00  → Flags = 0b010 (DF=1 Don't Fragment), Fragment Offset = 0

buf[8]  = 0x40  → TTL = 64 (default for Linux hosts)

buf[9]  = 0x01  → Protocol = 1 = ICMP ← this is a ping packet

buf[10] = 0xe2
buf[11] = 0x3f  → Header Checksum = 0xe23f

buf[12] = 0xc0
buf[13] = 0xa8
buf[14] = 0x00
buf[15] = 0x01  → Source IP = 192.168.0.1 ← who sent the ping

buf[16] = 0xc0
buf[17] = 0xa8
buf[18] = 0x00
buf[19] = 0x02  → Destination IP = 192.168.0.2 ← your stack's address
```

Notice: `0xc0.0xa8.0x00.0x01` = `192.168.0.1` because:
- `0xc0` = 192
- `0xa8` = 168
- `0x00` = 0
- `0x01` = 1

### 5.4 — Endianness: Why `from_be_bytes`?

Network protocols use **big-endian** byte order (also called "network byte order"). In big-endian, the **most significant byte comes first**.

Example: The number 1500 in decimal = `0x05DC` in hex.
- Big-endian (network order): `[0x05, 0xDC]` ← what you see in packets
- Little-endian (x86/ARM native): `[0xDC, 0x05]` ← what your CPU uses internally

Your x86 or ARM CPU is little-endian. If you just cast bytes to integers without byte-swapping, you will get the wrong value.

**Always use `u16::from_be_bytes([a, b])` or `u32::from_be_bytes([a, b, c, d])` when reading multi-byte fields from network packets.** Never use `from_ne_bytes` (native endian) for network data.

Example — reading the Total Length field:

```rust
// WRONG — gives garbage on x86/ARM
let total_len = u16::from_ne_bytes([buf[2], buf[3]]);

// RIGHT — correctly interprets network byte order
let total_len = u16::from_be_bytes([buf[2], buf[3]]);
```

This is one of the most common bugs beginners write. Remember it.

### 5.5 — What About IHL?

`IHL` (Internet Header Length) tells you how many **32-bit words** the IP header occupies.

```rust
let ihl = (buf[0] & 0x0f) as usize;  // bottom 4 bits
let header_bytes = ihl * 4;           // convert words to bytes
```

- Minimum IHL = 5 → 20 bytes (no IP options — most common)
- Maximum IHL = 15 → 60 bytes (with options)

**Why does this matter?** The TCP/UDP/ICMP payload starts at `buf[header_bytes]`, NOT always at `buf[20]`. If a packet has IP options (IHL > 5), `buf[20]` is still in the IP header. Always use `ihl * 4` to find where the next layer starts.

---

## Part 6 — Your Doc 1 Coding Tasks

Now that you understand the packet format, you will extend `main.rs` to be genuinely useful. You will do this in three stages, each building on the previous.

### Task 1 — Print Decoded Packet Info (Replace Hex Dump)

**Goal:** Instead of `Received 84 bytes: [45, 00, 00, 54, ...]`, print human-readable information: protocol, source IP, destination IP.

**Open `src/main.rs` in your editor:**

```bash
# If inside Docker container, you can edit on your host machine in the mounted volume
# or use nano/vim inside the container:
nano src/main.rs
```

**Replace the entire file with this:**

```rust
use tun_tap::{Iface, Mode};

fn main() -> std::io::Result<()> {
    let iface = Iface::new("tun0", Mode::Tun)?;

    println!("✓ TUN interface created: {}", iface.name());
    println!("→ In another terminal, run:");
    println!("    sudo ip addr add 192.168.0.1/24 dev {}", iface.name());
    println!("    sudo ip link set {} up", iface.name());
    println!("    ping 192.168.0.2");
    println!("─────────────────────────────────────────");

    let mut buf = [0u8; 1504];
    let mut packet_count = 0u64;

    loop {
        // blocks here until a packet arrives
        let n = iface.recv(&mut buf)?;
        packet_count += 1;

        // Safety check: IP header is at least 20 bytes
        if n < 20 {
            println!("[#{:04}] Packet too short to be IPv4: {} bytes — skipping", packet_count, n);
            continue;
        }

        // --- Parse IP version ---
        // The top 4 bits of byte 0 are the IP version
        let version = buf[0] >> 4;

        if version != 4 {
            println!("[#{:04}] Not IPv4 (version={}), {} bytes — skipping", packet_count, version, n);
            continue;
        }

        // --- Parse IP Header Length ---
        // Bottom 4 bits of byte 0 = IHL (in 32-bit words)
        let ihl = (buf[0] & 0x0f) as usize;
        let header_len = ihl * 4;

        if n < header_len {
            println!("[#{:04}] Packet smaller than declared header length — skipping", packet_count);
            continue;
        }

        // --- Parse Total Length ---
        let total_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;

        // --- Parse TTL ---
        let ttl = buf[8];

        // --- Parse Protocol ---
        let protocol = buf[9];
        let protocol_name = match protocol {
            1  => "ICMP",
            6  => "TCP",
            17 => "UDP",
            _  => "unknown",
        };

        // --- Parse Source IP ---
        // Bytes 12-15 are the 4 octets of the source IPv4 address
        let src_ip = format!("{}.{}.{}.{}", buf[12], buf[13], buf[14], buf[15]);

        // --- Parse Destination IP ---
        // Bytes 16-19 are the 4 octets of the destination IPv4 address
        let dst_ip = format!("{}.{}.{}.{}", buf[16], buf[17], buf[18], buf[19]);

        println!(
            "[#{:04}] IPv4  {} → {}  proto={} ({})  total={}B  ttl={}  ihl={}B",
            packet_count, src_ip, dst_ip, protocol, protocol_name, total_len, ttl, header_len
        );
    }
}
```

**Save and rebuild:**

```bash
cargo build 2>&1
sudo setcap cap_net_admin=eip target/debug/tcp-stack
```

**Watch for build errors.** If you see any, read them carefully. Common issues:
- Missing semicolons → `error: expected `;``
- Wrong type → Rust will tell you exactly what type was expected vs what was given
- Unused variable warning → not an error, but note `let packet_count = 0u64` needs `mut`

**Run it:**

```bash
./target/debug/tcp-stack
```

**In Terminal 2, ping again:**

```bash
ping -c 5 192.168.0.2
```

**Expected output in Terminal 1:**

```
✓ TUN interface created: tun0
→ In another terminal, run:
    sudo ip addr add 192.168.0.1/24 dev tun0
    sudo ip link set tun0 up
    ping 192.168.0.2
─────────────────────────────────────────
[#0001] IPv4  192.168.0.1 → 192.168.0.2  proto=1 (ICMP)  total=84B  ttl=64  ihl=20B
[#0002] IPv4  192.168.0.1 → 192.168.0.2  proto=1 (ICMP)  total=84B  ttl=64  ihl=20B
[#0003] IPv4  192.168.0.1 → 192.168.0.2  proto=1 (ICMP)  total=84B  ttl=64  ihl=20B
[#0004] IPv4  192.168.0.1 → 192.168.0.2  proto=1 (ICMP)  total=84B  ttl=64  ihl=20B
[#0005] IPv4  192.168.0.1 → 192.168.0.2  proto=1 (ICMP)  total=84B  ttl=64  ihl=20B
```

**✅ Checkpoint:** You are parsing a real IPv4 header and printing human-readable information from it.

---

### Task 2 — Decode ICMP Headers

**Goal:** When the protocol is ICMP, also decode the ICMP header to tell us the ICMP type and code.

**Background — The ICMP Header:**

ICMP sits inside the IP payload. After the IP header ends (at byte `ihl * 4`), the ICMP header begins:

```
[IP header: ihl*4 bytes]
[ICMP byte 0]: Type    (8 = Echo Request / ping, 0 = Echo Reply / pong)
[ICMP byte 1]: Code    (0 for Echo Request/Reply)
[ICMP byte 2]: Checksum high byte
[ICMP byte 3]: Checksum low byte
[ICMP byte 4]: Identifier high byte
[ICMP byte 5]: Identifier low byte
[ICMP byte 6]: Sequence Number high byte
[ICMP byte 7]: Sequence Number low byte
[ICMP bytes 8+]: Data payload (the ping payload — often a timestamp)
```

So if the IP header is 20 bytes, ICMP starts at `buf[20]`. If the IP header has options (rare), ICMP starts at `buf[ihl * 4]`.

**ICMP types you will encounter today:**
- Type 8, Code 0 = Echo Request (someone is pinging you)
- Type 0, Code 0 = Echo Reply (you will send these in Week 2)
- Type 3, Code X = Destination Unreachable (various sub-codes)
- Type 11, Code 0 = Time Exceeded (TTL ran out — what `traceroute` uses)

**Extend `src/main.rs` — replace the last `println!` in the loop with this:**

```rust
        println!(
            "[#{:04}] IPv4  {} → {}  proto={} ({})  total={}B  ttl={}",
            packet_count, src_ip, dst_ip, protocol, protocol_name, total_len, ttl
        );

        // --- Decode protocol-specific headers ---
        match protocol {
            1 => decode_icmp(&buf[header_len..n], packet_count),
            6 => decode_tcp(&buf[header_len..n], packet_count),
            _ => {}
        }
```

And add these functions **below `main`** (outside the `fn main` block):

```rust
fn decode_icmp(icmp_payload: &[u8], packet_num: u64) {
    // ICMP header is 8 bytes minimum
    if icmp_payload.len() < 8 {
        println!("         └── ICMP: too short ({} bytes)", icmp_payload.len());
        return;
    }

    let icmp_type = icmp_payload[0];
    let icmp_code = icmp_payload[1];
    let checksum  = u16::from_be_bytes([icmp_payload[2], icmp_payload[3]]);
    let identifier  = u16::from_be_bytes([icmp_payload[4], icmp_payload[5]]);
    let sequence_no = u16::from_be_bytes([icmp_payload[6], icmp_payload[7]]);

    let type_name = match (icmp_type, icmp_code) {
        (8, 0)  => "Echo Request (ping)",
        (0, 0)  => "Echo Reply (pong)",
        (3, 0)  => "Destination Net Unreachable",
        (3, 1)  => "Destination Host Unreachable",
        (3, 3)  => "Destination Port Unreachable",
        (3, 4)  => "Fragmentation Needed (PMTU)",
        (11, 0) => "Time Exceeded (TTL=0)",
        (11, 1) => "Fragment Reassembly Timeout",
        _       => "other",
    };

    println!(
        "         └── ICMP type={} code={} ({})  id={} seq={}  checksum=0x{:04x}",
        icmp_type, icmp_code, type_name, identifier, sequence_no, checksum
    );
}

fn decode_tcp(tcp_payload: &[u8], packet_num: u64) {
    // TCP header is 20 bytes minimum
    if tcp_payload.len() < 20 {
        println!("         └── TCP: too short ({} bytes)", tcp_payload.len());
        return;
    }

    let src_port = u16::from_be_bytes([tcp_payload[0], tcp_payload[1]]);
    let dst_port = u16::from_be_bytes([tcp_payload[2], tcp_payload[3]]);
    let seq_num  = u32::from_be_bytes([tcp_payload[4], tcp_payload[5], tcp_payload[6], tcp_payload[7]]);
    let ack_num  = u32::from_be_bytes([tcp_payload[8], tcp_payload[9], tcp_payload[10], tcp_payload[11]]);

    // Data offset: top 4 bits of byte 12 = header length in 32-bit words
    let data_offset = (tcp_payload[12] >> 4) as usize;
    let tcp_header_len = data_offset * 4;

    // Flags: byte 13
    let flags = tcp_payload[13];
    let flag_fin = (flags & 0x01) != 0;
    let flag_syn = (flags & 0x02) != 0;
    let flag_rst = (flags & 0x04) != 0;
    let flag_psh = (flags & 0x08) != 0;
    let flag_ack = (flags & 0x10) != 0;
    let flag_urg = (flags & 0x20) != 0;

    let window = u16::from_be_bytes([tcp_payload[14], tcp_payload[15]]);

    // Build a human-readable flags string
    let mut flag_str = String::new();
    if flag_syn { flag_str.push_str("SYN "); }
    if flag_ack { flag_str.push_str("ACK "); }
    if flag_fin { flag_str.push_str("FIN "); }
    if flag_rst { flag_str.push_str("RST "); }
    if flag_psh { flag_str.push_str("PSH "); }
    if flag_urg { flag_str.push_str("URG "); }
    let flag_str = flag_str.trim_end().to_string();

    println!(
        "         └── TCP  sport={} dport={}  seq={}  ack={}  flags=[{}]  win={}  hdr={}B",
        src_port, dst_port, seq_num, ack_num, flag_str, window, tcp_header_len
    );
}
```

**Important:** Make sure `decode_icmp` and `decode_tcp` are placed **outside** the `fn main() { ... }` block — they are separate functions, not inside the loop.

**Save, rebuild, and retest:**

```bash
cargo build 2>&1
sudo setcap cap_net_admin=eip target/debug/tcp-stack
./target/debug/tcp-stack
```

In Terminal 2:

```bash
ping -c 3 192.168.0.2
```

**Expected output:**

```
[#0001] IPv4  192.168.0.1 → 192.168.0.2  proto=1 (ICMP)  total=84B  ttl=64
         └── ICMP type=8 code=0 (Echo Request (ping))  id=1234 seq=1  checksum=0x3f2a
[#0002] IPv4  192.168.0.1 → 192.168.0.2  proto=1 (ICMP)  total=84B  ttl=64
         └── ICMP type=8 code=0 (Echo Request (ping))  id=1234 seq=2  checksum=0x3d2c
[#0003] IPv4  192.168.0.1 → 192.168.0.2  proto=1 (ICMP)  total=84B  ttl=64
         └── ICMP type=8 code=0 (Echo Request (ping))  id=1234 seq=3  checksum=0x3b2e
```

Notice: `seq=1`, `seq=2`, `seq=3` — the sequence number increments with each ping. The id stays the same (it is the ping process's PID or a random value — same process, same id). This is the ICMP sequence number — totally separate from TCP sequence numbers.

**Also test TCP visibility — try connecting to a port (it will fail, that's fine):**

```bash
# In Terminal 2 — attempt a TCP connection
nc -w 1 192.168.0.2 8080 2>/dev/null
```

**Expected output in Terminal 1:**

```
[#0001] IPv4  192.168.0.1 → 192.168.0.2  proto=6 (TCP)  total=60B  ttl=64
         └── TCP  sport=54321 dport=8080  seq=1234567890  ack=0  flags=[SYN]  win=65535  hdr=40B
```

You can see the TCP SYN packet — `nc` is trying to open a connection. `flags=[SYN]` means this is the first packet of a TCP three-way handshake. The connection times out because your stack doesn't respond. That is fine — TCP is Week 5.

**✅ Checkpoint:** You can decode ICMP and TCP headers from raw bytes.

---

### Task 3 — Verify Your Parser Against `etherparse`

The repo includes `etherparse` as a dependency. Use it to **verify your parsing is correct**.

This is a professional engineering habit: when you write a parser, verify it against a known-good reference. If they disagree, you have a bug to find.

**Add this to `src/main.rs` at the top:**

```rust
use tun_tap::{Iface, Mode};
use etherparse::Ipv4HeaderSlice;
```

**Add this after your manual parsing in the loop (inside the loop, after all your existing code):**

```rust
        // --- Cross-check with etherparse ---
        // Parse the same packet with etherparse and compare results
        match Ipv4HeaderSlice::from_slice(&buf[..n]) {
            Ok(parsed) => {
                let ep_src = format!("{}", parsed.source_addr());
                let ep_dst = format!("{}", parsed.destination_addr());
                let ep_proto = parsed.protocol().0;

                // Verify our manual parsing matches etherparse
                if ep_src != src_ip || ep_dst != dst_ip || ep_proto != protocol {
                    println!("⚠ PARSER MISMATCH! etherparse: {} → {}  proto={}", ep_src, ep_dst, ep_proto);
                    println!("  Our parser:      {} → {}  proto={}", src_ip, dst_ip, protocol);
                }
                // If they match, print nothing — silence means correctness
            }
            Err(e) => {
                // etherparse failed to parse — not necessarily our bug (could be IPv6 or truncated)
                // Only warn if we claimed it was valid IPv4
                println!("         (etherparse could not parse: {:?})", e);
            }
        }
```

**Rebuild and test:**

```bash
cargo build 2>&1
sudo setcap cap_net_admin=eip target/debug/tcp-stack
./target/debug/tcp-stack
```

Ping again. If you see no `⚠ PARSER MISMATCH` lines, your parser is producing the same results as `etherparse`. That is the confirmation you want.

If you DO see a mismatch, there is a bug in your manual parsing. Use the mismatch to find it. Common bugs:
- Wrong byte indices
- Using `from_ne_bytes` instead of `from_be_bytes`
- Off-by-one in the IHL calculation

---

## Part 7 — The Complete Final `src/main.rs`

Here is the complete `main.rs` for Doc 1, with all three tasks integrated and full comments:

```rust
use tun_tap::{Iface, Mode};
use etherparse::Ipv4HeaderSlice;

fn main() -> std::io::Result<()> {
    // Open /dev/net/tun and create a TUN interface named "tun0"
    // Mode::Tun = Layer 3 (raw IP packets, no Ethernet header)
    // Requires CAP_NET_ADMIN capability: sudo setcap cap_net_admin=eip ./target/debug/tcp-stack
    let iface = Iface::new("tun0", Mode::Tun)?;

    println!("✓ TUN interface created: {}", iface.name());
    println!("→ Run in another terminal:");
    println!("    sudo ip addr add 192.168.0.1/24 dev {}", iface.name());
    println!("    sudo ip link set {} up", iface.name());
    println!("    ping 192.168.0.2");
    println!("─────────────────────────────────────────────────────────────");

    // 1504 bytes = 1500 (Ethernet MTU) + 4 (safety margin)
    let mut buf = [0u8; 1504];
    let mut packet_count = 0u64;

    loop {
        // Blocking call: suspends here until a packet arrives
        // n = number of valid bytes written into buf
        let n = iface.recv(&mut buf)?;
        packet_count += 1;

        // --- Minimum length check ---
        // An IPv4 header is at least 20 bytes. Anything shorter is malformed.
        if n < 20 {
            println!("[#{:04}] Packet too short: {} bytes — discarding", packet_count, n);
            continue;
        }

        // --- Parse IP version ---
        // buf[0] encodes both version (top 4 bits) and IHL (bottom 4 bits)
        // bit shift right 4 gives us just the top 4 bits
        let version = buf[0] >> 4;

        if version != 4 {
            // This would be IPv6 (version=6) or something else — we only handle IPv4 today
            println!("[#{:04}] Non-IPv4 packet (version={}) — skipping", packet_count, version);
            continue;
        }

        // --- Parse IP Header Length (IHL) ---
        // Bottom 4 bits of buf[0] = IHL in 32-bit words
        // Bitwise AND with 0x0f (0b00001111) zeros out the top 4 bits
        let ihl = (buf[0] & 0x0f) as usize;
        let header_len = ihl * 4; // Convert 32-bit words to bytes

        if header_len < 20 || n < header_len {
            println!("[#{:04}] Invalid IHL: {} — discarding", packet_count, ihl);
            continue;
        }

        // --- Parse Total Length ---
        // 2-byte big-endian field at bytes 2–3
        let total_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;

        // --- Parse TTL ---
        // Single byte at offset 8
        let ttl = buf[8];

        // --- Parse Protocol ---
        // Single byte at offset 9: 1=ICMP, 6=TCP, 17=UDP
        let protocol = buf[9];
        let protocol_name = match protocol {
            1  => "ICMP",
            6  => "TCP",
            17 => "UDP",
            _  => "???",
        };

        // --- Parse Source IP Address ---
        // 4 bytes at offsets 12–15, format as dotted decimal
        let src_ip = format!("{}.{}.{}.{}", buf[12], buf[13], buf[14], buf[15]);

        // --- Parse Destination IP Address ---
        // 4 bytes at offsets 16–19
        let dst_ip = format!("{}.{}.{}.{}", buf[16], buf[17], buf[18], buf[19]);

        // --- Print the IP layer summary ---
        println!(
            "[#{:04}] IPv4  {} → {}  proto={} ({})  len={}B  ttl={}  hdr={}B",
            packet_count, src_ip, dst_ip, protocol, protocol_name, total_len, ttl, header_len
        );

        // --- Decode the upper-layer protocol ---
        // The payload for the upper layer starts at buf[header_len]
        let payload = &buf[header_len..n];

        match protocol {
            1  => decode_icmp(payload),
            6  => decode_tcp(payload),
            17 => decode_udp(payload),
            _  => {}
        }

        // --- Cross-check with etherparse (verification) ---
        match Ipv4HeaderSlice::from_slice(&buf[..n]) {
            Ok(parsed) => {
                let ep_src   = format!("{}", parsed.source_addr());
                let ep_dst   = format!("{}", parsed.destination_addr());
                let ep_proto = parsed.protocol().0;

                if ep_src != src_ip || ep_dst != dst_ip || ep_proto != protocol {
                    println!(
                        "         ⚠ MISMATCH: etherparse got {} → {}  proto={} but we got {} → {}  proto={}",
                        ep_src, ep_dst, ep_proto, src_ip, dst_ip, protocol
                    );
                }
            }
            Err(_) => {} // Not our problem if etherparse can't parse it
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ICMP Header Decoder
// ICMP sits directly after the IP header in the payload.
// RFC 792 defines the ICMP header format.
// ─────────────────────────────────────────────────────────────────────────────
fn decode_icmp(payload: &[u8]) {
    if payload.len() < 8 {
        println!("         └── ICMP: too short ({} bytes, need 8)", payload.len());
        return;
    }

    // ICMP header layout:
    // [0]: Type
    // [1]: Code
    // [2-3]: Checksum (one's complement of the ICMP header + data)
    // [4-5]: Identifier (for Echo: matches between request and reply)
    // [6-7]: Sequence Number (increments with each ping sent)
    let icmp_type  = payload[0];
    let icmp_code  = payload[1];
    let checksum   = u16::from_be_bytes([payload[2], payload[3]]);
    let identifier = u16::from_be_bytes([payload[4], payload[5]]);
    let sequence   = u16::from_be_bytes([payload[6], payload[7]]);

    let description = match (icmp_type, icmp_code) {
        (0,  0) => "Echo Reply",
        (3,  0) => "Destination Net Unreachable",
        (3,  1) => "Destination Host Unreachable",
        (3,  2) => "Destination Protocol Unreachable",
        (3,  3) => "Destination Port Unreachable",
        (3,  4) => "Fragmentation Needed (DF set)",
        (8,  0) => "Echo Request (ping)",
        (11, 0) => "Time Exceeded — TTL expired",
        (11, 1) => "Time Exceeded — Fragment reassembly timeout",
        _       => "other",
    };

    println!(
        "         └── ICMP  type={} code={}  ({})  id={} seq={}  checksum=0x{:04x}",
        icmp_type, icmp_code, description, identifier, sequence, checksum
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// TCP Header Decoder
// TCP sits directly after the IP header in the payload.
// RFC 793 defines the TCP header format.
// ─────────────────────────────────────────────────────────────────────────────
fn decode_tcp(payload: &[u8]) {
    if payload.len() < 20 {
        println!("         └── TCP: too short ({} bytes, need 20)", payload.len());
        return;
    }

    // TCP header layout (first 20 bytes, no options):
    // [0-1]:   Source Port
    // [2-3]:   Destination Port
    // [4-7]:   Sequence Number
    // [8-11]:  Acknowledgment Number
    // [12]:    Data Offset (top 4 bits) + Reserved (bottom 4 bits)
    // [13]:    Flags (CWR, ECE, URG, ACK, PSH, RST, SYN, FIN)
    // [14-15]: Window Size
    // [16-17]: Checksum
    // [18-19]: Urgent Pointer

    let src_port = u16::from_be_bytes([payload[0], payload[1]]);
    let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
    let seq_num  = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let ack_num  = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);

    // Data offset: top 4 bits of byte 12 = TCP header length in 32-bit words
    let data_offset    = (payload[12] >> 4) as usize;
    let tcp_header_len = data_offset * 4;

    // TCP flags are in byte 13, one flag per bit
    let flags   = payload[13];
    let flag_fin = (flags & 0x01) != 0;  // bit 0: FIN — no more data from sender
    let flag_syn = (flags & 0x02) != 0;  // bit 1: SYN — synchronize (handshake)
    let flag_rst = (flags & 0x04) != 0;  // bit 2: RST — reset the connection
    let flag_psh = (flags & 0x08) != 0;  // bit 3: PSH — push data to application
    let flag_ack = (flags & 0x10) != 0;  // bit 4: ACK — acknowledgment number valid
    let flag_urg = (flags & 0x20) != 0;  // bit 5: URG — urgent pointer valid
    // bits 6-7 are ECE and CWR (congestion control flags, ignored today)

    let window   = u16::from_be_bytes([payload[14], payload[15]]);
    let checksum = u16::from_be_bytes([payload[16], payload[17]]);

    // Build flags string
    let mut flag_str = String::new();
    if flag_syn { flag_str.push_str("SYN "); }
    if flag_ack { flag_str.push_str("ACK "); }
    if flag_fin { flag_str.push_str("FIN "); }
    if flag_rst { flag_str.push_str("RST "); }
    if flag_psh { flag_str.push_str("PSH "); }
    if flag_urg { flag_str.push_str("URG "); }
    let flag_str = if flag_str.is_empty() { "<no flags>".to_string() } else { flag_str.trim_end().to_string() };

    // How many bytes of actual data (not headers) are in this segment?
    let data_len = if payload.len() > tcp_header_len {
        payload.len() - tcp_header_len
    } else {
        0
    };

    println!(
        "         └── TCP  sport={} dport={}  seq={}  ack={}  flags=[{}]  win={}  data={}B  hdr={}B  checksum=0x{:04x}",
        src_port, dst_port, seq_num, ack_num, flag_str, window, data_len, tcp_header_len, checksum
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// UDP Header Decoder
// UDP sits directly after the IP header in the payload.
// RFC 768 defines the UDP header (it's only 8 bytes).
// ─────────────────────────────────────────────────────────────────────────────
fn decode_udp(payload: &[u8]) {
    if payload.len() < 8 {
        println!("         └── UDP: too short ({} bytes, need 8)", payload.len());
        return;
    }

    // UDP header is only 8 bytes:
    // [0-1]: Source Port
    // [2-3]: Destination Port
    // [4-5]: Length (header + data, in bytes)
    // [6-7]: Checksum
    let src_port = u16::from_be_bytes([payload[0], payload[1]]);
    let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
    let length   = u16::from_be_bytes([payload[4], payload[5]]);
    let checksum = u16::from_be_bytes([payload[6], payload[7]]);

    println!(
        "         └── UDP  sport={} dport={}  length={}B  checksum=0x{:04x}",
        src_port, dst_port, length, checksum
    );
}
```

**Final build:**

```bash
cargo build 2>&1
sudo setcap cap_net_admin=eip target/debug/tcp-stack
```

---

## Part 8 — Testing Everything

### 8.1 — Test ICMP (ping)

Terminal 1: run the stack
Terminal 2:

```bash
ping -c 5 192.168.0.2
```

Expected Terminal 1 output:

```
[#0001] IPv4  192.168.0.1 → 192.168.0.2  proto=1 (ICMP)  len=84B  ttl=64  hdr=20B
         └── ICMP  type=8 code=0  (Echo Request (ping))  id=5678 seq=1  checksum=0xa12b
[#0002] IPv4  192.168.0.1 → 192.168.0.2  proto=1 (ICMP)  len=84B  ttl=64  hdr=20B
         └── ICMP  type=8 code=0  (Echo Request (ping))  id=5678 seq=2  checksum=0xbf3c
...
```

Verify:
- [ ] `proto=1 (ICMP)` on every line
- [ ] `type=8 code=0 (Echo Request (ping))` — correct for an incoming ping
- [ ] `seq` increments from 1 to 5
- [ ] `id` is the same for all 5 packets
- [ ] No `⚠ MISMATCH` lines (your parser matches etherparse)

### 8.2 — Test TCP (nc / netcat)

In Terminal 2:

```bash
nc -w 2 192.168.0.2 80 2>/dev/null
```

`nc` tries to connect to port 80. It will fail (nothing listening) but you will see the SYN packet.

Expected Terminal 1 output:

```
[#0001] IPv4  192.168.0.1 → 192.168.0.2  proto=6 (TCP)  len=60B  ttl=64  hdr=20B
         └── TCP  sport=54321 dport=80  seq=3829164821  ack=0  flags=[SYN]  win=65535  data=0B  hdr=40B  checksum=0x1a2b
```

Verify:
- [ ] `proto=6 (TCP)` — correct
- [ ] `flags=[SYN]` — this is the first packet of a three-way handshake
- [ ] `dport=80` — nc is connecting to port 80
- [ ] `ack=0` — no ACK flag, so ack number is 0/irrelevant
- [ ] `data=0B` — SYN carries no data, just the header

Try port 8080 as well:

```bash
nc -w 2 192.168.0.2 8080 2>/dev/null
```

You will see another SYN, this time with `dport=8080`.

### 8.3 — Test UDP (DNS query)

Send a DNS query — DNS uses UDP:

```bash
# Ask a DNS server (we're faking the address — this goes through our TUN interface)
dig @192.168.0.2 google.com 2>/dev/null
```

Expected Terminal 1 output:

```
[#0001] IPv4  192.168.0.1 → 192.168.0.2  proto=17 (UDP)  len=49B  ttl=64  hdr=20B
         └── UDP  sport=54000 dport=53  length=29B  checksum=0x3a4b
```

Verify:
- [ ] `proto=17 (UDP)` — correct
- [ ] `dport=53` — DNS uses port 53

### 8.4 — Watch with tcpdump simultaneously

Keep your stack running (Terminal 1) and run:

```bash
# Terminal 3
sudo tcpdump -i tun0 -n -v
```

Send a ping from Terminal 2:

```bash
ping -c 1 192.168.0.2
```

Compare the output:

**tcpdump shows:**
```
12:34:56.789 IP (tos 0x0, ttl 64, id 1234, offset 0, flags [DF], proto ICMP (1), length 84)
    192.168.0.1 > 192.168.0.2: ICMP echo request, id 5678, seq 1, length 64
```

**Your stack shows:**
```
[#0001] IPv4  192.168.0.1 → 192.168.0.2  proto=1 (ICMP)  len=84B  ttl=64  hdr=20B
         └── ICMP  type=8 code=0  (Echo Request (ping))  id=5678 seq=1  checksum=0x...
```

They should contain the same information — same IPs, same TTL, same total length, same ICMP id and sequence. If they differ, there is a parsing bug to investigate.

---

## Part 9 — Understanding What You Built

Take a step back and appreciate what just happened.

**You wrote code that reads raw IP packets from the kernel.** Not socket data. Not HTTP requests. Raw IP packets — the same bytes that travel over actual network cables. You decoded the binary layout of the IPv4, ICMP, TCP, and UDP protocol headers by hand, without using any parsing library to do the work.

This is the foundation of everything that follows:

| Week | What you will build | What today enables |
|------|--------------------|--------------------|
| Week 2 | ARP + ICMP echo reply | You already know the ICMP header format |
| Week 3 | Full IP layer (fragmentation) | You already parse the IP header |
| Week 4 | TCP header parsing + state machine | You already parse TCP headers |
| Week 5 | TCP handshake | Builds on the TCP parsing you have |
| ... | ... | ... |

---

## Part 10 — Doc 1 Final Checklist

Go through each item. Do not mark it done until you have actually seen the expected output.

**Environment:**
- [ ] Docker container running with `--cap-add=NET_ADMIN` and `--device=/dev/net/tun`
- [ ] `cargo build` completes with no errors
- [ ] `setcap` applied to the binary (or using `sudo`)

**Basic operation:**
- [ ] `./target/debug/tcp-stack` starts and prints the "run in another terminal" message
- [ ] `ip addr show tun0` shows `UP` and `inet 192.168.0.1/24`
- [ ] `ping -c 3 192.168.0.2` from Terminal 2 causes output in Terminal 1

**Parser verification:**
- [ ] Output shows source IP `192.168.0.1` and destination IP `192.168.0.2` correctly
- [ ] Output shows `proto=1 (ICMP)` for ping packets
- [ ] ICMP decode shows `type=8 code=0 (Echo Request)` and incrementing `seq` number
- [ ] TCP SYN from `nc` shows `flags=[SYN]` and `dport=<your target port>`
- [ ] No `⚠ MISMATCH` lines appear (your parser matches etherparse)
- [ ] `tcpdump -i tun0` shows the same IPs and values as your parser

---

## Part 11 — Where to Go After Doc 1

### What to Read Tonight (Optional)

**RFC 791, Section 3.1 only** — the IP header format in the official specification. It is a 2-page section with a diagram. The goal is not to memorize it — you already know the layout — but to see how the official spec is structured. You will read many RFCs over the next 12 weeks. Get comfortable with how they are formatted.

Link: https://www.rfc-editor.org/rfc/rfc791#section-3.1

**RFC 792, pages 1–4** — the ICMP specification. Read the Echo Request/Reply section. You will implement this in 2 days (Week 2).

Link: https://www.rfc-editor.org/rfc/rfc792

### What is Coming on Doc 2

On Doc 2 you will:
1. Clean up `main.rs` — move the parsing into a proper struct `Ipv4Packet`
2. Understand what Ethernet frames look like (you will need this for ARP)
3. Start reading RFC 826 (ARP) — just the first 3 pages

### What is Coming on Docs 3–7 (Week 1 completion)

- Build a proper `EthernetFrame::from_bytes()` parser (you will switch to `Mode::Tap`)
- Understand MAC addresses and EtherType
- Handle ARP requests (Week 2 prerequisite)
- Build a clean packet dispatch loop: `read → parse ethernet → parse IP → dispatch to handler`

---

## Appendix A — Command Quick Reference

### Container management

```bash
# Start the container (first time)
docker run -it --cap-add=NET_ADMIN --device=/dev/net/tun:/dev/net/tun \
    -v "$(pwd):/workspace" --name tcp-stack-dev tcp-stack-env

# Attach another terminal to running container
docker exec -it tcp-stack-dev bash

# Stop and remove container when done for the day
docker stop tcp-stack-dev && docker rm tcp-stack-dev

# Restart existing stopped container
docker start tcp-stack-dev && docker exec -it tcp-stack-dev bash
```

### Build and run cycle (every time you change code)

```bash
# Inside container:
cargo build 2>&1                                         # compile
sudo setcap cap_net_admin=eip target/debug/tcp-stack     # grant capability
./target/debug/tcp-stack                                 # run
```

### TUN interface setup (every time you start the stack)

```bash
# Run these AFTER the stack creates tun0 (from a second terminal):
sudo ip addr add 192.168.0.1/24 dev tun0
sudo ip link set tun0 up

# Verify:
ip addr show tun0

# Tear down if something is broken:
sudo ip link delete tun0
```

### Test packets

```bash
ping -c 5 192.168.0.2                   # ICMP Echo Request
nc -w 2 192.168.0.2 8080                # TCP SYN to port 8080
nc -w 2 -u 192.168.0.2 53              # UDP to port 53
dig @192.168.0.2 example.com           # DNS (UDP port 53)
curl --connect-timeout 2 192.168.0.2   # HTTP (TCP port 80)
```

### Packet capture

```bash
sudo tcpdump -i tun0 -n              # all packets, IP addresses as numbers
sudo tcpdump -i tun0 -n -v           # verbose: decode headers
sudo tcpdump -i tun0 -n -X           # hex + ASCII dump of payload
sudo tcpdump -i tun0 -n icmp         # ICMP only
sudo tcpdump -i tun0 -n tcp          # TCP only
sudo tcpdump -i tun0 -n 'tcp port 8080'  # TCP port 8080 only
```

---

## Appendix B — IP Header Field Reference Card

```
buf[0]     = [version:4bits | IHL:4bits]
               version = buf[0] >> 4           (should be 4 for IPv4)
               IHL     = buf[0] & 0x0f         (header length in 32-bit words)
               header_bytes = IHL * 4          (convert to bytes, min=20)

buf[1]     = DSCP (top 6 bits) + ECN (bottom 2 bits)
               ignore for now

buf[2..4]  = Total Length (big-endian u16)
               u16::from_be_bytes([buf[2], buf[3]])

buf[4..6]  = Identification (big-endian u16)
               u16::from_be_bytes([buf[4], buf[5]])
               (used for fragment reassembly — Week 3)

buf[6..8]  = Flags (top 3 bits) + Fragment Offset (bottom 13 bits)
               DF flag  = (buf[6] >> 6) & 1    (Don't Fragment)
               MF flag  = (buf[6] >> 5) & 1    (More Fragments)
               offset   = u16::from_be_bytes([buf[6] & 0x1f, buf[7]]) * 8

buf[8]     = TTL (Time To Live)
               decremented by each router; if it reaches 0, packet is dropped

buf[9]     = Protocol
               1  = ICMP
               6  = TCP
               17 = UDP

buf[10..12]= Header Checksum (big-endian u16)
               one's complement checksum of the IP header only

buf[12..16]= Source IP Address (4 bytes)
               format!("{}.{}.{}.{}", buf[12], buf[13], buf[14], buf[15])

buf[16..20]= Destination IP Address (4 bytes)
               format!("{}.{}.{}.{}", buf[16], buf[17], buf[18], buf[19])

buf[20..]  = IP Options (if IHL > 5, rare) or Payload (ICMP/TCP/UDP header)
               payload starts at buf[IHL * 4]
```

---

## Appendix C — ICMP Header Reference Card

```
Starts at buf[IHL * 4] in the IP packet.

icmp[0]    = Type
               0  = Echo Reply
               8  = Echo Request (incoming ping)
               3  = Destination Unreachable (see code)
               11 = Time Exceeded

icmp[1]    = Code
               Meaning depends on Type.
               For Echo Request/Reply: always 0
               For Dest Unreachable: 0=net, 1=host, 3=port, 4=fragmentation needed

icmp[2..4] = Checksum (big-endian u16)
               one's complement of ICMP header + data

icmp[4..6] = Identifier (big-endian u16)
               for Echo: matches request to reply (usually PID of ping process)

icmp[6..8] = Sequence Number (big-endian u16)
               increments with each ping sent

icmp[8..]  = Data payload
               for Echo: usually timestamp + padding bytes
```

---

## Appendix D — TCP Header Reference Card

```
Starts at buf[IHL * 4] in the IP packet.

tcp[0..2]  = Source Port (big-endian u16)
tcp[2..4]  = Destination Port (big-endian u16)
tcp[4..8]  = Sequence Number (big-endian u32)
tcp[8..12] = Acknowledgment Number (big-endian u32)
tcp[12]    = Data Offset (top 4 bits) + Reserved (bottom 4 bits)
               header_len = (tcp[12] >> 4) * 4   (in bytes)

tcp[13]    = Flags byte
               bit 0 (0x01): FIN — no more data from sender
               bit 1 (0x02): SYN — synchronize sequence numbers (handshake)
               bit 2 (0x04): RST — reset the connection
               bit 3 (0x08): PSH — push data to application immediately
               bit 4 (0x10): ACK — acknowledgment number is valid
               bit 5 (0x20): URG — urgent pointer is valid
               bit 6 (0x40): ECE — ECN-Echo
               bit 7 (0x80): CWR — Congestion Window Reduced

tcp[14..16]= Window Size (big-endian u16) — peer's receive buffer space
tcp[16..18]= Checksum (big-endian u16)
tcp[18..20]= Urgent Pointer (big-endian u16) — only used if URG flag set
tcp[20..]  = Options (if data offset > 5) or Data payload
```

---

*You now have a packet analyzer running on real network traffic. The bytes you are decoding are the same bytes that power every TCP connection, every ping, every HTTP request on the internet. Everything in the 12-week curriculum is an elaboration on what you did today.*