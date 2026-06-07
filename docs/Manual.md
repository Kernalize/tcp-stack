# 🌐 tcp-stack — A Userspace TCP/IP Stack from Scratch

> **Build a complete TCP/IP network stack in Rust — no kernel modules, no magic, just bytes, RFCs, and your brain.**  
> 12 weeks · 1–2 hours/day · Production-grade understanding of how the internet works.

[![Build](https://img.shields.io/github/actions/workflow/status/Mannava-Daasaradhi/tcp-stack/ci.yml?label=CI&style=flat-square)](https://github.com/Mannava-Daasaradhi/tcp-stack/actions)
[![Packetdrill](https://img.shields.io/badge/packetdrill-10%2F10%20passing-brightgreen?style=flat-square)](tests/packetdrill/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.78%2B-orange?style=flat-square)](https://rustup.rs)

---

## Table of Contents

1. [What This Is](#what-this-is)
2. [What You Will Build](#what-you-will-build)
3. [Architecture Overview](#architecture-overview)
4. [Prerequisites](#prerequisites)
5. [Quick Start](#quick-start)
6. [Project Structure](#project-structure)
7. [The 12-Week Curriculum](#the-12-week-curriculum)
   - [Phase 1 — Foundation (Weeks 1–2)](#phase-1--foundation-weeks-12)
   - [Phase 2 — IP Layer (Weeks 3–4)](#phase-2--ip-layer-weeks-34)
   - [Phase 3 — TCP Core (Weeks 5–8)](#phase-3--tcp-core-weeks-58)
   - [Phase 4 — Connection Lifecycle + API (Weeks 9–10)](#phase-4--connection-lifecycle--api-weeks-910)
   - [Phase 5 — Testing + Polish (Weeks 11–12)](#phase-5--testing--polish-weeks-1112)
8. [Core Concepts Deep Dive](#core-concepts-deep-dive)
   - [The Network Stack Model](#the-network-stack-model)
   - [TUN/TAP Devices](#tuntap-devices)
   - [Ethernet & ARP](#ethernet--arp)
   - [IP Layer](#ip-layer)
   - [TCP State Machine](#tcp-state-machine)
   - [Transmission Control Block (TCB)](#transmission-control-block-tcb)
   - [Reliable Delivery](#reliable-delivery)
   - [Flow Control](#flow-control)
   - [Congestion Control](#congestion-control)
9. [The Complete RFC Reading List](#the-complete-rfc-reading-list)
10. [Resource Library](#resource-library)
    - [Books](#books)
    - [Video Courses](#video-courses)
    - [Reference Implementations](#reference-implementations)
    - [Tools](#tools)
    - [Papers](#papers)
11. [Testing Guide](#testing-guide)
12. [Benchmarks](#benchmarks)
13. [Known Limitations](#known-limitations)
14. [FAQ](#faq)
15. [Glossary](#glossary)
16. [Contributing](#contributing)

---

## What This Is

This repo is both a **working userspace TCP/IP stack** and a **structured curriculum** for building one. It runs in userspace (no kernel changes needed), talks to the OS via a TUN virtual network interface, and implements every layer of the network stack from raw Ethernet frames up to a socket-like API that real applications can use.

This is not a tutorial wrapper around `libc`. Every protocol is parsed from raw bytes. Every checksum is computed by hand. Every timer is implemented explicitly. When you're done, you will understand — with no remaining mystery — exactly what happens when you type `curl https://example.com`.

**This is a systems programming project in the tradition of:**
- [Jon Gjengset's live-coded TCP in Rust](https://www.youtube.com/watch?v=bzja9fQWzdA)
- [saminiir's "Let's code a TCP/IP stack"](https://www.saminiir.com/lets-code-tcp-ip-stack-1-ethernet-arp/)
- [lwIP — the Lightweight IP stack](https://savannah.nongnu.org/projects/lwip/)
- [smoltcp — a pure-Rust embedded TCP/IP stack](https://github.com/smoltcp-rs/smoltcp)

---

## What You Will Build

By week 12 you will have a working implementation of:

| Component | Protocol | RFC |
|---|---|---|
| Virtual NIC | TUN/TAP device | Linux `if_tun.h` |
| Layer 2 | Ethernet frame parsing | RFC 894 |
| Layer 2 | ARP (Address Resolution Protocol) | RFC 826 |
| Layer 3 | IPv4 header parsing + routing | RFC 791 |
| Layer 3 | IP fragmentation + reassembly | RFC 791 §3.2 |
| Layer 3 | ICMP (ping, time exceeded) | RFC 792 |
| Layer 4 | TCP header parsing | RFC 793 |
| Layer 4 | TCP state machine (11 states) | RFC 793 |
| Layer 4 | Three-way handshake | RFC 793 §3.4 |
| Layer 4 | Reliable delivery (seq/ack/retransmit) | RFC 793, RFC 6298 |
| Layer 4 | Flow control (receive window) | RFC 793 §3.5 |
| Layer 4 | Flow control (window scaling) | RFC 1323 |
| Layer 4 | Congestion control (slow start, AIMD) | RFC 5681 |
| Layer 4 | Fast retransmit + fast recovery | RFC 5681 |
| Layer 4 | TCP teardown (FIN/RST/TIME_WAIT) | RFC 793, RFC 2018 |
| API | TcpListener + TcpStream | POSIX socket semantics |
| Application | Minimal HTTP/1.0 server | RFC 1945 |

**Final proof it works:** `curl http://192.168.0.2:8080/` returns a response served entirely by your code.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                     Your Application                     │
│              TcpListener / TcpStream API                 │
└────────────────────────┬────────────────────────────────┘
                         │ read() / write() / accept()
┌────────────────────────▼────────────────────────────────┐
│                    TCP Layer (Layer 4)                    │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────────┐ │
│  │  State   │ │ Send/Rcv │ │Congestion│ │Retransmit  │ │
│  │ Machine  │ │ Buffers  │ │ Control  │ │   Timer    │ │
│  └──────────┘ └──────────┘ └──────────┘ └────────────┘ │
│  Connection table: HashMap<(src_ip, src_port,           │
│                              dst_ip, dst_port), Tcb>    │
└────────────────────────┬────────────────────────────────┘
                         │ IP datagrams
┌────────────────────────▼────────────────────────────────┐
│                    IP Layer (Layer 3)                     │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │ Header parse │  │ Fragmentation│  │ ICMP handler  │  │
│  │ + checksum   │  │ reassembly   │  │ (ping replies)│  │
│  └──────────────┘  └──────────────┘  └───────────────┘  │
└────────────────────────┬────────────────────────────────┘
                         │ Ethernet frames
┌────────────────────────▼────────────────────────────────┐
│                  Ethernet Layer (Layer 2)                 │
│  ┌──────────────┐  ┌──────────────────────────────────┐ │
│  │ Frame parser │  │  ARP (IP ↔ MAC resolution cache) │ │
│  └──────────────┘  └──────────────────────────────────┘ │
└────────────────────────┬────────────────────────────────┘
                         │ raw bytes (read/write syscalls)
┌────────────────────────▼────────────────────────────────┐
│                TUN Virtual Network Interface              │
│             /dev/net/tun  (Linux kernel driver)          │
└────────────────────────┬────────────────────────────────┘
                         │
              ┌──────────▼──────────┐
              │   Linux IP stack    │  ← the real kernel
              │  (for everything    │     handles everything
              │   you DON'T handle) │     you don't intercept
              └─────────────────────┘
```

**Data flow for an incoming packet:**

```
Network → TUN fd → read() → Ethernet parser
       → EtherType dispatch
         → 0x0806 ARP → ARP handler → send ARP reply
         → 0x0800 IP  → IP parser + checksum verify
                      → Protocol dispatch
                        → proto=1 ICMP → ping reply
                        → proto=6 TCP  → TCB lookup/create
                                       → state machine
                                       → deliver to app
```

---

## Prerequisites

### Knowledge

You should be comfortable with:
- **Rust** at an intermediate level (ownership, lifetimes, `Result`/`Option`, traits, `async` basics). If you need a refresher: [The Rust Book](https://doc.rust-lang.org/book/) chapters 1–15.
- **C/systems basics**: file descriptors, `ioctl`, `read`/`write` syscalls, endianness (big-endian vs little-endian), bit manipulation.
- **Networking concepts** at a conceptual level (you don't need to know the byte layouts yet — that's what this project teaches): what an IP address is, what a port is, client vs server.

You do **not** need to know how TCP works internally. You'll learn that here.

### System Requirements

| Requirement | Minimum | Notes |
|---|---|---|
| OS | Linux (kernel 3.x+) | TUN/TAP is Linux-specific. WSL2 works with caveats (see FAQ). macOS requires `utun` — see [macOS](#macos) |
| Rust | 1.78+ | Install via [rustup.rs](https://rustup.rs) |
| Privileges | `sudo` or `CAP_NET_ADMIN` | Required for TUN device creation |
| RAM | 512MB | Comfortable with 4GB+ for running Wireshark alongside |

### Install system tools

```bash
# Ubuntu / Debian
sudo apt-get install -y \
  iproute2 \        # ip link, ip addr commands
  tcpdump \         # packet capture CLI
  wireshark \       # GUI packet analysis
  netcat-openbsd \  # nc for testing
  curl \            # HTTP testing
  iperf3 \          # throughput benchmarking
  linux-tools-generic  # perf profiling

# Also install packetdrill (TCP test tool by Google)
git clone https://github.com/google/packetdrill
cd packetdrill/gtests/net/packetdrill && ./configure && make && sudo make install
```

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/Mannava-Daasaradhi/tcp-stack
cd tcp-stack

# 2. Build
cargo build --release

# 3. Give binary permission to open TUN devices
sudo setcap cap_net_admin=eip target/release/tcp-stack

# 4. Run (opens /dev/net/tun, configures 192.168.0.2/24)
./target/release/tcp-stack

# 5. In another terminal — test it
ping 192.168.0.2            # should reply (ICMP, Week 2)
telnet 192.168.0.2 8080     # should connect (TCP, Week 5)
curl http://192.168.0.2:8080/ # full HTTP response (Week 10)
```

**Expected output from your stack:**

```
[tcp-stack] TUN device opened: tun0
[tcp-stack] Address configured: 192.168.0.2/24
[ethernet] ARP request from 192.168.0.1 — who has 192.168.0.2?
[arp]      Sending ARP reply: 192.168.0.2 is at de:ad:be:ef:00:01
[icmp]     Echo request from 192.168.0.1 id=1234 seq=1
[icmp]     Sending echo reply
[tcp]      SYN from 192.168.0.1:54321 → port 8080
[tcp]      SYN-ACK sent, state → SYN_RECEIVED
[tcp]      ACK received, state → ESTABLISHED
[http]     GET / HTTP/1.0
[http]     200 OK sent (6 bytes)
[tcp]      FIN from 192.168.0.1 → CLOSE_WAIT
[tcp]      FIN sent → LAST_ACK → CLOSED
```

---

## Project Structure

```
tcp-stack/
├── src/
│   ├── main.rs              # TUN setup, main event loop
│   ├── tun.rs               # TUN fd open + ioctl wrapper
│   │
│   ├── ethernet.rs          # EthernetFrame struct, EtherType enum
│   ├── arp.rs               # ARP packet parser, ARP cache
│   │
│   ├── ip.rs                # IPv4 header, checksum, fragmentation
│   ├── icmp.rs              # ICMP echo request/reply + time exceeded
│   │
│   └── tcp/
│       ├── mod.rs           # TCP segment parser, dispatcher
│       ├── tcb.rs           # Transmission Control Block
│       ├── state.rs         # TcpState enum + transitions
│       ├── send_buf.rs      # Send buffer (circular, tracks SND.UNA/NXT)
│       ├── recv_buf.rs      # Receive buffer (reorder queue)
│       ├── retransmit.rs    # RTO timer, Jacobson/Karels RTT estimation
│       ├── flow.rs          # Receive window management, zero-window probe
│       ├── congestion.rs    # Slow start, AIMD, fast retransmit/recovery
│       ├── teardown.rs      # FIN/RST handling, TIME_WAIT
│       └── api.rs           # TcpListener + TcpStream public API
│
├── examples/
│   └── http_server.rs       # Minimal HTTP/1.0 server using your API
│
├── tests/
│   └── packetdrill/         # .pkt test scripts
│       ├── handshake.pkt
│       ├── data_transfer.pkt
│       ├── retransmit.pkt
│       ├── fast_recovery.pkt
│       ├── zero_window.pkt
│       └── teardown.pkt
│
├── benches/
│   └── throughput.rs        # Criterion benchmarks
│
├── ARCHITECTURE.md          # Deeper design rationale
├── CONTRIBUTING.md
└── README.md                # ← you are here
```

---

## The 12-Week Curriculum

> **Daily commitment:** 1–2 hours. **Total:** ~100–150 hours to a working, tested, benchmarked TCP stack.  
> Each week has a concrete, verifiable milestone. Don't move on until yours passes.

---

### Phase 1 — Foundation (Weeks 1–2)

#### Week 1 — TUN Device + Ethernet Frame Parsing

**Goal:** Open a TUN virtual network interface and parse raw Ethernet frames byte by byte.

**Why it matters:** TUN is your portal into the Linux network stack. It gives your userspace process a virtual NIC — packets destined for your IP get delivered to your `read()` call instead of to a kernel driver. Understanding this removes the mystery of how userspace networking stacks (VPNs, WireGuard, smoltcp) work.

**Daily breakdown:**

| Days | Task |
|---|---|
| Day 1 | Install Rust via rustup. Read what a TUN device is: a virtual network interface that delivers raw IP packets to your process. |
| Day 2 | Open `/dev/net/tun` with `ioctl(IFF_TUN \| IFF_NO_PI)`. Configure your IP with `ip link` and `ip addr`. `read()` from the fd — you're receiving packets. |
| Day 3–4 | Parse Ethernet frames: 6-byte dest MAC, 6-byte src MAC, 2-byte EtherType (`0x0800`=IPv4, `0x0806`=ARP). Print every header in hex. |
| Day 5–7 | Build a clean abstraction: `EthernetFrame::from_bytes()`. Handle malformed frames gracefully. Log packet types. |

**Milestone:** `ping 192.168.0.2` from another terminal prints `ARP request from ...` in your binary's stdout. You are receiving real network traffic in your code.

**Code reference:**
```rust
let mut buf = [0u8; 1504];
let n = tun_fd.read(&mut buf)?;
let frame = EthernetFrame::from_bytes(&buf[..n])?;
println!("{:?}", frame.ethertype);
```

**Resources:**
- [Linux tun.h source — the ioctl flags you need](https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_tun.h)
- [saminiir.com — Let's code a TCP/IP stack, part 1 (C walkthrough)](https://www.saminiir.com/lets-code-tcp-ip-stack-1-ethernet-arp)
- [RFC 894 — IP over Ethernet](https://www.rfc-editor.org/rfc/rfc894)

---

#### Week 2 — ARP + ICMP Ping — Your First Working Protocol

**Goal:** Implement ARP so your stack can map IP addresses to MAC addresses, then implement ICMP echo reply so `ping` actually works.

**Why it matters:** ARP is the bridge between Layer 3 (IP) and Layer 2 (Ethernet). Without it, nobody can even send your stack a packet because they don't know your MAC address. ICMP ping is the simplest possible end-to-end test — and the first time it works, it feels genuinely magical.

**Daily breakdown:**

| Days | Task |
|---|---|
| Day 1–2 | Read RFC 826. Parse ARP: hardware type, protocol type, operation (request=1, reply=2), sender/target MAC+IP. Build ARP cache (`HashMap<Ipv4Addr, MacAddr>`). |
| Day 3–4 | When you receive an ARP request for your IP, craft and send an ARP reply. Populate your cache with the sender's mapping. |
| Day 5–6 | Parse ICMP: type (8=request, 0=reply), code, checksum, identifier, sequence. Verify the checksum (one's complement sum). |
| Day 7 | On ICMP echo request: swap src/dst, set type=0, recompute checksum, send. `ping` now works. |

**Milestone:** `ping 192.168.0.2` returns real replies from your userspace stack. Wireshark confirms your ARP and ICMP packets are well-formed.

**One's complement checksum — commit this to memory:**
```rust
fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = data.chunks(2)
        .map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]) as u32)
        .sum();
    while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16); }
    !(sum as u16)
}
```

This same checksum function is reused verbatim for IP headers and TCP pseudo-headers.

**Resources:**
- [RFC 826 — ARP specification](https://www.rfc-editor.org/rfc/rfc826)
- [RFC 792 — ICMP specification](https://www.rfc-editor.org/rfc/rfc792)
- [saminiir.com — part 1, ARP section](https://www.saminiir.com/lets-code-tcp-ip-stack-1-ethernet-arp)

---

### Phase 2 — IP Layer (Weeks 3–4)

#### Week 3 — IP Header Parsing + Fragmentation Reassembly

**Goal:** Implement the full IPv4 layer: header parsing, checksum validation, TTL handling, and fragment reassembly.

**Why it matters:** IP fragmentation is almost never taught but is critical for correctness. When a large packet (say, 4000 bytes) traverses a network with a 1500-byte MTU, it gets split into fragments. Your stack must buffer and reassemble them. If you skip this, large pings will silently fail.

**Daily breakdown:**

| Days | Task |
|---|---|
| Day 1–2 | Parse the IP header: version, IHL (header length in 32-bit words), DSCP, total length, identification, flags (DF, MF), fragment offset, TTL, protocol, checksum, src/dst IP. |
| Day 3 | Validate the IP checksum. Decrement TTL and drop packets with TTL=0 (send ICMP time exceeded). Dispatch to upper-layer handler by protocol field (1=ICMP, 6=TCP, 17=UDP). |
| Day 4–5 | Implement IP fragmentation reassembly: use a `HashMap` keyed by `(src_ip, dst_ip, identification, protocol)`. Buffer fragments until `MF=0` and all offsets are present. |
| Day 6–7 | Test fragmentation: `ping -s 4000 192.168.0.2`. Your stack must reassemble 3+ fragments correctly. Add a timeout to drop incomplete fragment sets. |

**Milestone:** `ping -s 4000 192.168.0.2` (4000-byte ping that forces fragmentation) returns correct replies.

**Fragment reassembly data structure:**
```rust
#[derive(Hash, Eq, PartialEq)]
struct FragKey { src: Ipv4Addr, dst: Ipv4Addr, id: u16, proto: u8 }

struct FragBuf {
    frags: BTreeMap<u16, Vec<u8>>,  // offset → data
    total: Option<usize>,            // known once MF=0 arrives
}
```

**Resources:**
- [RFC 791 — IP specification (the canonical reference)](https://www.rfc-editor.org/rfc/rfc791)
- [saminiir.com — Let's code a TCP/IP stack, part 2](https://www.saminiir.com/lets-code-tcp-ip-stack-2-ipv4-icmpv4)
- [Wireshark IP dissector documentation](https://wiki.wireshark.org/IP)

---

#### Week 4 — TCP Header Parsing + State Machine Skeleton

**Goal:** Read RFC 793 cover to cover. Implement TCP header parsing and the full state machine as an enum.

**Why it matters:** The structure you build this week is the scaffolding for Weeks 5–9. Getting it right now means you don't refactor under pressure later. The state machine is not complex to implement — it's complex to understand. Read the RFC. Seriously.

**The 11 TCP states you must implement:**

```
CLOSED → LISTEN → SYN_RECEIVED → ESTABLISHED ─┐
                                                │ (active open path)
CLOSED → SYN_SENT ──────────────────────────── ┘

ESTABLISHED → FIN_WAIT_1 → FIN_WAIT_2 → TIME_WAIT → CLOSED  (active close)
ESTABLISHED → CLOSE_WAIT → LAST_ACK → CLOSED                  (passive close)
FIN_WAIT_1 → CLOSING → TIME_WAIT → CLOSED                     (simultaneous close)
```

**Daily breakdown:**

| Days | Task |
|---|---|
| Day 1–2 | Read RFC 793 sections 1–3 and the state diagram on page 23. Understand: sequence numbers, ACK numbers, SYN/ACK/FIN/RST flags, window size. |
| Day 3 | Parse the TCP header. Handle options: MSS (kind=2), SACK permitted (kind=4), timestamps (kind=8), window scale (kind=3). Skip unknown options gracefully. |
| Day 4–5 | Implement the `TcpState` enum and `Tcb` (Transmission Control Block) struct. |
| Day 6–7 | Build a connection table: `HashMap<(src_ip, src_port, dst_ip, dst_port), Tcb>`. Dispatch incoming segments to the right TCB. Log every state transition. |

**Milestone:** Every incoming TCP segment is parsed and dispatched. `nc -z 192.168.0.2 8080` prints `SYN received` in your logs.

```rust
#[derive(Debug, Clone, PartialEq)]
enum TcpState {
    Closed, Listen, SynSent, SynReceived,
    Established, FinWait1, FinWait2,
    CloseWait, Closing, LastAck, TimeWait
}

struct Tcb {
    state:   TcpState,
    snd_nxt: u32,   // next sequence number to send
    snd_una: u32,   // oldest unacknowledged sequence number
    rcv_nxt: u32,   // next expected sequence number from peer
    rcv_wnd: u16,   // our receive window (advertised to peer)
}
```

**Resources:**
- [RFC 793 — TCP specification (read sections 1–3 and the state diagram)](https://www.rfc-editor.org/rfc/rfc793)
- [Jon Gjengset — Implementing TCP in Rust (4-hour YouTube series — the best resource that exists)](https://www.youtube.com/watch?v=bzja9fQWzdA)
- [TCP state machine visual reference — tcpipguide.com](http://www.tcpipguide.com/free/t_TCPOperationalOverviewandtheTCPFiniteStateMachineF.htm)

---

### Phase 3 — TCP Core (Weeks 5–8)

#### Week 5 — Three-Way Handshake — First Real Connection

**Goal:** Implement `SYN → SYN-ACK → ACK` so external programs can connect to your stack.

**Why it matters:** This is the most satisfying milestone in the project. When `telnet 192.168.0.2 8080` shows `Connected` and your logs show `ESTABLISHED`, you know your stack is real.

**Security note:** Your initial sequence number (ISN) must be cryptographically random, not a counter. This prevents TCP sequence prediction attacks. RFC 793 originally suggested a time-based ISN — that was famously broken by attackers in the 1990s.

**Daily breakdown:**

| Days | Task |
|---|---|
| Day 1–2 | Handle SYN in LISTEN state: allocate TCB, generate random ISN, send SYN-ACK, move to SYN_RECEIVED. |
| Day 3 | Handle the final ACK: validate it ACKs your SYN-ACK, move to ESTABLISHED. |
| Day 4–5 | Handle simultaneous open and SYN retransmits from the peer. |
| Day 6–7 | Handle RST correctly in SYN_RECEIVED. Validate RST sequence numbers per RFC 5961. |

**Milestone:** `telnet 192.168.0.2 8080` shows `Connected`. Three-way handshake visible in Wireshark.

```rust
use rand::Rng;
fn gen_isn() -> u32 { rand::thread_rng().gen() }

fn make_syn_ack(syn: &TcpHeader, isn: u32) -> TcpHeader {
    TcpHeader { seq: isn, ack: syn.seq.wrapping_add(1),
        flags: SYN | ACK, window: 64240, .. Default::default() }
}
```

**Resources:**
- [RFC 793 §3.4 — Sequence number selection](https://www.rfc-editor.org/rfc/rfc793#section-3.4)
- [RFC 5961 — TCP's robustness to blind in-window attacks](https://www.rfc-editor.org/rfc/rfc5961)
- [Jon Gjengset — Implementing TCP in Rust, part 1](https://www.youtube.com/watch?v=bzja9fQWzdA)

---

#### Week 6 — Reliable Delivery — Sequence Numbers, ACKs, Retransmission

**Goal:** Implement TCP's core reliability mechanism: a send buffer tracking unACKed data, a receive buffer that reorders incoming segments, and a retransmission timer.

**Why it matters:** This is TCP's reason for existence. IP is unreliable. TCP makes it reliable by numbering every byte and retransmitting any that aren't acknowledged. Without this week, TCP is just a fancy handshake.

**The Jacobson/Karels RTT estimation algorithm (memorize this):**

```rust
fn update_rtt(&mut self, rtt_sample: Duration) {
    let r = rtt_sample.as_secs_f64();
    self.rttvar = 0.75 * self.rttvar + 0.25 * (self.srtt - r).abs();
    self.srtt   = 0.875 * self.srtt  + 0.125 * r;
    self.rto    = Duration::from_secs_f64(self.srtt + 4.0 * self.rttvar);
}
```

This was Jacobson's 1988 insight: measure variance, not just average RTT. Queuing delay is bursty, so high variance means set a longer RTO to avoid spurious retransmits.

**Daily breakdown:**

| Days | Task |
|---|---|
| Day 1–2 | Build the send buffer: circular byte buffer tracking `SND.UNA` and `SND.NXT`. Advance `SND.UNA` on ACK. |
| Day 3 | Build the receive buffer: `BTreeMap<u32, Vec<u8>>` keyed by sequence number. Deliver to app only when contiguous. |
| Day 4–5 | Implement the retransmission timer (RTO). Exponential backoff on timeout (double RTO, cap at 60s). |
| Day 6–7 | Implement RTT estimation via Jacobson/Karels. Adaptive timeouts. |

**Milestone:** Transfer a 100KB file with `nc`. Verify SHA-256 integrity. Simulate 5% packet loss with `tc netem loss 5%` and watch retransmission fire and recover.

**Resources:**
- [RFC 793 §§3.2–3.3 — Sequence/ACK number logic](https://www.rfc-editor.org/rfc/rfc793#section-3.2)
- [RFC 6298 — Computing TCP's Retransmission Timer](https://www.rfc-editor.org/rfc/rfc6298)
- [Jon Gjengset — Implementing TCP in Rust, part 2](https://www.youtube.com/watch?v=OCpt1I0MWXE)

---

#### Week 7 — Flow Control — Receive Window Management

**Goal:** Implement TCP flow control so the sender never overwhelms the receiver's buffer.

**Why it matters:** Without flow control, a fast sender will overflow a slow receiver's buffer and lose data. TCP's window mechanism is elegantly simple: the receiver tells the sender exactly how many bytes it can accept. The sender must not exceed that budget.

**Daily breakdown:**

| Days | Task |
|---|---|
| Day 1–2 | Advertise `rwnd = receive_buffer_capacity - bytes_in_buffer` in every outgoing segment. |
| Day 3–4 | Sender-side: track peer's `rwnd`. Never send more than `min(cwnd, rwnd)` bytes beyond `SND.UNA`. |
| Day 5 | Implement zero-window probe: when peer's `rwnd=0`, start a persist timer and send 1-byte probes to solicit a window update. |
| Day 6–7 | Implement window scaling (RFC 1323): negotiate scale factor during handshake (TCP option kind=3). Effective window = `rwnd << scale_factor`. |

**Milestone:** Transfer a 10MB file without data loss even when you throttle the receive buffer. Sender correctly pauses when `rwnd=0`.

```rust
fn send_window(&self) -> usize {
    let rwnd = self.peer_rwnd as usize;
    let cwnd = self.cwnd;
    let in_flight = (self.snd_nxt.wrapping_sub(self.snd_una)) as usize;
    min(rwnd, cwnd).saturating_sub(in_flight)
}
```

**Resources:**
- [RFC 793 §3.5 — Flow control](https://www.rfc-editor.org/rfc/rfc793#section-3.5)
- [RFC 1323 — TCP Extensions for High Performance (window scaling + timestamps)](https://www.rfc-editor.org/rfc/rfc1323)
- [TCP/IP Illustrated Vol 1, chapter 20 — W. Richard Stevens](https://www.oreilly.com/library/view/tcpip-illustrated-volume/9780132808200/)

---

#### Week 8 — Congestion Control — Slow Start, AIMD, Fast Retransmit

**Goal:** Implement TCP's congestion control so your stack is a good citizen on shared networks.

**Why it matters:** Without congestion control, your stack would transmit at line rate until routers drop everything. AIMD (Additive Increase, Multiplicative Decrease) is one of the most elegant control theory results in computer science. It is provably stable and fair under congestion.

**The AIMD algorithm — the heart of TCP:**

```
If cwnd < ssthresh:          SLOW START
    cwnd += 1 MSS per ACK   (exponential growth — doubles per RTT)

If cwnd ≥ ssthresh:          CONGESTION AVOIDANCE
    cwnd += MSS²/cwnd per ACK  (linear growth — +1 MSS per RTT)

On packet loss (3 dup ACKs): FAST RETRANSMIT + RECOVERY
    ssthresh = cwnd / 2
    cwnd = ssthresh + 3*MSS
    retransmit missing segment immediately

On timeout:                  SEVERE CONGESTION
    ssthresh = cwnd / 2
    cwnd = 1 MSS
    re-enter slow start
```

**Daily breakdown:**

| Days | Task |
|---|---|
| Day 1–2 | Initialize `cwnd=1 MSS`, `ssthresh=65535`. Implement slow start. |
| Day 3–4 | Implement congestion avoidance. On timeout: halve `ssthresh`, reset `cwnd=1`. |
| Day 5–7 | Implement fast retransmit on 3 duplicate ACKs. Implement fast recovery (RFC 5681). |

**Milestone:** `iperf3` through your stack with `tc netem loss 5%` shows graceful throughput degradation, not collapse. Logs show `cwnd` oscillating and recovering.

**Resources:**
- [RFC 5681 — TCP Congestion Control (the current standard)](https://www.rfc-editor.org/rfc/rfc5681)
- [Computer Networks: A Systems Approach, chapter 6 — free online](https://book.systemsapproach.org/congestion/tcpcc.html)
- [Jacobson 1988 — "Congestion Avoidance and Control" (the original paper)](https://ee.lbl.gov/papers/congavoid.pdf)

---

### Phase 4 — Connection Lifecycle + API (Weeks 9–10)

#### Week 9 — TCP Teardown — FIN, RST, TIME_WAIT

**Goal:** Implement the four-way FIN handshake, TIME_WAIT, abortive RST closes, and half-close semantics.

**Why TIME_WAIT exists (and must be 2×MSL):** When you close a connection, delayed packets from that connection might still be in flight on the network. If you immediately reuse the same 4-tuple (src_ip, src_port, dst_ip, dst_port) for a new connection, those old packets could corrupt the new one. `TIME_WAIT` prevents this by holding the 4-tuple hostage for `2 × MSL` (Maximum Segment Lifetime, typically 30s → 60s total).

**Daily breakdown:**

| Days | Task |
|---|---|
| Day 1–2 | Active close: send FIN → FIN_WAIT_1 → FIN_WAIT_2 → TIME_WAIT → CLOSED (after 2×MSL). |
| Day 3 | Passive close: receive FIN → CLOSE_WAIT → send FIN → LAST_ACK → CLOSED. |
| Day 4–5 | Simultaneous close: ESTABLISHED → FIN_WAIT_1 → CLOSING → TIME_WAIT → CLOSED. |
| Day 6–7 | RST handling with in-window validation. SACK blocks in ACKs (RFC 2018). |

**Milestone:** `curl http://192.168.0.2:8080/` completes a full HTTP request and closes cleanly. Wireshark shows FIN→ACK→FIN→ACK with no RSTs.

**Resources:**
- [RFC 793 §3.5 — Closing a connection](https://www.rfc-editor.org/rfc/rfc793#section-3.5)
- [RFC 2018 — TCP Selective Acknowledgment Options](https://www.rfc-editor.org/rfc/rfc2018)
- [Dan Kegel — The TIME_WAIT state explained (classic article)](https://www.isi.edu/touch/pubs/infocomm99/infocomm99-web/)

---

#### Week 10 — Socket-like API — TcpListener + TcpStream

**Goal:** Wrap all your machinery into a clean socket API. Run a real HTTP server on top of it.

**Why it matters:** This is what makes your stack usable instead of just a demo. Everything so far has been internal machinery. This week you build the interface that real applications talk to.

**Daily breakdown:**

| Days | Task |
|---|---|
| Day 1–2 | Design: `TcpListener::bind(addr)`, `listener.accept() → TcpStream`, `stream.read()`, `stream.write()`, `stream.shutdown()`. Start with blocking I/O. |
| Day 3–4 | Build an event loop: poll the TUN fd + all in-progress connections. Use a timer wheel or min-heap for retransmit and TIME_WAIT timers. `mio` or `epoll` work well. |
| Day 5–6 | Implement the accept queue: completed connections go into a bounded queue. `accept()` dequeues them. Respect the backlog parameter. |
| Day 7 | Write a tiny HTTP/1.0 server: read the GET request, write `200 OK` with a static body. Serve it with `curl`. |

**Milestone:** A minimal HTTP server using your `TcpListener`/`TcpStream` API serves `curl http://192.168.0.2:8080/`. Multiple simultaneous connections work correctly.

```rust
let listener = TcpListener::bind("192.168.0.2:8080")?;
loop {
    let mut stream = listener.accept()?;
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf)?;
    stream.write_all(b"HTTP/1.0 200 OK\r\n\r\nHello!")?;
}
```

**Resources:**
- [mio — Rust non-blocking I/O (for your event loop)](https://github.com/tokio-rs/mio)
- [The C10K problem — Dan Kegel (how to handle 10k connections)](http://www.kegel.com/c10k.html)
- [tun2socks — production userspace TCP for reference](https://github.com/xjasonlyu/tun2socks)

---

### Phase 5 — Testing + Polish (Weeks 11–12)

#### Week 11 — Testing + Benchmarking — Prove It Works

**Goal:** Test your stack against the real kernel using packetdrill. Benchmark throughput vs kernel TCP. Profile where latency goes.

**Daily breakdown:**

| Days | Task |
|---|---|
| Day 1–2 | Install packetdrill. Write 10 test scripts: handshake, data transfer, retransmit, fast recovery, zero-window, teardown. |
| Day 3–4 | iperf3 throughput benchmark. Profile with `perf record` / `cargo flamegraph`. Find your bottleneck (usually receive buffer or checksum loop). |
| Day 5–6 | Latency benchmark: measure RTT for a 1-byte request/response. Implement RFC 1323 timestamps option to measure RTT at the protocol level. |
| Day 7 | Fix the 3 most impactful bugs. Document test results. Write comparison table: your stack vs kernel TCP. |

**Milestone:** A benchmark table in your README. All 10 packetdrill tests pass. A flamegraph PNG in the repo.

**Resources:**
- [packetdrill — TCP behavior testing tool by Google](https://github.com/google/packetdrill)
- [cargo-flamegraph — profiling for Rust](https://github.com/flamegraph-rs/flamegraph)
- [tc-netem — Linux traffic control for simulating loss/delay](https://man7.org/linux/man-pages/man8/tc-netem.8.html)

---

#### Week 12 — Documentation, README, Publishing

**Goal:** Turn a personal project into a professional artifact.

**Daily breakdown:**

| Days | Task |
|---|---|
| Day 1–2 | Write the README: what it is, what RFC it implements, architecture diagram, how to build and run, known limitations, benchmark table. |
| Day 3 | Record a terminal demo GIF with `asciinema` or `gifski`. Show ping + curl working alongside Wireshark. Embed in README. |
| Day 4–5 | Write a blog post: "I built a TCP/IP stack from scratch in Rust." Walk through the hardest problem you solved. Post on dev.to, then HN or r/networking. |
| Day 6–7 | Tag v1.0.0. Add GitHub Actions CI. Open 5 `good-first-issue` tickets. |

**Milestone:** A polished public GitHub repo with README, demo GIF, benchmark results, CI badge, and a published blog post.

---

## Core Concepts Deep Dive

### The Network Stack Model

The OSI model is often taught as 7 layers. For this project, think in 4:

```
Layer 4 — Transport (TCP/UDP)    → segments, ports, reliability
Layer 3 — Network (IP)           → packets, routing, IP addresses
Layer 2 — Data Link (Ethernet)   → frames, MAC addresses
Layer 1 — Physical               → the TUN device abstracts this
```

Each layer adds a header, passes the payload down to the next, and the receiver strips headers from the bottom up. This is called **encapsulation**.

```
Application data: "GET / HTTP/1.0\r\n"
  └─ TCP wraps it: [TCP header | data]
      └─ IP wraps it: [IP header | TCP header | data]
          └─ Ethernet wraps it: [Ethernet header | IP header | TCP header | data | CRC]
```

Your job is to implement the unwrapping (parsing) and wrapping (serialization) at each layer.

---

### TUN/TAP Devices

A **TUN** device is a virtual Layer 3 device. When the kernel wants to route a packet to your TUN device's IP, instead of sending it out a real NIC, it delivers it to your process via a file descriptor `read()`.

```
Normal NIC:  kernel → driver → hardware → network
TUN device:  kernel → /dev/net/tun → your process's read()
```

**TAP** is similar but works at Layer 2 (Ethernet frames, not IP packets). This project uses TUN because we want to handle IP ourselves.

**Key ioctl flags:**
- `IFF_TUN` — create a TUN (Layer 3) device
- `IFF_TAP` — create a TAP (Layer 2) device
- `IFF_NO_PI` — don't prepend a 4-byte `struct tun_pi` header to each packet

Reference: [Linux tun.h](https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_tun.h)

---

### Ethernet & ARP

**Ethernet frame layout:**
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├─────────────────────────────────────────────────────────────────┤
│                    Destination MAC (6 bytes)                     │
├─────────────────────────────────────────────────────────────────┤
│                      Source MAC (6 bytes)                        │
├─────────────────────────┬───────────────────────────────────────┤
│    EtherType (2 bytes)  │          Payload (46–1500 bytes)       │
│  0x0800=IPv4 0x0806=ARP │                                        │
└─────────────────────────┴───────────────────────────────────────┘
```

**ARP operation:**
1. Host A wants to send to IP `192.168.0.2` but doesn't know its MAC.
2. Host A broadcasts: "Who has `192.168.0.2`? Tell `192.168.0.1`."
3. Your stack receives this, recognizes `192.168.0.2` is your IP, replies: "`192.168.0.2` is at `de:ad:be:ef:00:01`."
4. Host A now knows your MAC and can send Ethernet frames directly to you.

---

### IP Layer

**IPv4 header layout (20 bytes minimum):**
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├───┬───┬───────────────────────────┬───────────────────────────────┤
│Ver│IHL│ DSCP/ECN                  │         Total Length          │
├───┴───┴───────────────────────────┴───────────────────────────────┤
│         Identification            │Flags│   Fragment Offset        │
├───────────────────────────────────┼─────┴──────────────────────────┤
│      TTL      │    Protocol       │         Header Checksum        │
├───────────────┴───────────────────┴────────────────────────────────┤
│                          Source IP Address                          │
├────────────────────────────────────────────────────────────────────┤
│                       Destination IP Address                        │
└────────────────────────────────────────────────────────────────────┘
```

Key fields for your implementation:
- **IHL** (Internet Header Length): header length in 32-bit words. Multiply by 4 to get bytes. Minimum is 5 (20 bytes).
- **TTL**: hop limit. Decrement on forward. Drop (and send ICMP time exceeded) when it reaches 0.
- **Protocol**: `1`=ICMP, `6`=TCP, `17`=UDP. Use to dispatch to upper layers.
- **Fragment offset**: offset of this fragment in 8-byte units. Used for reassembly.
- **Flags**: bit 1 = Don't Fragment (DF), bit 2 = More Fragments (MF).

---

### TCP State Machine

The complete state machine from RFC 793, page 23:

```
                              ┌──────┐
                         ┌───►CLOSED◄───┐
                         │    └──┬──┘   │
                    RST  │  passive│    │ delete TCB
                    recv │   open  │    │
                         │    ┌───▼──┐  │
                         │    │LISTEN│  │
                         │    └───┬──┘  │
                         │   SYN  │     │
                         │   recv │     │
                         │  ┌─────▼──┐  │
           SYN sent ──────► │  SYN   │  │
                         │  │ RCVD   │  │
                         │  └─────┬──┘  │
                  SYN+ACK│        │ ACK │
                    recv ▼  ┌─────▼──┐  │
                  ┌───────► │ESTAB-  │  │
                  │SYN      │LISHED  │  │
              SYN─┤sent     └──┬─┬───┘  │
              SENT│             │ │      │
                  └─────────────┘ │ FIN  │
                                  │ sent │
                           ┌──────▼──┐  │
                           │FIN_WAIT_1│  │
                           └──┬───┬──┘  │
                       ACK recv│   │FIN │
                               │   │recv│
                         ┌─────▼┐ ┌▼───────┐
                         │FIN_  │ │CLOSING │
                         │WAIT_2│ └────┬───┘
                         └──┬───┘      │ ACK recv
                    FIN recv│          │
                        ┌───▼──────────▼──┐
                        │   TIME_WAIT     │
                        └────────┬────────┘
                         2*MSL   │
                         timeout │
                            ┌────▼──┐
                            │CLOSED │
                            └───────┘
```

---

### Transmission Control Block (TCB)

The TCB is the per-connection state struct. Every variable defined in RFC 793 §3.2 must live here:

```rust
struct Tcb {
    // State
    state: TcpState,

    // Send sequence variables (RFC 793 §3.2)
    snd_una: u32,   // send unacknowledged — oldest byte not yet ACKed
    snd_nxt: u32,   // send next — next byte to send
    snd_wnd: u16,   // send window — peer's receive window
    snd_wl1: u32,   // sequence number of last window update
    snd_wl2: u32,   // ack number of last window update
    iss:     u32,   // initial send sequence number

    // Receive sequence variables
    rcv_nxt: u32,   // receive next — next expected byte from peer
    rcv_wnd: u16,   // receive window — how much we can accept
    irs:     u32,   // initial receive sequence number

    // Congestion control
    cwnd:    usize, // congestion window (bytes)
    ssthresh: usize, // slow start threshold

    // RTT estimation
    srtt:   f64,    // smoothed RTT (Jacobson)
    rttvar: f64,    // RTT variance (Jacobson)
    rto:    Duration, // retransmission timeout

    // Buffers
    send_buf: SendBuffer,
    recv_buf: RecvBuffer,

    // Options negotiated during handshake
    peer_mss:    u16,
    wscale_local:  u8,
    wscale_remote: u8,
    sack_ok:     bool,
    timestamps:  bool,
}
```

---

### Reliable Delivery

TCP's reliability comes from three mechanisms working together:

**1. Sequence numbers:** Every byte in the stream has a position. The sender records which bytes haven't been ACKed (`SND.UNA`). The receiver records which byte it expects next (`RCV.NXT`).

**2. Acknowledgment:** The receiver ACKs every byte it receives by sending back `RCV.NXT` — the next byte it wants. This is a cumulative ACK: ACK=1001 means "I have everything through byte 1000."

**3. Retransmission:** The sender starts a timer when it sends data. If no ACK arrives before the timer fires, it retransmits the oldest unACKed segment. The timer uses exponential backoff to avoid hammering a congested network.

The subtle part: **out-of-order delivery**. IP doesn't guarantee order. Segment 2 might arrive before segment 1. Your receive buffer must hold segment 2 until segment 1 arrives, then deliver both in order.

---

### Flow Control

Flow control prevents the sender from overwhelming the receiver's buffer. It operates at the receiver's direction:

```
Receiver's buffer: [....used....][.......free.......]
                                  ↑
                              rwnd = this size

Receiver advertises rwnd in every ACK.
Sender must not send more than rwnd bytes beyond SND.UNA.
```

**Zero window:** When the receiver's buffer is full, `rwnd=0`. The sender must stop transmitting data (but keeps the connection alive with periodic 1-byte probes called "zero window probes"). When the receiver drains its buffer, it sends a window update to resume the sender.

---

### Congestion Control

Congestion control prevents the sender from overwhelming the *network* (not the receiver). It operates at the sender's initiative, using packet loss as a signal of congestion.

The sender maintains a **congestion window (cwnd)**. It may only send `min(cwnd, rwnd)` bytes in flight.

**Slow start:** cwnd starts at 1 MSS and doubles every RTT. Fast growth to fill the pipe quickly.

**Congestion avoidance:** Once cwnd exceeds `ssthresh`, grow linearly (+1 MSS per RTT). This is the "AI" (Additive Increase) in AIMD.

**Loss detection → cwnd halving:** On packet loss, `ssthresh = cwnd/2`. This is the "MD" (Multiplicative Decrease) in AIMD. Why multiplicative? Because it provably converges to fair allocation across competing flows.

**Fast retransmit:** On 3 duplicate ACKs (3 ACKs for the same sequence number), assume the next segment was lost. Retransmit immediately without waiting for RTO. This is faster than waiting for the timer.

---

## The Complete RFC Reading List

Read these in order. They are all freely available at rfc-editor.org.

| RFC | Title | When to Read | Priority |
|---|---|---|---|
| [RFC 894](https://www.rfc-editor.org/rfc/rfc894) | IP over Ethernet | Week 1 | Required |
| [RFC 826](https://www.rfc-editor.org/rfc/rfc826) | ARP | Week 2 | Required |
| [RFC 792](https://www.rfc-editor.org/rfc/rfc792) | ICMP | Week 2 | Required |
| [RFC 791](https://www.rfc-editor.org/rfc/rfc791) | IP | Week 3 | Required |
| [RFC 793](https://www.rfc-editor.org/rfc/rfc793) | TCP (the bible) | Week 4–9 | Required |
| [RFC 5961](https://www.rfc-editor.org/rfc/rfc5961) | TCP Robustness to Blind Attacks | Week 5 | Required |
| [RFC 6298](https://www.rfc-editor.org/rfc/rfc6298) | TCP Retransmission Timer | Week 6 | Required |
| [RFC 1323](https://www.rfc-editor.org/rfc/rfc1323) | TCP Extensions (window scaling, timestamps) | Week 7 | Required |
| [RFC 5681](https://www.rfc-editor.org/rfc/rfc5681) | TCP Congestion Control | Week 8 | Required |
| [RFC 2018](https://www.rfc-editor.org/rfc/rfc2018) | TCP SACK | Week 9 | Required |
| [RFC 7323](https://www.rfc-editor.org/rfc/rfc7323) | TCP Extensions for High Performance (updated 1323) | Week 7 | Recommended |
| [RFC 2525](https://www.rfc-editor.org/rfc/rfc2525) | Known TCP Implementation Problems | Any week | Highly recommended |
| [RFC 9293](https://www.rfc-editor.org/rfc/rfc9293) | Transmission Control Protocol (2022 update to RFC 793) | After week 9 | Recommended |
| [RFC 4821](https://www.rfc-editor.org/rfc/rfc4821) | Packetization Layer Path MTU Discovery | Extension | Optional |
| [RFC 3168](https://www.rfc-editor.org/rfc/rfc3168) | Explicit Congestion Notification (ECN) | Extension | Optional |

**How to read an RFC:** Don't read linearly on first pass. Scan the table of contents, read the abstract and introduction, then jump to the section describing the exact feature you're implementing. Use the RFC as a reference, not a tutorial.

---

## Resource Library

### Books

| Book | Author | Why Read It | Link |
|---|---|---|---|
| **TCP/IP Illustrated, Vol. 1** | W. Richard Stevens | The definitive reference. Every TCP/IP concept with Wireshark traces. If you own one book, this is it. | [O'Reilly](https://www.oreilly.com/library/view/tcpip-illustrated-volume/9780132808200/) |
| **TCP/IP Illustrated, Vol. 2** | Gary Wright | The actual BSD kernel source code explained. Read after Vol. 1. | [Amazon](https://www.amazon.com/TCP-IP-Illustrated-Vol-Implementation/dp/020163354X) |
| **Computer Networks: A Systems Approach** | Peterson & Davie | Excellent systems perspective, free online. Best chapter on congestion control. | [Free online](https://book.systemsapproach.org/) |
| **The Linux Programming Interface** | Michael Kerrisk | Everything about Linux system calls: `ioctl`, `epoll`, file descriptors. Indispensable. | [No Starch Press](https://man7.org/tlpi/) |
| **Rust Programming Language** | Klabnik & Nichols | The official Rust book. Free online. | [Free online](https://doc.rust-lang.org/book/) |
| **Programming Rust** | Blandy & Orendorff | Deep Rust for systems programmers. | [O'Reilly](https://www.oreilly.com/library/view/programming-rust-2nd/9781492052586/) |

---

### Video Courses

| Resource | Length | Content | Link |
|---|---|---|---|
| **Jon Gjengset — Implementing TCP in Rust** | 4 hours | Live-coded TCP stack in Rust. The single best resource for this project. Watch after Week 3. | [YouTube](https://www.youtube.com/watch?v=bzja9fQWzdA) |
| **saminiir — Let's code a TCP/IP stack** | Blog series (5 parts) | Step-by-step C implementation. Excellent companion. | [saminiir.com](https://www.saminiir.com/lets-code-tcp-ip-stack-1-ethernet-arp) |
| **MIT 6.033 — Computer Systems Engineering** | Full course | Top-tier systems course. Networking lectures are exceptional. Free recordings online. | [MIT OCW](https://ocw.mit.edu/courses/6-033-computer-system-engineering-spring-2018/) |
| **Stanford CS144 — Introduction to Computer Networks** | Full course | Taught in Rust in recent years. Overlaps perfectly with this project. Labs are gold. | [Stanford](https://cs144.github.io/) |

---

### Reference Implementations

Study these codebases once you have your own working implementation. Don't read them before — you'll learn more by struggling first.

| Project | Language | What to Study | Link |
|---|---|---|---|
| **smoltcp** | Rust | The best-organized userspace TCP/IP stack. Pure Rust, no_std capable. Read `src/socket/tcp.rs`. | [GitHub](https://github.com/smoltcp-rs/smoltcp) |
| **lwIP** | C | The dominant embedded TCP/IP stack. Used in billions of IoT devices. | [Savannah](https://savannah.nongnu.org/projects/lwip/) |
| **Linux kernel tcp.c** | C | The real thing. 7000+ lines. Read only specific functions, not the whole file. | [GitHub](https://github.com/torvalds/linux/blob/master/net/ipv4/tcp.c) |
| **tun2socks** | Go | Production userspace TCP. Shows how to bridge TUN to socks5. | [GitHub](https://github.com/xjasonlyu/tun2socks) |
| **rust-tcp** (Jon Gjengset) | Rust | The companion code to the YouTube video above. | [GitHub](https://github.com/jonhoo/rust-tcp) |
| **netstack in Go** | Go | gVisor's TCP/IP stack. Production quality. | [GitHub](https://github.com/google/gvisor/tree/master/pkg/tcpip) |

---

### Tools

#### Network Debugging

| Tool | Use | Command |
|---|---|---|
| **Wireshark** | GUI packet analysis. Dissects every field of every protocol. Essential. | `wireshark &` |
| **tcpdump** | CLI packet capture. Use when Wireshark is too heavy. | `tcpdump -i tun0 -vv -X` |
| **tshark** | CLI Wireshark. Scriptable. | `tshark -i tun0 -V` |
| **netcat (nc)** | TCP testing: send data, listen on ports. | `nc -l 8080` / `nc 192.168.0.2 8080` |
| **curl** | HTTP testing | `curl -v http://192.168.0.2:8080/` |
| **telnet** | Raw TCP connection testing | `telnet 192.168.0.2 8080` |
| **ss** | Socket state inspection | `ss -tnp` |

#### Network Simulation

| Tool | Use | Command |
|---|---|---|
| **tc netem** | Simulate packet loss, delay, reordering | `tc qdisc add dev tun0 root netem loss 5% delay 10ms` |
| **iperf3** | Throughput benchmarking | `iperf3 -s` / `iperf3 -c 192.168.0.2` |
| **packetdrill** | TCP behavior testing (Google) | `packetdrill tests/handshake.pkt` |

#### Profiling

| Tool | Use | Command |
|---|---|---|
| **cargo flamegraph** | Flame graph profiling for Rust | `cargo flamegraph --bin tcp-stack` |
| **perf** | Linux performance profiler | `perf record -g ./target/release/tcp-stack` |
| **heaptrack** | Heap allocation profiling | `heaptrack ./target/release/tcp-stack` |
| **criterion** | Microbenchmarking library for Rust | Add to `[dev-dependencies]` |

#### Development

| Tool | Use | Link |
|---|---|---|
| **Wireshark display filters** | Filter to see only your traffic | [Filter reference](https://www.wireshark.org/docs/dfref/) |
| **hexdump** | Inspect raw packet bytes | `hexdump -C` |
| **asciinema** | Record terminal sessions as GIFs | [asciinema.org](https://asciinema.org) |
| **ip commands cheatsheet** | Configure your TUN device | `ip link set tun0 up` / `ip addr add 192.168.0.2/24 dev tun0` |

---

### Papers

Read these for deep understanding. All are freely available as PDFs.

| Paper | Authors | Year | What You'll Learn | Link |
|---|---|---|---|---|
| **Congestion Avoidance and Control** | Van Jacobson | 1988 | The original AIMD + RTT estimation paper. One of the most influential systems papers ever written. | [PDF](https://ee.lbl.gov/papers/congavoid.pdf) |
| **A Protocol for Packet Network Intercommunication** | Cerf & Kahn | 1974 | The paper that invented TCP/IP. Read for historical context. | [PDF](https://www.cs.princeton.edu/courses/archive/fall06/cos561/papers/cerf74.pdf) |
| **End-to-End Arguments in System Design** | Saltzer, Reed & Clark | 1984 | The intellectual foundation for why TCP lives at Layer 4 instead of being built into the network. | [PDF](https://web.mit.edu/Saltzer/www/publications/endtoend/endtoend.pdf) |
| **Analysis of the Increase and Decrease Algorithms for Congestion Avoidance** | Chiu & Jain | 1989 | Proves mathematically that AIMD converges to efficiency and fairness. | [PDF](https://www.cse.wustl.edu/~jain/papers/ftp/cj89.pdf) |
| **CUBIC: A New TCP-Friendly High-Speed TCP Variant** | Ha, Rhee & Xu | 2008 | The current default Linux congestion control algorithm (replaces AIMD for long-distance links). | [PDF](https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.309.9936&rep=rep1&type=pdf) |
| **BBR: Congestion-Based Congestion Control** | Cardwell et al. | 2016 | Google's BBR algorithm — model-based rather than loss-based. The future of congestion control. | [PDF](https://queue.acm.org/detail.cfm?id=3022184) |

---

## Testing Guide

### Running Packetdrill Tests

```bash
# All tests
for f in tests/packetdrill/*.pkt; do
    echo "Running $f..."
    sudo packetdrill "$f" && echo "PASS" || echo "FAIL"
done

# Single test with verbose output
sudo packetdrill --verbose tests/packetdrill/handshake.pkt
```

**Example packetdrill test — three-way handshake:**
```
# Verify the three-way handshake
0    socket(..., SOCK_STREAM, IPPROTO_TCP) = 3
+0   bind(3, ..., ...) = 0
+0   listen(3, 1) = 0

# Client sends SYN
+0   < S  0:0(0) win 65535 <mss 1460>
# Stack sends SYN-ACK
+0   > S. 0:0(0) ack 1 <...>
# Client sends ACK — handshake complete
+.1  < .  1:1(0) ack 1 win 65535
```

### Simulating Adverse Network Conditions

```bash
# Add 5% packet loss
sudo tc qdisc add dev tun0 root netem loss 5%

# Add 50ms delay + 10ms jitter
sudo tc qdisc add dev tun0 root netem delay 50ms 10ms

# Add packet reordering (10% of packets reordered by up to 25ms)
sudo tc qdisc add dev tun0 root netem delay 25ms reorder 10%

# Remove all network impairments
sudo tc qdisc del dev tun0 root

# Show current settings
tc qdisc show dev tun0
```

### Verifying Data Integrity

```bash
# Server side: serve a file
cat /usr/share/doc/bash/copyright | nc -l 192.168.0.2 9999

# Client side: receive and verify
nc 192.168.0.2 9999 | sha256sum

# Compare with known good
sha256sum /usr/share/doc/bash/copyright
```

---

## Benchmarks

*Run on: AMD Ryzen 9 5900X, 32GB RAM, Linux 6.5, loopback via TUN*

| Metric | Your Stack | Linux Kernel TCP | Delta |
|---|---|---|---|
| Throughput (large file) | — MB/s | ~9,400 MB/s | TBD |
| Latency (1-byte RTT) | — µs | ~15 µs | TBD |
| Connections/second | — | ~50,000 | TBD |
| CPU @ 1 Gbps | — % | ~8% | TBD |

Fill this table in Week 11. The expected result for a well-optimized Rust userspace stack: throughput ~5–15% of kernel TCP (kernel bypasses many copies you can't avoid), latency comparable (TUN overhead is minimal).

**To run iperf3 benchmark:**
```bash
# Terminal 1: start iperf3 server through your stack
./target/release/tcp-stack --iperf3-mode

# Terminal 2: run the benchmark
iperf3 -c 192.168.0.2 -t 30 -P 4
```

---

## Known Limitations

This is a learning implementation, not a production kernel. Known limitations:

- **No IPv6.** Only IPv4 is implemented. Adding IPv6 is a significant but well-defined extension (RFC 8200).
- **No UDP.** Only TCP is implemented at Layer 4.
- **Single-threaded event loop.** The event loop is not parallelized. On multi-core systems, this limits throughput to a single core. Adding multi-threading requires careful locking around the connection table and TCBs.
- **No PMTU Discovery.** We don't discover the path MTU dynamically (RFC 4821). We assume 1500-byte MTU everywhere.
- **No ECN.** Explicit Congestion Notification (RFC 3168) is not implemented. We only detect congestion via packet loss.
- **No TCP Fast Open.** TFO (RFC 7413) allows data in the SYN packet, reducing latency by one RTT.
- **TIME_WAIT recycling.** We don't implement `SO_REUSEADDR`/`SO_REUSEPORT` semantics for recycling TIME_WAIT connections.
- **No Nagle's algorithm.** Nagle coalesces small writes into fewer segments. We send immediately. This is correct but inefficient for small writes.
- **Limited options.** We implement MSS, window scale, timestamps, and SACK permitted. Other TCP options are ignored.

---

## FAQ

**Q: Do I need to run as root?**  
A: You need `CAP_NET_ADMIN` to create TUN devices. Either run with `sudo`, or grant the capability with `sudo setcap cap_net_admin=eip ./target/release/tcp-stack`. The latter is preferred for development.

**Q: Can I run this on macOS?**  
A: macOS uses `utun` devices instead of `/dev/net/tun`. The ioctl interface is different. You'll need to use the [tun crate](https://crates.io/crates/tun) which abstracts both, or port the TUN setup code. The rest of the implementation (Ethernet, IP, TCP) is platform-independent.

**Q: Can I run this on WSL2?**  
A: WSL2 supports TUN devices. You may need to enable them: `sudo modprobe tun`. Note that WSL2 has a NAT layer between you and the Windows host, so some tests (like `ping` from Windows) may behave differently.

**Q: My ping works but curl doesn't — why?**  
A: ICMP (ping) is stateless — one request, one reply. HTTP over TCP requires the full handshake, data transfer, and teardown to work. Each phase builds on the previous. Check your logs: where does the state machine stop? Common culprits in early weeks: not sending SYN-ACK (check your LISTEN handler), not handling the final ACK of the handshake (check SYN_RECEIVED → ESTABLISHED transition), not retransmitting when the client's ACK gets lost.

**Q: Wireshark shows my packets but the connection keeps resetting — why?**  
A: The Linux kernel is also receiving your packets (via the TUN device's route). If your userspace stack doesn't respond fast enough, the kernel may send a RST because it has no socket listening on that port. Solution: either firewall the port on the kernel (`sudo iptables -A INPUT -p tcp --dport 8080 -j DROP`), or make your stack respond before the kernel's RST timeout.

**Q: Why does TIME_WAIT have to be 2×MSL?**  
A: MSL (Maximum Segment Lifetime) is the longest a packet can live on the internet (RFC 793 says 2 minutes, Linux uses 30s). When you close a connection, your final ACK might get lost, causing the peer to retransmit their FIN. You need to be around for `1 MSL` to handle that retransmit. The other `1 MSL` ensures any delayed packets from the connection are dead before you reuse the 4-tuple. Total: `2 × MSL`.

**Q: What's the difference between SND.UNA, SND.NXT, and SND.WND?**  
A: These are the three core send-side variables from RFC 793 §3.2:  
- `SND.UNA` = oldest unACKed byte. The left edge of the unACKed window.  
- `SND.NXT` = next byte to send. The right edge of what you've sent so far.  
- `SND.WND` = peer's receive window. How many bytes ahead of `SND.UNA` you're allowed to send.  
- Invariant: `SND.UNA ≤ SND.NXT ≤ SND.UNA + SND.WND`

---

## Glossary

| Term | Definition |
|---|---|
| **ACK** | Acknowledgment. A TCP flag indicating the ACK number field is valid. Also, the act of acknowledging received data. |
| **ARP** | Address Resolution Protocol. Maps IPv4 addresses to MAC (Ethernet) addresses. |
| **cwnd** | Congestion Window. The sender's limit on bytes in flight, set by congestion control. |
| **EtherType** | A 2-byte field in the Ethernet header identifying the payload type (0x0800=IPv4, 0x0806=ARP). |
| **FIN** | TCP flag. Sent when a side wants to close its half of the connection. |
| **Fragment offset** | In IP, the byte offset of this fragment within the original datagram, in units of 8 bytes. |
| **IHL** | IP Header Length. The IP header length in 32-bit words (minimum 5, maximum 15). |
| **ISN** | Initial Sequence Number. The starting sequence number for a new TCP connection. Must be random. |
| **MAC** | Media Access Control address. The 6-byte hardware address of a network interface. |
| **MSL** | Maximum Segment Lifetime. The longest a TCP segment can exist in the network (RFC 793: 2 minutes). |
| **MSS** | Maximum Segment Size. The largest TCP payload a connection will send. Negotiated via TCP option during handshake. Default 536 bytes if not negotiated. |
| **MTU** | Maximum Transmission Unit. The largest frame a link layer will transmit (Ethernet: 1500 bytes). |
| **MF** | More Fragments flag in IP header. Set on all fragments except the last. |
| **RTT** | Round-Trip Time. Time from sending a segment to receiving its ACK. |
| **RTO** | Retransmission Timeout. How long to wait for an ACK before retransmitting. Computed from RTT estimates. |
| **RST** | TCP Reset flag. Immediately aborts a connection. |
| **rwnd** | Receive Window. Advertised by the receiver in every segment to tell the sender how many bytes it can accept. |
| **SACK** | Selective Acknowledgment. A TCP option that allows the receiver to ACK non-contiguous blocks, enabling the sender to retransmit only what was lost. |
| **ssthresh** | Slow Start Threshold. cwnd below this → slow start; cwnd at or above → congestion avoidance. |
| **SYN** | TCP flag. Synchronize sequence numbers. Used during the three-way handshake. |
| **TAP** | A virtual network interface at Layer 2 (Ethernet frames). Like TUN but for Ethernet. |
| **TCB** | Transmission Control Block. The per-connection state struct containing all RFC 793 §3.2 variables. |
| **TTL** | Time To Live. A counter decremented at each IP hop. Packet is dropped when TTL reaches 0. Prevents routing loops. |
| **TUN** | A virtual network interface at Layer 3 (IP packets). Delivers packets to a userspace process. |

---

## Contributing

Contributions welcome! This is a learning project, so the bar for contribution is: **does it help someone understand how TCP/IP works?**

**Good first issues** (see the issue tracker):
- Add UDP implementation
- Add IPv6 support (big one)
- Add Nagle's algorithm
- Improve error messages to reference the specific RFC section
- Add more packetdrill test cases
- Port TUN setup to macOS (`utun`)

**To contribute:**
```bash
git clone https://github.com/Mannava-Daasaradhi/tcp-stack
cd tcp-stack
cargo test
cargo clippy -- -D warnings
# Make your change
# Add a test or packetdrill script
# Open a PR with a description of what RFC behavior you're implementing
```

Please open an issue before working on large features to avoid duplicated effort.

---

*Built with RFC 793, a lot of Wireshark, and unreasonable amounts of patience.*  
*"The entire internet runs on this. Now so does your laptop."*

---

## License

**SPDX-License-Identifier: MIT**

```
MIT License

Copyright (c) 2024 tcp-stack contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

See [LICENSE](LICENSE) for the full text. This project is intentionally permissively licensed so that students, researchers, and engineers can freely adapt and embed it into their own learning projects without restriction.

---

## Acknowledgements & Credits

This project stands on the shoulders of extraordinary engineers, educators, and open-source authors. Each of the following directly shaped the design, pedagogy, or reference implementation of this stack.

### People

| Name | Contribution |
|---|---|
| **Jon Gjengset** | His 4-hour live-coded TCP-in-Rust YouTube stream is the single most instructive piece of content for this project. Watching him reason through RFC 793 in real time is irreplaceable. |
| **W. Richard Stevens** | Author of *TCP/IP Illustrated*, the definitive reference for every protocol implemented here. The packet traces throughout this README are inspired by his style. |
| **Van Jacobson** | Invented TCP congestion control (slow start, AIMD, fast retransmit, RTT estimation). Every line of `congestion.rs` and `retransmit.rs` descends from his 1988 paper. |
| **Vint Cerf & Bob Kahn** | Co-invented TCP/IP in 1974. RFC 793 is their work. |
| **saminiir (Sandor Dargo)** | Author of the "Let's code a TCP/IP stack" C blog series — the clearest step-by-step walkthrough of TUN/ARP/IP/ICMP/TCP for beginners. |
| **Michael Kerrisk** | Author of *The Linux Programming Interface* — the bible for `ioctl`, `epoll`, file descriptors, and the Linux system call interface. |
| **Dan Kegel** | Author of the TIME_WAIT and C10K articles that remain essential reading decades later. |

### Libraries & Tools

| Project | License | Use in This Stack |
|---|---|---|
| [smoltcp](https://github.com/smoltcp-rs/smoltcp) | MIT/Apache-2.0 | Architecture reference; `src/tcp/` module organization is inspired by smoltcp's `socket/tcp.rs`. |
| [mio](https://github.com/tokio-rs/mio) | MIT | Optional event loop backend for `src/tcp/api.rs`. |
| [packetdrill](https://github.com/google/packetdrill) | Apache-2.0 | The entire `tests/packetdrill/` suite uses Google's packetdrill tool. |
| [criterion.rs](https://github.com/bheisler/criterion.rs) | MIT/Apache-2.0 | Throughput and latency benchmarks in `benches/`. |
| [cargo-flamegraph](https://github.com/flamegraph-rs/flamegraph) | MIT/Apache-2.0 | Performance profiling workflow. |

### Institutions & Curricula

| Institution | Resource |
|---|---|
| **MIT CSAIL** | MIT 6.033 systems lecture notes, freely available on OCW. |
| **Stanford University** | CS144 labs (now Rust-based), which share nearly identical learning objectives with this project. |
| **IETF** | The RFC authors and editors who maintain the specifications at rfc-editor.org. |

---

## Changelog

All notable changes to this project will be documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/). This project adheres to [Semantic Versioning](https://semver.org/).

---

### [Unreleased]

#### In Progress
- UDP socket implementation (`src/udp/`)
- IPv6 dual-stack support (RFC 8200)
- Nagle's algorithm (`tcp_nodelay` toggle)
- `SO_REUSEADDR` / `SO_REUSEPORT` semantics for TIME_WAIT recycling
- macOS `utun` support via the `tun` crate
- Async API using `tokio` (in a separate `feature = "async"` flag)

---

### [1.0.0] — 2024-MM-DD *(target: end of Week 12)*

#### Added
- Full TUN/TAP setup on Linux (`src/tun.rs`)
- Ethernet frame parser and serializer (`src/ethernet.rs`)
- ARP request/reply with a time-bounded cache (`src/arp.rs`)
- IPv4 header parsing, checksum verification, fragment reassembly (`src/ip.rs`)
- ICMP echo request/reply + TTL exceeded (`src/icmp.rs`)
- TCP header parser with all option fields (`src/tcp/mod.rs`)
- 11-state TCP state machine (`src/tcp/state.rs`, `src/tcp/tcb.rs`)
- Three-way handshake (SYN, SYN-ACK, ACK)
- Reliable delivery: send buffer, receive reorder queue, cumulative ACK (`src/tcp/send_buf.rs`, `src/tcp/recv_buf.rs`)
- Retransmission timer using Jacobson/Karels RTT estimation with exponential backoff (`src/tcp/retransmit.rs`)
- Flow control: advertised receive window, zero-window probe (`src/tcp/flow.rs`)
- Window scaling option (RFC 1323) negotiated at handshake
- Congestion control: slow start, AIMD, fast retransmit, fast recovery (RFC 5681) (`src/tcp/congestion.rs`)
- SACK option support during handshake (`sack_ok` flag in TCB)
- TCP teardown: active close, passive close, simultaneous close, RST (`src/tcp/teardown.rs`)
- TIME_WAIT with configurable 2×MSL timer
- Public `TcpListener` / `TcpStream` API with blocking I/O (`src/tcp/api.rs`)
- Minimal HTTP/1.0 server example (`examples/http_server.rs`)
- 10 packetdrill test scripts (`tests/packetdrill/`)
- Criterion throughput benchmark (`benches/throughput.rs`)
- GitHub Actions CI pipeline (`.github/workflows/ci.yml`)

#### Known Limitations (v1.0.0)
- No IPv6, no UDP, no ECN, no TFO, no Nagle's, single-threaded event loop
- See [Known Limitations](#known-limitations) for the full list

---

### [0.5.0] — Week 8 checkpoint

#### Added
- TCP congestion control (slow start, AIMD, fast retransmit/recovery)
- RTT estimation and RTO computation per RFC 6298
- Flow control with zero-window probe
- Window scaling negotiation (RFC 1323)

#### Changed
- Send buffer refactored from `VecDeque<u8>` to a circular byte ring for efficiency
- Log output now includes `cwnd` and `ssthresh` values in every send event

---

### [0.3.0] — Week 5 checkpoint

#### Added
- TCP state machine (LISTEN → SYN_RECEIVED → ESTABLISHED)
- Three-way handshake
- TCP header parser with options (MSS, window scale, SACK permitted, timestamps)

---

### [0.2.0] — Week 3 checkpoint

#### Added
- IPv4 header parsing and IP checksum
- IP fragmentation and reassembly
- ICMP echo request/reply (`ping` works)

---

### [0.1.0] — Week 1 checkpoint

#### Added
- TUN device setup via `ioctl(IFF_TUN | IFF_NO_PI)`
- Ethernet frame parser (destination MAC, source MAC, EtherType)
- ARP request/reply

---

## Roadmap

The following extensions are planned or community-requested. They are ordered from easiest to hardest. Each is a well-scoped project on its own.

### Near-term (v1.1)

| Feature | Difficulty | RFC | Notes |
|---|---|---|---|
| Nagle's algorithm | Easy | RFC 896 | Coalesce small writes. Add `TCP_NODELAY` socket option to disable. |
| `SO_REUSEADDR` / `SO_REUSEPORT` | Medium | POSIX | Allow TIME_WAIT connections to be reused. Essential for servers that restart. |
| TCP keepalive | Medium | RFC 1122 §4.2.3.6 | Detect dead connections with periodic probes. Implement `SO_KEEPALIVE`. |
| Improved SACK handling | Medium | RFC 2018 | Use SACK blocks to retransmit only genuinely lost segments, not the whole window. |
| TCP timestamps | Medium | RFC 1323 | More accurate RTT measurements. Required for PAWS (Protect Against Wrapped Sequence numbers). |

### Medium-term (v1.2)

| Feature | Difficulty | RFC | Notes |
|---|---|---|---|
| UDP | Medium | RFC 768 | Stateless, much simpler than TCP. Good first extension after v1.0. |
| PMTU Discovery | Medium | RFC 4821 | Don't assume 1500-byte MTU everywhere. Handle ICMP "fragmentation needed" messages. |
| ECN (Explicit Congestion Notification) | Hard | RFC 3168 | Use IP/TCP header bits to signal congestion without dropping packets. |
| macOS `utun` support | Medium | — | Port TUN setup to macOS via the `utun` ioctl or the `tun` crate. |
| Multi-threaded event loop | Hard | — | Shard the connection table by 4-tuple hash. Use `crossbeam-channel` for inter-thread communication. |

### Long-term (v2.0)

| Feature | Difficulty | RFC | Notes |
|---|---|---|---|
| IPv6 dual-stack | Very Hard | RFC 8200 | Full IPv6 header, ICMPv6, NDP (replaces ARP), dual-stack socket API. |
| TCP Fast Open (TFO) | Hard | RFC 7413 | Send application data in the SYN packet. Reduces latency by 1 RTT for repeat connections. |
| QUIC (UDP-based) | Expert | RFC 9000 | Google's replacement for TCP+TLS. Separate project scope. |
| CUBIC congestion control | Hard | RFC 8312 | The default Linux algorithm since kernel 2.6.19. Replace AIMD in `congestion.rs`. |
| BBR congestion control | Expert | — | Google's model-based algorithm. Requires accurate bandwidth estimation. |
| Async API (`tokio` integration) | Hard | — | Non-blocking `TcpListener`/`TcpStream` backed by `tokio`'s reactor. Feature-flagged. |
| `no_std` embedded target | Very Hard | — | Inspired by smoltcp. Remove all heap allocation; use fixed-size arrays everywhere. |

---

## API Reference

A comprehensive reference for the public types and functions exported by this crate.

### `TcpListener`

Analogous to `std::net::TcpListener`. Binds to a local address and listens for incoming connections.

```rust
use tcp_stack::TcpListener;

// Bind to an address on your TUN interface
let listener = TcpListener::bind("192.168.0.2:8080")?;

// Accept a connection (blocking until one arrives)
let stream = listener.accept()?;

// Accept in a loop (basic server pattern)
loop {
    match listener.accept() {
        Ok(stream) => {
            // handle stream in a thread or async task
        }
        Err(e) => eprintln!("Accept error: {}", e),
    }
}
```

#### Methods

| Method | Signature | Description |
|---|---|---|
| `bind` | `fn bind(addr: &str) -> Result<TcpListener>` | Creates a new listener bound to the given address. Adds it to the listen queue in the connection table. |
| `accept` | `fn accept(&self) -> Result<TcpStream>` | Blocks until a connection completes the three-way handshake. Returns the connected stream. |
| `set_backlog` | `fn set_backlog(&mut self, n: usize)` | Sets the maximum number of pending connections waiting in the accept queue. Default: 128. |
| `local_addr` | `fn local_addr(&self) -> SocketAddr` | Returns the local address this listener is bound to. |

---

### `TcpStream`

Analogous to `std::net::TcpStream`. Represents a connected TCP connection.

```rust
use tcp_stack::TcpStream;
use std::io::{Read, Write};

// Client-side: connect to a remote host
let mut stream = TcpStream::connect("192.168.0.1:9000")?;

// Write data
stream.write_all(b"GET / HTTP/1.0\r\n\r\n")?;

// Read response
let mut buf = vec![0u8; 4096];
let n = stream.read(&mut buf)?;
println!("Received {} bytes: {}", n, String::from_utf8_lossy(&buf[..n]));

// Graceful close (sends FIN)
stream.shutdown(std::net::Shutdown::Both)?;
```

#### Methods

| Method | Signature | Description |
|---|---|---|
| `connect` | `fn connect(addr: &str) -> Result<TcpStream>` | Initiates a three-way handshake to the given address. Blocks until ESTABLISHED. |
| `read` | `fn read(&mut self, buf: &mut [u8]) -> Result<usize>` | Reads data from the receive buffer. Blocks until at least 1 byte is available. Returns 0 on EOF (FIN received). |
| `write` | `fn write(&mut self, buf: &[u8]) -> Result<usize>` | Copies data into the send buffer. May not send immediately (subject to cwnd and rwnd). |
| `write_all` | `fn write_all(&mut self, buf: &[u8]) -> Result<()>` | Writes all bytes, retrying until done. |
| `flush` | `fn flush(&mut self) -> Result<()>` | Forces any buffered data to be sent immediately. Bypasses Nagle (once implemented). |
| `shutdown` | `fn shutdown(how: Shutdown) -> Result<()>` | Initiates a graceful close. `Shutdown::Write` sends FIN. `Shutdown::Both` sends FIN and stops reads. |
| `peer_addr` | `fn peer_addr(&self) -> SocketAddr` | Returns the remote address of the connection. |
| `local_addr` | `fn local_addr(&self) -> SocketAddr` | Returns the local address of the connection. |
| `set_read_timeout` | `fn set_read_timeout(&mut self, dur: Option<Duration>) -> Result<()>` | Sets a timeout for `read()`. Returns `Err(WouldBlock)` if the timeout expires. |

---

### `TcpState` enum

All 11 states from RFC 793 §3.2, represented as a Rust enum.

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}
```

You can inspect the current state of a connection for debugging:

```rust
let tcb = connection_table.get(&four_tuple).unwrap();
println!("Current state: {:?}", tcb.state);
```

---

### `Tcb` struct (internal)

The Transmission Control Block is not part of the public API but is documented here for contributors and extension authors. All field names are taken directly from RFC 793 §3.2.

```rust
// Access via connection_table (internal only)
let tcb: &Tcb = table.get(&(src_ip, src_port, dst_ip, dst_port))?;
println!("SND.UNA={} SND.NXT={} cwnd={} ssthresh={}",
    tcb.snd_una, tcb.snd_nxt, tcb.cwnd, tcb.ssthresh);
```

Key fields are documented in the [Transmission Control Block (TCB)](#transmission-control-block-tcb) section above.

---

### Error Types

```rust
use tcp_stack::Error;

match stream.read(&mut buf) {
    Ok(0)                      => { /* EOF — FIN received */ }
    Ok(n)                      => { /* n bytes read */ }
    Err(Error::ConnectionReset) => { /* RST received */ }
    Err(Error::TimedOut)        => { /* read timeout expired */ }
    Err(Error::BrokenPipe)      => { /* connection closed before write finished */ }
    Err(e)                     => eprintln!("Unexpected error: {}", e),
}
```

| Error Variant | Meaning | RFC Reference |
|---|---|---|
| `Error::ConnectionReset` | RST received from peer | RFC 793 §3.4 |
| `Error::ConnectionRefused` | SYN sent but RST received (no listener on port) | RFC 793 §3.4 |
| `Error::TimedOut` | `read_timeout` expired with no data | — |
| `Error::BrokenPipe` | Tried to write after peer closed with RST | POSIX |
| `Error::AddressInUse` | Port already bound by another listener | POSIX |
| `Error::InvalidInput` | Malformed address string | — |
| `Error::Io(io::Error)` | Underlying TUN I/O error | — |

---

## Configuration Reference

All runtime configuration is controlled by environment variables and an optional `tcp-stack.toml` config file. Environment variables take precedence over config file values.

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `TUN_DEVICE_NAME` | `tun0` | Name of the TUN interface to create (must not already exist). |
| `TUN_IP_ADDR` | `192.168.0.2` | IP address to assign to the TUN interface. |
| `TUN_NETMASK` | `255.255.255.0` | Network mask for the TUN interface. |
| `TUN_MTU` | `1500` | MTU for the TUN interface. Reduce for tunnels with overhead (e.g., `1420` for WireGuard). |
| `TCP_MSS` | `1460` | Maximum Segment Size to advertise during the TCP handshake. `MTU - 40` (IP+TCP headers). |
| `TCP_INITIAL_CWND` | `1` | Initial congestion window in MSS units. RFC 3390 allows up to 4, RFC 6928 allows up to 10. |
| `TCP_INITIAL_RTO_MS` | `1000` | Initial retransmission timeout in milliseconds. RFC 6298 recommends 1 second. |
| `TCP_MAX_RTO_MS` | `60000` | Maximum RTO (after backoff). RFC 6298 §2.5 requires at least 60 seconds. |
| `TCP_TIME_WAIT_MS` | `60000` | Duration of TIME_WAIT state in milliseconds. Standard is 2×MSL = 60s. |
| `TCP_BACKLOG` | `128` | Default accept queue length for `TcpListener`. |
| `TCP_RECV_BUF_SIZE` | `65536` | Receive buffer size per connection (bytes). This is the maximum advertised `rwnd`. |
| `TCP_SEND_BUF_SIZE` | `131072` | Send buffer size per connection (bytes). |
| `TCP_SACK_ENABLED` | `true` | Whether to advertise SACK support in the SYN option. |
| `TCP_WSCALE_ENABLED` | `true` | Whether to negotiate window scaling (RFC 1323). |
| `TCP_TIMESTAMPS_ENABLED` | `true` | Whether to negotiate TCP timestamps (RFC 1323). More accurate RTT, PAWS protection. |
| `LOG_LEVEL` | `info` | Logging verbosity. One of: `error`, `warn`, `info`, `debug`, `trace`. Use `trace` for full per-packet logging. |
| `LOG_FORMAT` | `text` | Log output format. One of: `text` (human-readable), `json` (for log aggregation). |

### Config File (`tcp-stack.toml`)

Place `tcp-stack.toml` in the working directory. All fields are optional (defaults shown).

```toml
[tun]
device_name = "tun0"
ip_addr     = "192.168.0.2"
netmask     = "255.255.255.0"
mtu         = 1500

[tcp]
mss                  = 1460
initial_cwnd_mss     = 1
initial_rto_ms       = 1000
max_rto_ms           = 60000
time_wait_ms         = 60000
backlog              = 128
recv_buf_size        = 65536
send_buf_size        = 131072
sack_enabled         = true
wscale_enabled       = true
timestamps_enabled   = true

[log]
level  = "info"
format = "text"
```

---

## Extended Debugging Guide

### Setting Log Verbosity

```bash
# See every packet, every state transition, every timer fire
LOG_LEVEL=trace ./target/release/tcp-stack

# See only TCP state machine transitions
LOG_LEVEL=debug ./target/release/tcp-stack 2>&1 | grep '\[tcp\]'

# See only errors and warnings
LOG_LEVEL=warn ./target/release/tcp-stack
```

### Reading Trace Logs

At `LOG_LEVEL=trace`, every incoming and outgoing packet is logged with its full header. The format is:

```
[tcp][ESTABLISHED] RX  seq=1001 ack=4001 len=512  flags=A   rwnd=65535
[tcp][ESTABLISHED] TX  seq=4001 ack=1513 len=1460 flags=A   rwnd=65024  cwnd=2920 ssthresh=65535
[tcp][ESTABLISHED] TX  seq=5461 ack=1513 len=1460 flags=A   rwnd=65024  cwnd=2920 ssthresh=65535
[tcp][ESTABLISHED] TIMER retransmit  seq=4001  rto=240ms
[tcp][ESTABLISHED] TX  seq=4001 ack=1513 len=1460 flags=A   rwnd=65024  cwnd=1460 ssthresh=1460
```

**Reading the fields:**
- `RX` / `TX` — received from peer / sent to peer
- `seq` — TCP sequence number of this segment's first byte
- `ack` — cumulative ACK: all bytes before this have been received
- `len` — payload bytes in this segment (0 for pure ACKs)
- `flags` — `S`=SYN, `A`=ACK, `F`=FIN, `R`=RST, `P`=PSH (e.g., `SA` = SYN-ACK)
- `rwnd` — advertised receive window (our side if TX, peer's side if RX)
- `cwnd` — our congestion window (bytes)
- `ssthresh` — current slow-start threshold

---

### Wireshark Display Filters for This Stack

Save these as Wireshark "Display Filter" bookmarks for fast switching during debugging.

```
# Only your stack's traffic
ip.addr == 192.168.0.2

# Only TCP traffic on your port
tcp.port == 8080

# Only TCP handshake packets
tcp.flags.syn == 1

# Only retransmissions (Wireshark detects these)
tcp.analysis.retransmission

# Only zero-window notifications
tcp.window_size == 0

# Only RST packets
tcp.flags.reset == 1

# Only FIN packets
tcp.flags.fin == 1

# Only ACKs without data (pure ACKs)
tcp.flags == 0x010 && tcp.len == 0

# Duplicate ACKs (fast retransmit trigger)
tcp.analysis.duplicate_ack

# Packets with SACK blocks
tcp.options.sack

# Show the TCP stream following one connection
Follow → TCP Stream (right-click any packet in the connection)
```

---

### Common Bugs and Fixes

This section documents the bugs that trip up almost every implementation in roughly the order you'll encounter them.

#### Bug: Ping works but the first `curl` always times out

**Symptom:** ICMP echo reply works, but TCP connections never establish. Wireshark shows your stack sending SYN-ACK, but the client sends a RST.

**Cause:** The Linux kernel is also attached to the same TUN interface and is sending a RST because *it* has no socket on port 8080. Your stack and the kernel race, and the kernel usually wins.

**Fix:**
```bash
# Drop all TCP traffic on port 8080 at the kernel level so only your stack responds
sudo iptables -A INPUT  -p tcp --dport 8080 -j DROP
sudo iptables -A OUTPUT -p tcp --sport 8080 -j DROP
# Clean up when done
sudo iptables -D INPUT  -p tcp --dport 8080 -j DROP
sudo iptables -D OUTPUT -p tcp --sport 8080 -j DROP
```

---

#### Bug: Connection establishes but `read()` returns 0 immediately

**Symptom:** The three-way handshake completes (ESTABLISHED in logs), but the first `read()` on the TcpStream returns 0 (EOF) without any data arriving.

**Cause A:** Your FIN handler in `SYN_RECEIVED` state is incorrectly transitioning to `CLOSE_WAIT` when it should be going to `ESTABLISHED`. Check: are you processing the final handshake ACK before checking for FIN?

**Cause B:** Your receive buffer is treating a segment with `PSH` flag as a control packet and discarding the payload. PSH is only a hint to flush to the application; it carries data normally.

**Fix:** In your state machine, always process the payload bytes *before* checking for FIN. Pseudocode:
```
if segment has ACK: advance SND.UNA
if segment has payload: add bytes to recv_buf
if segment has FIN: advance RCV.NXT by 1, transition to CLOSE_WAIT
```

---

#### Bug: Large file transfers corrupt data

**Symptom:** `sha256sum` of received file doesn't match. Corruption is deterministic (same bytes wrong every time) or non-deterministic (random failures).

**Cause A (deterministic):** Your receive buffer has an off-by-one in the reorder queue insertion or delivery logic. Bytes from the "wrong" segment are being delivered.

**Cause B (non-deterministic):** Race condition between your retransmit timer thread and your main receive loop — both touching `SND.UNA` without a lock.

**Diagnostic:**
```bash
# Send a known file and compare checksums
cat /usr/share/doc/bash/copyright | nc -l -p 9999 &
nc 192.168.0.2 9999 | sha256sum
sha256sum /usr/share/doc/bash/copyright
```

**Fix for B:** Ensure that `SND.UNA` advancement (in `process_ack`) and retransmit scheduling are both performed under the same `Mutex` guard.

---

#### Bug: Stack hangs after sending large amounts of data

**Symptom:** Throughput starts fine, then suddenly drops to zero. Logs show the send window (`min(cwnd, rwnd)`) is non-zero, but no segments are sent.

**Cause:** Zero-window situation — the peer has advertised `rwnd=0` and your stack correctly stopped sending. But your zero-window probe timer was never started (or fired and sent the probe, but the probe's ACK didn't update `peer_rwnd`).

**Fix:** 
1. Ensure `peer_rwnd` is updated on *every* incoming segment, not just data segments.
2. Ensure the zero-window probe timer is started whenever `peer_rwnd` transitions to 0.
3. Ensure the probe's ACK updates `peer_rwnd` even though the probe was out-of-window data.

```rust
// In process_segment(), always update peer_rwnd:
self.snd_wnd = segment.window_size;
if self.snd_wnd == 0 && !self.persist_timer_running {
    self.start_persist_timer();
}
```

---

#### Bug: `TIME_WAIT` connections accumulate and are never cleaned up

**Symptom:** After many connections, memory usage climbs. `LOG_LEVEL=debug` shows thousands of entries in `TIME_WAIT` state.

**Cause:** Your `TIME_WAIT` timer is not being scheduled, or the timer fires but doesn't remove the TCB from the connection table.

**Fix:** Use a min-heap (e.g., `BinaryHeap<Reverse<(Instant, FourTuple)>>`) ordered by expiry time. In your main event loop:
```rust
while let Some(&Reverse((expiry, four_tuple))) = time_wait_heap.peek() {
    if Instant::now() >= expiry {
        time_wait_heap.pop();
        connection_table.remove(&four_tuple);
    } else {
        break;
    }
}
```

---

#### Bug: Congestion window never grows beyond 1 MSS

**Symptom:** Throughput is terrible — stuck at ~1 segment per RTT. Logs show `cwnd=1460` every time.

**Cause:** Your slow-start logic is only incrementing `cwnd` on ACKs that advance `SND.UNA`, but it's checking `cwnd += MSS` after the increment — meaning you're computing the post-increment value and comparing it to `ssthresh` instead of the pre-increment value. Or: you're incrementing by `1` (byte) instead of `MSS` (bytes) per ACK.

**Fix (RFC 5681 §3.1 exact wording):**
```rust
// Slow start: for each ACK that advances SND.UNA
if self.cwnd < self.ssthresh {
    self.cwnd += self.mss; // +1 MSS per ACK in slow start
} else {
    // Congestion avoidance: +MSS² / cwnd per ACK
    self.cwnd += (self.mss * self.mss) / self.cwnd;
}
```

---

## Developer Workflow

### Recommended Development Loop

The most efficient way to develop and debug this stack:

```
Terminal 1: LOG_LEVEL=trace cargo run 2>&1 | tee /tmp/stack.log
Terminal 2: wireshark -i tun0 &
Terminal 3: # your test commands (ping, curl, nc, packetdrill)
Terminal 4: tail -f /tmp/stack.log | grep '\[tcp\]'
```

This setup gives you simultaneous visibility into: your stack's internal state (Terminal 4), the raw packet-level view (Terminal 2), and the full logs for post-mortem analysis (`/tmp/stack.log`).

---

### Adding a New Protocol (e.g., UDP)

The architecture is designed to make adding new Layer 4 protocols straightforward. Follow these steps:

**Step 1 — Register the protocol number in `ip.rs`:**

```rust
// In ip.rs:
pub enum IpProtocol {
    Icmp = 1,
    Tcp  = 6,
    Udp  = 17,  // ← add this
}
```

**Step 2 — Create `src/udp/mod.rs`:**

```rust
// Minimal UDP socket implementation
pub struct UdpSocket { ... }

impl UdpSocket {
    pub fn bind(addr: &str) -> Result<UdpSocket> { ... }
    pub fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> { ... }
    pub fn send_to(&self, buf: &[u8], addr: &str) -> Result<usize> { ... }
}
```

**Step 3 — Dispatch to your handler in `main.rs`:**

```rust
match ip_header.protocol {
    IpProtocol::Icmp => icmp::handle(payload, &mut tun)?,
    IpProtocol::Tcp  => tcp::handle(payload, src_ip, dst_ip, &mut table)?,
    IpProtocol::Udp  => udp::handle(payload, src_ip, dst_ip, &mut udp_table)?,  // ← add
    _                => { /* ignore */ }
}
```

**Step 4 — Write a packetdrill test:**

```
# tests/packetdrill/udp_echo.pkt
0   socket(..., SOCK_DGRAM, IPPROTO_UDP) = 3
+0  bind(3, ..., ...) = 0
+0  < udp [192.168.0.1:54321 > 192.168.0.2:5000] "hello\n"
+0  > udp [192.168.0.2:5000 > 192.168.0.1:54321] "hello\n"
```

---

### Writing a Packetdrill Test From Scratch

Packetdrill tests script the expected exchange of packets. Lines starting with `<` are *injected* (sent to your stack); lines starting with `>` are *expected* (must be sent by your stack).

```
# File: tests/packetdrill/my_test.pkt

# t=0: bind a listening socket
0    socket(..., SOCK_STREAM, IPPROTO_TCP) = 3
+0   bind(3, ..., ...) = 0
+0   listen(3, 1) = 0

# t=0: remote sends SYN
+0   < S  0:0(0) win 65535 <mss 1460,sackOK,nop,nop,wscale 7>

# Your stack must send SYN-ACK within 0 seconds (instantly)
+0   > S. 0:0(0) ack 1 <mss 1460,...>

# t=0.1s: remote ACKs the SYN-ACK
+.1  < .  1:1(0) ack 1 win 65535

# t=0.1s: remote sends 6 bytes of data
+0   < P. 1:7(6) ack 1 win 65535

# Your stack must ACK within 200ms
+.2  > .  ack 7

# Run the test:
# sudo packetdrill tests/packetdrill/my_test.pkt
```

**Timing rules:**
- Absolute time: `0`, `1`, `2.5` — seconds from start
- Relative time: `+0`, `+.1`, `+1.5` — seconds after previous line

---

### CI Pipeline

The GitHub Actions CI pipeline (`.github/workflows/ci.yml`) runs on every push and pull request:

```yaml
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy
      - name: fmt check
        run: cargo fmt --check
      - name: clippy (warnings as errors)
        run: cargo clippy -- -D warnings
      - name: unit tests
        run: cargo test --lib
      - name: doc tests
        run: cargo test --doc
      - name: build release
        run: cargo build --release
      - name: install packetdrill
        run: |
          git clone https://github.com/google/packetdrill
          cd packetdrill/gtests/net/packetdrill && ./configure && make && sudo make install
      - name: packetdrill integration tests
        run: |
          sudo ./target/release/tcp-stack &
          sleep 1
          for f in tests/packetdrill/*.pkt; do sudo packetdrill "$f"; done
```

To run the full CI suite locally:

```bash
# One-shot local CI equivalent
cargo fmt --check \
  && cargo clippy -- -D warnings \
  && cargo test \
  && cargo build --release \
  && echo "All checks passed"
```

---

## Security Considerations

This is a learning implementation and is **not suitable for production network traffic**. The following security properties are not implemented and are important to understand before deploying:

### ISN Randomization
RFC 793 requires that Initial Sequence Numbers (ISN) be hard to predict to prevent TCP hijacking. This implementation uses a simple random number from `rand::random::<u32>()`. A production stack should use a cryptographically secure ISN generator (e.g., `SipHash(key, src_ip, src_port, dst_ip, dst_port, timestamp)` per RFC 6528).

### SYN Flood Resistance
This stack maintains a full TCB for every incoming SYN, which means a SYN flood will exhaust memory. Production stacks use **SYN cookies** (RFC 4987) to handle this: encode the TCB into the SYN-ACK's ISN, deferring state allocation until the final ACK.

### RST Attack Validation
RFC 5961 tightens RST validation: a RST is only valid if its sequence number equals `RCV.NXT` exactly (not just within the receive window). Looser validation allows blind RST attacks. This stack implements the RFC 793 "within window" check; upgrading to RFC 5961 semantics is recommended.

### Half-open Connection Timeout
Without a timeout on connections in the `SYN_RECEIVED` state, an attacker can leave connections in that state indefinitely. Add a `syn_received_timeout` (typically 75 seconds) that sends a RST and removes the TCB if the final ACK never arrives.

### Checksum Verification
All IP and TCP checksums are verified on inbound packets. Segments with invalid checksums are silently dropped. This is correct per RFC 793.

---

## Performance Tuning

Once you have a working stack, here are the highest-impact knobs for improving throughput and latency.

### Increase Initial Congestion Window

RFC 6928 (2013) raises the recommended initial cwnd from 1 to 10 MSS, which dramatically improves performance for small HTTP responses:

```bash
TCP_INITIAL_CWND=10 ./target/release/tcp-stack
```

### Tune Buffer Sizes for High-BDP Links

For high-bandwidth, high-latency links (e.g., 1 Gbps, 100ms RTT), the bandwidth-delay product is:
```
BDP = 1,000,000,000 bits/s × 0.1 s / 8 = 12,500,000 bytes = ~12 MB
```
Your send and receive buffers must be at least `BDP` to keep the pipe full:

```bash
TCP_RECV_BUF_SIZE=16777216 TCP_SEND_BUF_SIZE=16777216 ./target/release/tcp-stack
```

### Use `writev`-style Batching in the Send Path

Instead of calling `tun_fd.write()` for every segment, batch multiple segments into a single `writev()` syscall. This reduces syscall overhead at high packet rates by 30–50%.

```rust
// Pseudocode: batch pending segments
let iov: Vec<IoVec<&[u8]>> = pending_segments
    .iter()
    .map(|seg| IoVec::from_slice(seg))
    .collect();
writev(&tun_fd, &iov)?;
```

### Profile Before Optimizing

Run `cargo flamegraph` before guessing:

```bash
cargo flamegraph --bin tcp-stack -- --iperf3-mode &
iperf3 -c 192.168.0.2 -t 30
```

Common hot paths (in order of typical impact):
1. **Checksum computation** — consider using SIMD (`std::arch`) or offloading to the kernel via `SO_NO_CHECK`
2. **Memory copies** — avoid copying payload bytes more than once between TUN read, receive buffer, and application
3. **Lock contention** — if multi-threaded, connection table sharding by 4-tuple hash

---

## Extended Contributing Guide

### Code Style

This project follows standard Rust conventions enforced by `rustfmt` and `clippy`:

```bash
# Auto-format all source files
cargo fmt

# Lint with all warnings as errors
cargo clippy -- -D warnings

# Check documentation coverage
cargo doc --no-deps --document-private-items
```

Specific style rules:
- All public items must have doc comments (`///`).
- Every RFC reference in the code must cite the exact section: `// RFC 793 §3.9`.
- Error types must be `#[non_exhaustive]` to allow future additions.
- Prefer `u32` for sequence numbers (matching RFC 793 notation), never `usize`.
- Use wrapping arithmetic (`wrapping_add`, `wrapping_sub`) for all sequence number comparisons.

---

### Branch Naming

| Branch prefix | Purpose | Example |
|---|---|---|
| `feat/` | New feature | `feat/udp-socket` |
| `fix/` | Bug fix | `fix/zero-window-probe` |
| `docs/` | Documentation only | `docs/congestion-control` |
| `bench/` | Benchmarks | `bench/throughput-writev` |
| `test/` | Test additions | `test/packetdrill-fast-recovery` |
| `refactor/` | Code restructuring without behavior change | `refactor/tcb-to-separate-module` |

---

### Pull Request Checklist

Before opening a PR, ensure the following:

- [ ] All existing tests pass: `cargo test`
- [ ] No new `clippy` warnings: `cargo clippy -- -D warnings`
- [ ] New behavior is covered by at least one unit test or packetdrill script
- [ ] RFC references are cited in relevant code comments (`// RFC 793 §3.9`)
- [ ] `CHANGELOG.md` has an entry under `[Unreleased]`
- [ ] Doc comments updated for any public API changes
- [ ] `README.md` updated if new features are user-visible

---

### Commit Message Format

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short description>

[optional body: explain the why, not the what]
[optional RFC reference: implements RFC 5681 §3.2]
```

**Types:** `feat`, `fix`, `docs`, `test`, `bench`, `refactor`, `chore`  
**Scopes:** `tun`, `ethernet`, `arp`, `ip`, `icmp`, `tcp`, `api`, `ci`, `deps`

**Examples:**
```
feat(tcp): implement fast retransmit on 3 duplicate ACKs

On receipt of the third duplicate ACK for a given sequence number,
immediately retransmit the oldest unACKed segment without waiting
for the RTO. This implements RFC 5681 §3.2.

fix(tcp): wrap sequence number comparison with wrapping_sub

Sequence numbers wrap at 2^32. Using plain subtraction caused
incorrect SND.UNA advancement when wrapping occurred, leading
to data corruption on long-lived high-throughput connections.

docs(congestion): add ASCII diagram of cwnd evolution through phases
```

---

### Adding Packetdrill Tests for Edge Cases

Good packetdrill tests cover these edge cases (currently missing — great first contributions):

```bash
tests/packetdrill/
├── simultaneous_close.pkt       # both sides send FIN simultaneously
├── rst_in_syn_received.pkt      # RST while in SYN_RECEIVED
├── data_after_fin.pkt           # data arrives after FIN (should be ignored)
├── ack_beyond_snd_nxt.pkt       # ACK for unsent data (must RST)
├── window_shrink.pkt            # peer shrinks window mid-connection
├── persist_timer.pkt            # zero-window probe behavior
├── sack_recovery.pkt            # selective retransmit via SACK
├── time_wait_reuse.pkt          # reject duplicate SYN during TIME_WAIT
└── large_options.pkt            # TCP options padding to 4-byte boundary
```

---

## Deeper Technical Notes

### Why Sequence Numbers Are 32-Bit and Wrap

RFC 793 defines sequence numbers as unsigned 32-bit integers. This means they wrap at 2³² = 4,294,967,296 bytes (~4 GB). At 1 Gbps, a sequence number space wraps in about 34 seconds. On a 10 Gbps link, it wraps in 3.4 seconds.

This is why sequence number comparisons must use **modular arithmetic**:

```rust
// WRONG: doesn't handle wrapping
if seq > snd_una { ... }

// CORRECT: wrapping comparison (from RFC 793 Appendix)
fn seq_gt(a: u32, b: u32) -> bool {
    // a > b in sequence number space
    (a.wrapping_sub(b) as i32) > 0
}
```

RFC 1323 timestamps (PAWS) protect against old segments from a previous incarnation of the connection arriving after a sequence number wrap.

---

### Why ISN Must Be Random

If ISN were always 0, an attacker on a shared network could predict the sequence number of a connection they didn't initiate and inject forged segments. RFC 6528 recommends:

```
ISN = F(local_ip, local_port, remote_ip, remote_port, secret_key) + clock_counter
```

where `F` is a cryptographic PRF (e.g., SipHash-2-4) and `clock_counter` increments at ~250,000 per second (roughly following the original RFC 793 recommendation of incrementing every 4µs).

---

### The Silly Window Syndrome

**Silly Window Syndrome (SWS)** occurs when small windows lead to very small segments, wasting bandwidth on headers.

**Sender-side SWS avoidance (Nagle's algorithm, RFC 896):** Don't send a new segment unless:
1. The segment is a full MSS, OR
2. There is no unACKed data in flight (the pipe is empty)

This coalesces many small `write()` calls into fewer, larger segments.

**Receiver-side SWS avoidance (Clark's algorithm):** Don't advertise a small window update. Only send a window update when your available buffer increases by at least `min(MSS, half of maximum receive buffer)`.

This stack currently doesn't implement Nagle (sends immediately). This is correct but inefficient. See [Roadmap](#roadmap).

---

### The RTT Estimation Algorithm (Jacobson/Karels)

From Van Jacobson's 1988 paper, the algorithm that replaced the original RFC 793 "smoothed RTT" estimate:

```
# On each new RTT measurement M:
Error  = M - SRTT
SRTT   = SRTT + g × Error          # g = 1/8
RTTVAR = RTTVAR + h × (|Error| - RTTVAR)  # h = 1/4
RTO    = SRTT + 4 × RTTVAR

# In Rust:
let error = m - self.srtt;
self.srtt   += error / 8.0;
self.rttvar += (error.abs() - self.rttvar) / 4.0;
self.rto = Duration::from_secs_f64(self.srtt + 4.0 * self.rttvar)
    .max(Duration::from_millis(200))   // floor: RFC 6298
    .min(Duration::from_secs(60));     // ceiling: RFC 6298
```

The key insight: `RTTVAR` measures RTT variance. On a jittery network, the variance is high, so `RTO` gets a larger safety margin. On a stable LAN, variance is low, so `RTO` tracks `SRTT` tightly.

**Do not sample RTT for retransmitted segments** (Karn's Algorithm, RFC 6298 §4): you don't know whether the ACK is for the original or the retransmission. Only sample RTT for segments that were sent exactly once.

---

### TCP Header Option Encoding

TCP options are encoded in the 20–60 byte options field (IHL > 5) using a type-length-value (TLV) format, with two single-byte special cases:

```
Kind=0  NOP (no operation — used for padding to 32-bit boundary)
Kind=1  EOL (end of options list)
Kind=2  MSS               [kind=2][len=4][mss_value: u16]
Kind=3  Window Scale      [kind=3][len=3][shift_count: u8]
Kind=4  SACK Permitted    [kind=4][len=2]
Kind=5  SACK              [kind=5][len=N][left_edge: u32][right_edge: u32]...
Kind=8  Timestamps        [kind=8][len=10][tsval: u32][tsecr: u32]
```

**Critical implementation detail:** Options must be padded to a 4-byte boundary using NOP bytes (kind=1). Failing to pad will corrupt the TCP header, because the Data Offset field specifies the header length in 32-bit words.

```rust
// Encoding MSS + window scale + SACK permitted + NOP padding
let options: Vec<u8> = vec![
    2, 4, (mss >> 8) as u8, mss as u8,       // MSS
    3, 3, wscale, 0,                           // window scale + NOP pad
    4, 2,                                      // SACK permitted
    0, 0,                                      // two NOPs to reach 4-byte boundary
    // Total: 12 bytes = 3 words → IHL = 5 + 3 = 8
];
```

---

### The TIME_WAIT Assassination Hazard

There is a subtle edge case (RFC 1337 — "TIME-WAIT Assassination Hazards") where a late-arriving RST segment can prematurely kill a TIME_WAIT connection, potentially corrupting a new connection on the same 4-tuple.

**The fix:** Ignore RST segments received in the TIME_WAIT state. A RST in TIME_WAIT can only be a delayed segment from the closed connection, not a legitimate reset request from a new connection (because the new connection hasn't been established yet).

```rust
TcpState::TimeWait => {
    if segment.flags.rst {
        // RFC 1337: ignore RSTs in TIME_WAIT
        return Ok(());
    }
    // Handle duplicate FIN retransmission, otherwise ignore
}
```

---

## Roadmap

> This section tracks the planned evolution of `tcp-stack` beyond the v1.0.0 curriculum milestone. Items are ordered by educational value and implementation difficulty. Community contributions on any of these are welcome — see [Contributing](#contributing).

### Near-Term (v1.1.x)

#### Nagle's Algorithm (RFC 896)
Nagle's algorithm coalesces small writes to avoid the "small-packet problem" — sending many tiny segments wastes header bandwidth when a single large segment would suffice.

**Implementation sketch:**
```rust
fn should_send_now(&self, payload_len: usize) -> bool {
    // Case 1: segment is full-sized (MSS)
    if payload_len >= self.mss { return true; }
    // Case 2: no unacknowledged data in flight (pipe is idle)
    if self.snd_una == self.snd_nxt { return true; }
    // Otherwise: buffer and wait for ACK or full segment
    false
}
```

Toggle with a `tcp_nodelay` flag (equivalent to `TCP_NODELAY` socket option). Interactive applications (SSH, telnet) always set `TCP_NODELAY=true`.

---

#### `SO_REUSEADDR` / `SO_REUSEPORT` (TIME_WAIT Recycling)

Without `SO_REUSEADDR`, a server that crashes and restarts cannot rebind its port for 2×MSL (up to 60 seconds) because the old connection is in `TIME_WAIT`. This is one of the most common "why can't I restart my server?" errors.

**Implementation:** When `SO_REUSEADDR` is set on a `TcpListener`, allow binding to a port that has connections in `TIME_WAIT`. When a new `SYN` arrives on a TIME_WAIT 4-tuple with a sequence number beyond the `TIME_WAIT` connection's, accept it as a new connection and immediately destroy the TIME_WAIT entry.

---

#### TCP Fast Open (RFC 7413)
TCP Fast Open (TFO) eliminates one full RTT for repeat connections by piggybacking application data onto the SYN packet, using a cryptographic cookie to authenticate the client.

Without TFO:
```
Client → SYN             (RTT 1 start)
Server → SYN-ACK
Client → ACK + GET /     (RTT 1 end — first data sent on 3rd packet)
Server → 200 OK
```

With TFO:
```
Client → SYN + GET /     (data in SYN itself)
Server → SYN-ACK + 200 OK
Client → ACK
```

Net savings: one full RTT on every cached connection.

---

#### SACK-Based Selective Retransmission (RFC 2018)
The current implementation retransmits from `SND.UNA` on any loss signal (go-back-N). SACK allows the receiver to describe exactly which ranges of sequence numbers it has received, so the sender can retransmit *only* what was actually lost.

```
Receiver's SACK block: [1001–2001) [3001–4001)
↓ means the receiver has: 1001–2001 and 3001–4001
↓ and is missing: 0–1001 and 2001–3001
↓ sender retransmits ONLY: 0–1001 and 2001–3001
```

This is especially valuable on lossy links where multiple segments are lost in a single window.

---

### Medium-Term (v1.2.x)

#### UDP (RFC 768)
UDP is a thin layer over IP — no connection, no reliability, no ordering. Just a port number, checksum, and payload. An excellent extension because it shares the IP and Ethernet layers you've already built.

| Feature | TCP | UDP |
|---|---|---|
| Connection | Yes (handshake) | No (stateless) |
| Reliability | Yes (retransmit) | No |
| Ordering | Yes (sequence numbers) | No |
| Flow control | Yes (rwnd) | No |
| Overhead | 20+ bytes/segment | 8 bytes/datagram |
| Use case | HTTP, SSH, FTP | DNS, video, gaming |

RFC 768 is only 3 pages. This is a one-week extension.

---

#### ICMP Destination Unreachable + Path MTU Discovery (RFC 1191)
When a router cannot forward a packet because it exceeds the link's MTU, it sends an ICMP "Destination Unreachable, Fragmentation Needed" message back to the source. TCP should react by reducing its MSS.

```
Your stack sends 1500-byte segment
   ↓
Router on path has 1400-byte MTU
   ↓
Router drops segment, sends ICMP Type=3 Code=4 (Fragmentation Needed, next-hop MTU = 1400)
   ↓
Your stack receives ICMP, reduces MSS to 1360 (1400 - 40 bytes headers)
   ↓
Retransmit at 1360-byte MSS — now it fits
```

---

#### DNS Resolver (RFC 1035)
A minimal DNS resolver over UDP lets you connect to hostnames instead of raw IPs. This makes your stack actually usable: `curl http://example.com/` instead of `curl http://93.184.216.34/`.

A minimal stub resolver only needs to:
1. Send a DNS query (UDP to port 53)
2. Parse the response (A record → IPv4 address)
3. Cache the result with the TTL

---

### Long-Term (v2.0 — Major Extensions)

#### IPv6 (RFC 8200)
IPv6 replaces 32-bit IP addresses with 128-bit addresses and removes IP fragmentation from routers (only the source can fragment). Key differences from IPv4:

| Feature | IPv4 | IPv6 |
|---|---|---|
| Address length | 32 bits | 128 bits |
| Header length | Variable (options) | Fixed 40 bytes + extension headers |
| Fragmentation | Any router | Source only |
| Checksum | Yes (IP header) | No (removed) |
| Broadcast | Yes | No (multicast instead) |
| ARP | Yes | No (replaced by NDP) |

NDP (Neighbor Discovery Protocol) replaces ARP. It uses ICMPv6 messages instead of a dedicated protocol.

---

#### QUIC (RFC 9000)
QUIC is a UDP-based transport protocol developed by Google (and now IETF-standardized) that provides TCP-like reliability with improvements: 0-RTT connection establishment, built-in TLS 1.3, independent stream multiplexing (no head-of-line blocking).

Understanding QUIC requires a solid foundation in TCP internals — which is exactly what this project provides. After completing the 12-week curriculum, QUIC will read as "TCP but redesigned with 30 years of hindsight."

Key RFC reading: RFC 9000 (QUIC transport), RFC 9001 (QUIC-TLS), RFC 9002 (QUIC loss detection and congestion control).

---

#### TLS 1.3 Integration (RFC 8446)
Wrapping your `TcpStream` with a TLS layer is the next step after a working socket API. A minimal TLS 1.3 handshake (using `rustls` for the crypto) would let your stack serve `https://` — the actual internet protocol.

```rust
// After your TcpStream is ESTABLISHED:
let config = rustls::ServerConfig::builder()
    .with_no_client_auth()
    .with_single_cert(certs, key)?;
let conn = rustls::ServerConnection::new(Arc::new(config))?;
let mut tls_stream = rustls::Stream::new(&mut conn, &mut tcp_stream);
tls_stream.write_all(b"HTTP/1.1 200 OK\r\n\r\nHello TLS!")?;
```

---

#### BBR Congestion Control (Google, 2016)
CUBIC (the current Linux default) is loss-based: it assumes packet loss = congestion. BBR (Bottleneck Bandwidth and RTT) is model-based: it estimates the bottleneck bandwidth and the minimum RTT, and controls its rate directly rather than reacting to loss.

BBR is significantly more performant on high-bandwidth, long-RTT paths (transoceanic links) and in environments with shallow buffers (mobile networks). Understanding it requires a solid AIMD foundation — which you'll have after Week 8.

---

## Extended API Reference

This section provides complete, runnable examples of every public API surface in `tcp-stack`. All examples assume you have a running stack instance and the TUN device is configured.

### `TcpListener`

```rust
use tcp_stack::TcpListener;
use std::io::{Read, Write};

fn main() -> std::io::Result<()> {
    // Bind to a local address on your TUN IP
    let listener = TcpListener::bind("192.168.0.2:8080")?;

    println!("Listening on 192.168.0.2:8080");

    // Accept connections in a loop — each accept() blocks until a new
    // ESTABLISHED connection is dequeued from the backlog
    loop {
        let (mut stream, peer_addr) = listener.accept()?;
        println!("Connection from {}", peer_addr);

        // Handle the connection — in production, spawn a thread here
        handle_connection(&mut stream)?;
    }
}

fn handle_connection(stream: &mut tcp_stack::TcpStream) -> std::io::Result<()> {
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf)?;

    let request = std::str::from_utf8(&buf[..n]).unwrap_or("<binary>");
    println!("Received: {}", &request[..request.len().min(80)]);

    let response = b"HTTP/1.0 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!";
    stream.write_all(response)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    Ok(())
}
```

---

### `TcpStream` — Full Read/Write Loop

```rust
use tcp_stack::TcpStream;
use std::io::{BufRead, BufReader, Write};

fn echo_server() -> std::io::Result<()> {
    let listener = tcp_stack::TcpListener::bind("192.168.0.2:7")?;  // RFC 862: echo port
    loop {
        let (stream, addr) = listener.accept()?;
        println!("[echo] connected: {}", addr);

        let mut reader = BufReader::new(stream.try_clone()?);
        let mut writer = stream;

        // Echo every line back to the sender
        let mut line = String::new();
        loop {
            line.clear();
            let n = reader.read_line(&mut line)?;
            if n == 0 { break; }  // EOF (FIN received)
            writer.write_all(line.as_bytes())?;
        }
        println!("[echo] connection closed: {}", addr);
    }
}
```

---

### `TcpStream::set_read_timeout` — Non-Blocking with Timeout

```rust
use std::time::Duration;
use tcp_stack::TcpStream;

fn with_timeout(mut stream: TcpStream) -> std::io::Result<()> {
    // Wait at most 5 seconds for the peer to send data
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;

    let mut buf = vec![0u8; 65536];
    match stream.read(&mut buf) {
        Ok(0) => println!("Connection closed by peer"),
        Ok(n) => println!("Received {} bytes", n),
        Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {
            println!("No data received within 5s — closing");
        }
        Err(e) => return Err(e),
    }
    Ok(())
}
```

---

### Concurrent Connections with `std::thread`

The event loop in `tcp-stack` is single-threaded (see [Known Limitations](#known-limitations)), but you can handle multiple connections concurrently by dispatching each accepted stream to a worker thread:

```rust
use std::thread;
use tcp_stack::TcpListener;

fn threaded_server() -> std::io::Result<()> {
    let listener = TcpListener::bind("192.168.0.2:8080")?;

    for (mut stream, addr) in listener.incoming() {
        let stream = stream?;
        thread::spawn(move || {
            println!("[worker] handling {}", addr);
            if let Err(e) = handle(stream) {
                eprintln!("[worker] error from {}: {}", addr, e);
            }
        });
    }
    Ok(())
}

fn handle(mut stream: tcp_stack::TcpStream) -> std::io::Result<()> {
    // ... your handler
    Ok(())
}
```

> **Note:** `TcpListener::incoming()` is a convenience iterator that calls `accept()` in a loop, yielding `Result<TcpStream>`.

---

### Building an HTTP/1.1 Echo Server

```rust
use std::io::{BufRead, BufReader, Write};
use tcp_stack::{TcpListener, TcpStream};

fn http_echo_server() -> std::io::Result<()> {
    let listener = TcpListener::bind("192.168.0.2:8080")?;
    println!("HTTP echo server at http://192.168.0.2:8080/");

    for stream in listener.incoming() {
        let mut stream = stream?;
        if let Err(e) = handle_http(&mut stream) {
            eprintln!("HTTP error: {}", e);
        }
    }
    Ok(())
}

fn handle_http(stream: &mut TcpStream) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    
    // Read request line
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    
    // Read headers (until blank line)
    let mut content_length = 0usize;
    let mut headers_done = false;
    while !headers_done {
        let mut header = String::new();
        reader.read_line(&mut header)?;
        if header == "\r\n" { headers_done = true; }
        if header.to_lowercase().starts_with("content-length:") {
            content_length = header.split(':').nth(1)
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0);
        }
    }
    
    // Read body
    let mut body = vec![0u8; content_length];
    std::io::Read::read_exact(&mut reader, &mut body)?;
    
    // Echo back as JSON
    let response_body = format!(
        "{{\"method\": \"{}\", \"body\": \"{}\"}}",
        request_line.split_whitespace().next().unwrap_or("?"),
        String::from_utf8_lossy(&body)
    );
    
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        response_body.len(),
        response_body
    );
    stream.write_all(response.as_bytes())?;
    Ok(())
}
```

---

## Performance Tuning Guide

Once your stack is functionally correct (all packetdrill tests pass), this section shows how to systematically improve throughput and latency.

### Step 1 — Profile First

Never optimize without data. Generate a flamegraph before and after every change:

```bash
# Install flamegraph tool
cargo install flamegraph

# Run a throughput benchmark under perf
sudo cargo flamegraph --bin tcp-stack -- --iperf3-mode

# Open flamegraph.svg in a browser and look for the widest frames
```

Common hot spots in a first-iteration userspace TCP stack:

| Hot Spot | Typical % of CPU | Fix |
|---|---|---|
| One's complement checksum | 30–40% | Use `crc32` hardware instruction via `std::arch` or `checksum` crate |
| `memcpy` in send/receive buffer | 20–30% | Zero-copy with `IoSlice` / `writev` system call |
| `HashMap` connection table lookup | 10–20% | Pre-hash the 4-tuple; consider `AHashMap` |
| Timer management (`BinaryHeap`) | 5–10% | Hierarchical timing wheel (see below) |
| Per-packet allocation | 5–15% | Pool allocator for `Vec<u8>` buffers |

---

### Step 2 — Hardware Checksum Offload

The one's complement checksum is computed on every segment. On a 1 Gbps link with 1460-byte segments, you're checksumming ~860,000 segments per second — about 700 MB/s of data.

```rust
// Naive Rust implementation (scalar)
fn checksum_scalar(data: &[u8]) -> u16 {
    let mut sum: u32 = data.chunks(2)
        .map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]) as u32)
        .sum();
    while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16); }
    !(sum as u16)
}

// Optimized: process 8 bytes at a time (compiler will auto-vectorize with -C target-cpu=native)
#[target_feature(enable = "avx2")]
unsafe fn checksum_avx2(data: &[u8]) -> u16 {
    // Process 32 bytes per iteration using 256-bit AVX2 registers
    // (implementation left as an exercise — see the `checksum` crate for reference)
    checksum_scalar(data)  // fallback
}
```

Build with `-C target-cpu=native` to enable auto-vectorization:
```toml
# .cargo/config.toml
[target.x86_64-unknown-linux-gnu]
rustflags = ["-C", "target-cpu=native"]
```

---

### Step 3 — Zero-Copy Receive Path

The default implementation copies bytes from the TUN buffer into a per-connection receive buffer, and again when the application calls `read()`. This is two copies per segment. Eliminate one:

```rust
// BEFORE: two copies
// TUN buffer → recv_buf.data Vec<u8> → app buffer
let n = tun_fd.read(&mut tun_buf)?;
recv_buf.push_back(&tun_buf[payload_offset..n]);  // copy 1
stream.read(&mut app_buf)?;                        // copy 2

// AFTER: one copy using IoSlice
// TUN buffer → app buffer (via writev-style interface)
// Only possible if the receive buffer is contiguous and the app reads quickly enough
```

For educational purposes, the two-copy path is clearer. Profile to confirm this is actually your bottleneck before optimizing.

---

### Step 4 — Hierarchical Timing Wheel

The default retransmit timer implementation uses `BinaryHeap<(Instant, ConnId)>`. This is `O(log N)` per timer operation. With 10,000 simultaneous connections, each firing a retransmit timer every ~200ms, that's 50,000 `O(log 10000)` heap operations per second — fine for educational use, but a production stack uses a **hierarchical timing wheel**.

```
A 3-level timing wheel (1ms / 100ms / 10s buckets):

Level 0: 100 buckets, 1ms each  → covers 0–100ms
Level 1: 100 buckets, 100ms each → covers 0–10s
Level 2: 100 buckets, 10s each  → covers 0–1000s

Insert: O(1) — hash timer into bucket based on expiry
Expire: O(1) amortized — advance hand pointer, process current bucket
```

This is how Linux's `timer_wheel` works internally. The `tokio` runtime uses a similar structure.

---

### Step 5 — Batch Syscalls with `sendmmsg` / `recvmmsg`

Linux 2.6.33+ provides `sendmmsg(2)` and `recvmmsg(2)` — system calls that send/receive multiple messages in a single kernel transition. Replacing individual `write()` calls with `sendmmsg()` can reduce syscall overhead by 4–8× at high packet rates.

```rust
// Using nix crate for recvmmsg
use nix::sys::socket::{recvmmsg, MsgFlags};

let mut msgs: Vec<RecvMmsgData> = (0..32).map(|_| {
    RecvMmsgData { iov: [IoSliceMut::new(&mut [0u8; 1504])], cmsg_buffer: [] }
}).collect();

let received = recvmmsg(tun_fd, &mut msgs, MsgFlags::MSG_DONTWAIT, None)?;
// Process all `received` packets in a tight loop before yielding back to epoll
```

---

### Throughput Optimization Checklist

Work through these in order — each is a potential 2–10× improvement over the naive implementation:

- [ ] Compile with `--release` and `target-cpu=native`
- [ ] Enable link-time optimization: `lto = "thin"` in `Cargo.toml [profile.release]`
- [ ] Profile with `cargo flamegraph` — find actual bottleneck before guessing
- [ ] Verify checksum computation is vectorized (check assembly with `cargo asm`)
- [ ] Replace `HashMap` with `AHashMap` (non-cryptographic hash, ~2× faster for short keys)
- [ ] Batch TUN reads with `recvmmsg` (reduces syscall overhead)
- [ ] Tune TCP buffer sizes: `TCP_RECV_BUF_SIZE` and `TCP_SEND_BUF_SIZE` in environment
- [ ] Enable window scaling (`TCP_WSCALE_ENABLED=true`) to allow windows > 65535 bytes
- [ ] Profile allocations with `heaptrack` — eliminate per-packet heap alloc if present
- [ ] Implement TCP segmentation offload simulation for large writes (send up to `cwnd` in one burst before waiting for ACK)

---

## Platform-Specific Notes

### Linux (Primary Platform)

The full feature set is supported on any Linux kernel 3.x or newer with TUN/TAP compiled in (virtually all distributions).

**Ubuntu / Debian setup:**
```bash
sudo apt-get update
sudo apt-get install -y build-essential iproute2 tcpdump wireshark-qt \
    netcat-openbsd iperf3 linux-tools-generic

# Verify TUN support
ls /dev/net/tun && echo "TUN available" || echo "TUN not found"
modinfo tun  # confirm module is loadable
```

**Fedora / RHEL / CentOS:**
```bash
sudo dnf install -y iproute tcpdump wireshark nmap-ncat iperf3 perf
# tun module is loaded on first use — no explicit install needed
```

**Arch Linux:**
```bash
sudo pacman -S iproute2 tcpdump wireshark-qt gnu-netcat iperf3 perf
```

**Granting `CAP_NET_ADMIN` without running as root (preferred):**
```bash
# After each `cargo build --release`:
sudo setcap cap_net_admin=eip target/release/tcp-stack

# Verify the capability was set:
getcap target/release/tcp-stack
# Should output: target/release/tcp-stack = cap_net_admin+eip
```

Note: `setcap` must be re-run after every recompile, because building a new binary clears capabilities. Add this to a `Makefile` or `build.rs` post-build hook:
```makefile
# Makefile
.PHONY: run
run: build
    sudo setcap cap_net_admin=eip target/release/tcp-stack
    ./target/release/tcp-stack

build:
    cargo build --release
```

---

### macOS

macOS does not have `/dev/net/tun`. Instead it exposes `utun` devices via a different `ioctl` interface. Use the [`tun`](https://crates.io/crates/tun) crate which abstracts both:

```toml
# Cargo.toml
[dependencies]
tun = { version = "0.6", features = ["async"] }
```

```rust
// src/tun.rs — platform-independent TUN open
#[cfg(target_os = "linux")]
pub fn open_tun(name: &str) -> std::io::Result<std::fs::File> {
    // Linux: open /dev/net/tun with ioctl(IFF_TUN | IFF_NO_PI)
    crate::tun_linux::open(name)
}

#[cfg(target_os = "macos")]
pub fn open_tun(name: &str) -> std::io::Result<std::fs::File> {
    // macOS: open /dev/utunN via CTLIOCGINFO + connect()
    crate::tun_macos::open(name)
}
```

**macOS-specific caveats:**
- Requires at least macOS 10.15 (Catalina) for stable `utun` support.
- The `utun` interface name is assigned by the kernel — you cannot choose `tun0`. Check the assigned name with `ifconfig utun0` after opening.
- `CAP_NET_ADMIN` does not exist on macOS. You must run as root (`sudo`) to open a `utun` device.
- Wireshark on macOS captures `utun` interfaces correctly — filter with `ip.addr == 192.168.0.2`.

---

### Windows Subsystem for Linux 2 (WSL2)

WSL2 runs a real Linux kernel, so TUN support works — but with caveats from the WSL2 NAT layer.

**Enable TUN in WSL2:**
```bash
# Check if tun module is present
lsmod | grep tun

# If not present, load it
sudo modprobe tun

# Verify /dev/net/tun exists
ls -la /dev/net/tun
```

**Known WSL2 limitations:**
- The WSL2 virtual machine is on a private network behind a NAT. Packets sent from your TUN device to `192.168.0.2` are visible from other processes *inside* WSL2, but not from the Windows host or external machines.
- `ping 192.168.0.2` from a Windows terminal (PowerShell/cmd) will not work — WSL2's network namespace is isolated. Run `ping 192.168.0.2` from *inside* WSL2 instead.
- Wireshark on Windows cannot capture the WSL2 `tun0` interface. Install Wireshark inside WSL2 with `sudo apt-get install wireshark`, or use `tcpdump` in WSL2: `sudo tcpdump -i tun0 -w /tmp/capture.pcap`.
- Some WSL2 kernel versions have a bug where `ioctl(TUNSETIFF)` returns `EPERM` even with `sudo`. Upgrade to WSL2 kernel 5.15+ to resolve: `wsl --update` in PowerShell.

---

### Docker / Container Environments

Running inside a Docker container requires the `NET_ADMIN` capability:

```bash
# Build and run with NET_ADMIN
docker run --cap-add=NET_ADMIN --device=/dev/net/tun:/dev/net/tun \
    -it rust:latest bash

# Inside the container:
git clone https://github.com/Mannava-Daasaradhi/tcp-stack
cd tcp-stack && cargo build --release
./target/release/tcp-stack
```

Or in a `docker-compose.yml`:
```yaml
services:
  tcp-stack-dev:
    image: rust:latest
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/net/tun:/dev/net/tun
    volumes:
      - .:/app
    working_dir: /app
    command: bash
```

---

### GitHub Codespaces / Cloud Dev Environments

Codespaces runs on a Linux VM with full kernel access. TUN support is available by default.

```bash
# In a Codespaces terminal — no special setup needed beyond:
sudo apt-get install -y iproute2 tcpdump
cargo build --release
sudo setcap cap_net_admin=eip target/release/tcp-stack
./target/release/tcp-stack
```

Wireshark GUI is not available in Codespaces. Use `tcpdump` instead:
```bash
sudo tcpdump -i tun0 -n -X &
```

---

## Comparison with Other Implementations

Understanding where this project fits in the ecosystem of TCP/IP implementations helps you choose the right tool for your use case and gives you context for what "production-grade" looks like.

### Feature Comparison Matrix

| Feature | `tcp-stack` (this project) | smoltcp | lwIP | Linux kernel TCP |
|---|---|---|---|---|
| **Language** | Rust | Rust | C | C |
| **Target environment** | Linux userspace (learning) | Embedded / no_std | Embedded / RTOS | Linux kernel |
| **IPv4** | ✅ | ✅ | ✅ | ✅ |
| **IPv6** | ❌ (roadmap) | ✅ | ✅ | ✅ |
| **TCP** | ✅ | ✅ | ✅ | ✅ |
| **UDP** | ❌ (roadmap) | ✅ | ✅ | ✅ |
| **DHCP** | ❌ | ✅ | ✅ | Via `dhclient` |
| **DNS** | ❌ (roadmap) | ❌ | ✅ | Via `glibc` resolver |
| **TLS** | ❌ (roadmap) | Via `embedded-tls` | Via `mbedTLS` | Via OpenSSL |
| **SACK** | ✅ (basic) | ✅ | ✅ | ✅ (full) |
| **Fast retransmit** | ✅ | ✅ | ✅ | ✅ |
| **Nagle** | ❌ (roadmap) | ✅ | ✅ | ✅ |
| **ECN** | ❌ | ❌ | Partial | ✅ |
| **BBR** | ❌ (roadmap) | ❌ | ❌ | ✅ (CUBIC default) |
| **RFC 5961** | Partial | ✅ | Partial | ✅ |
| **`async` API** | ❌ (roadmap) | ✅ | N/A | Via `io_uring` |
| **Documentation quality** | Inline RFC cites | Good | C comments | Kernel docs |
| **Educational value** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| **Production readiness** | ⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |

### Key Architectural Differences from smoltcp

[smoltcp](https://github.com/smoltcp-rs/smoltcp) is the closest cousin to this project — a pure-Rust userspace TCP/IP stack. The major differences:

**smoltcp design philosophy:** Designed for embedded systems (`no_std`). Zero heap allocation. All buffers are statically sized. The interface is poll-based (you call `iface.poll()` on each iteration, not event-driven).

**tcp-stack design philosophy:** Designed for learning on Linux. Heap allocation allowed. Event-driven (epoll-backed). RFC citations inline in the code. Verbose logging designed to be read while debugging.

Reading smoltcp's source after completing this project is an excellent exercise — you'll recognize every data structure and function name, but see production-grade edge cases and optimizations you haven't implemented yet.

---

## What You'll Be Able to Explain After This Project

The goal of this curriculum is not just a working binary. It's the ability to answer — confidently and in technical depth — the questions that separate senior engineers from junior ones. Here are 20 questions you'll be able to answer after completing all 12 weeks.

### System Design Questions

**Q: "Walk me through what happens when I type `curl https://example.com`."**

After this project, a complete answer covers: DNS resolution → TCP handshake (SYN/SYN-ACK/ACK) → TLS handshake → HTTP request → HTTP response → TCP teardown (FIN/ACK). You'll be able to describe every field of every packet at every step, including which RFC specifies each behavior.

---

**Q: "How does TCP ensure reliable delivery over an unreliable network?"**

Sequence numbers identify every byte. The receiver acknowledges cumulative bytes received. Unacknowledged bytes are retransmitted after RTO expires (Jacobson/Karels timer). Fast retransmit fires after 3 duplicate ACKs without waiting for RTO. SACK allows selective retransmission of only lost segments.

---

**Q: "What is TCP flow control? How is it different from congestion control?"**

Flow control (RFC 793 §3.5) prevents the sender from overwhelming the *receiver's buffer* — implemented via the advertised receive window (`rwnd`). Congestion control (RFC 5681) prevents the sender from overwhelming the *network* — implemented via the congestion window (`cwnd`). The sender's actual limit is `min(rwnd, cwnd)`. Flow control is end-to-end (between the two endpoints). Congestion control is global (between the sender and the network as a whole).

---

**Q: "Why does TIME_WAIT exist? Why is it 2×MSL and not shorter?"**

TIME_WAIT prevents two problems: (1) The final ACK of the FIN handshake might get lost, causing the peer to retransmit their FIN. We need to stay alive for 1 MSL to handle this retransmit. (2) Old delayed packets from the now-closed connection might still be in flight on the network. We hold the 4-tuple hostage for another 1 MSL to ensure those packets expire before a new connection could reuse the same 4-tuple. Total: 2×MSL.

---

**Q: "What is the three-way handshake and why does it need to be three-way, not two-way?"**

The handshake establishes two independent sequence number spaces — one for each direction. A two-way handshake (SYN → SYN-ACK) would establish the client→server direction but never confirm the server→client direction. The client's final ACK confirms that the server's sequence number was received. Without it, the server doesn't know the client received its SYN-ACK (and thus its ISN), so the server can't confirm its transmit path is working.

---

### Debugging / Troubleshooting Questions

**Q: "A server has thousands of sockets in TIME_WAIT. What's happening and how do you fix it?"**

TIME_WAIT connections accumulate when the server closes connections frequently (e.g., short-lived HTTP/1.0). Each closed connection holds its 4-tuple for 60 seconds. With high-volume traffic, you can exhaust the ephemeral port range. Fixes: (1) Enable `SO_REUSEADDR` / `SO_REUSEPORT` to recycle TIME_WAIT ports. (2) Use HTTP/1.1 with `Connection: keep-alive` to reduce connection churn. (3) Tune `net.ipv4.tcp_tw_reuse=1` on Linux (server side). (4) Reduce TIME_WAIT duration via `net.ipv4.tcp_fin_timeout` (risky on unreliable networks).

---

**Q: "Why would a TCP connection show retransmissions in Wireshark even though the network is fine?"**

Several causes, roughly in order of probability: (1) RTO is set too aggressively low — slightly jittery RTT causes false timeouts. Tune RTT estimation. (2) The application is holding the ACK (delayed ACK timer, 40–200ms) — this looks like a retransmit from the sender's perspective but isn't. (3) Receive buffer overflow — the kernel silently drops packets, causing the sender to retransmit. Check `/proc/net/udp` or `ss -m`. (4) NIC driver bug / TSO interaction — segmentation offload corrupts packets, causing the remote to send duplicate ACKs. Disable TSO with `ethtool -K eth0 tso off`.

---

**Q: "What's the difference between `close()` and `shutdown()` on a socket?"**

`shutdown(SHUT_WR)` sends a FIN, signaling no more data will be sent in this direction. The socket can still receive data (half-closed). `close()` decrements the file descriptor reference count — only when it reaches 0 does the kernel send a FIN. With `dup()` or `fork()`, `close()` may not send a FIN at all. For clean connection teardown: always call `shutdown(SHUT_WR)` to initiate the FIN exchange, then drain remaining data, then `close()`.

---

### Networking Fundamentals Questions

**Q: "What's the difference between a TUN and TAP device?"**

Both are virtual network interfaces backed by a userspace file descriptor. TUN (Layer 3): delivers raw IP packets to your process. You must handle everything above IP yourself (routing, ARP is irrelevant at this layer). TAP (Layer 2): delivers raw Ethernet frames — including MAC addresses, EtherType, and ARP. Use TUN when you want to implement IP and above. Use TAP when you want to implement a full Ethernet-level bridge or VPN that needs MAC-level visibility. WireGuard, OpenVPN TUN mode, and this project use TUN.

---

**Q: "How does ARP work? What happens when the ARP cache entry expires?"**

ARP maps IPv4 addresses to Ethernet MAC addresses. On cache miss: send an ARP Request broadcast ("who has 192.168.1.5?"). The owner replies with an ARP Reply unicast ("192.168.1.5 is at aa:bb:cc:dd:ee:ff"). The requester caches the mapping (typically 20–120 seconds). On expiry: the entry is probed (one more ARP request) before being flushed. If the probe gets no reply (the host is gone), subsequent packets to that IP will trigger a new ARP Request. Linux ARP cache timers: `net.ipv4.neigh.default.base_reachable_time_ms` (default 30s).

---

## Interview Preparation: TCP Deep Dives

This section compiles the hardest TCP interview questions at top-tier systems companies (Jane Street, Cloudflare, Google, Dropbox, FAANG infrastructure/SRE roles), along with precise technical answers that demonstrate real implementation experience.

### "Describe the TCP state machine. What are all 11 states?"

The TCP finite state machine (RFC 793, Figure 6) has 11 states:

| State | Description |
|---|---|
| `CLOSED` | No connection. Default initial state. |
| `LISTEN` | Server is waiting for incoming SYN. |
| `SYN_SENT` | Client has sent SYN, waiting for SYN-ACK. |
| `SYN_RECEIVED` | Server has received SYN and sent SYN-ACK, waiting for ACK. |
| `ESTABLISHED` | Three-way handshake complete. Data flows in both directions. |
| `FIN_WAIT_1` | Active closer has sent FIN, waiting for ACK. |
| `FIN_WAIT_2` | Active closer's FIN was ACKed, waiting for peer's FIN. |
| `CLOSE_WAIT` | Passive closer has received FIN and ACKed it. Application must call `close()`. |
| `CLOSING` | Both sides sent FIN simultaneously. Waiting for ACK of our FIN. |
| `LAST_ACK` | Passive closer has sent FIN. Waiting for final ACK. |
| `TIME_WAIT` | Active closer has received peer's FIN. Waiting 2×MSL before CLOSED. |

---

### "Explain slow start and congestion avoidance. Why does TCP use both?"

**Slow start** (RFC 5681 §3.1): At connection open, `cwnd=1 MSS`. For each ACK received, `cwnd += 1 MSS`. This doubles the sending rate each RTT (exponential growth). The rationale: we have no information about the network's capacity. Growing exponentially finds the capacity quickly.

**Congestion avoidance** (RFC 5681 §3.1): When `cwnd ≥ ssthresh`, switch to `cwnd += MSS²/cwnd per ACK`, which is approximately `+1 MSS per RTT` (linear growth). The rationale: we're near the network's capacity. Growing linearly probes gently, avoiding sudden congestion.

**Why both?** Slow start alone would cause immediate congestion on every connection. Congestion avoidance alone would take too many RTTs to reach line rate from a cold start. The combination — exponential growth until we approach capacity, then linear probing — is the AIMD algorithm, proven by Chiu & Jain (1989) to converge to both efficiency (full utilization) and fairness (equal share among competing flows).

---

### "What is head-of-line blocking in TCP? How does HTTP/2 address it? Why doesn't it fully solve it?"

**Head-of-line blocking (HoL blocking):** TCP delivers data to the application strictly in order. If segment N is lost, segments N+1, N+2, ... are held in the receive buffer even if they arrived intact. The application cannot read any of them until N is retransmitted and received. At 1% packet loss on a 100ms RTT link, HoL blocking reduces effective throughput by ~25%.

**HTTP/2's approach:** HTTP/2 multiplexes multiple logical "streams" over a single TCP connection. In theory, a stalled stream shouldn't block other streams. **In practice:** HoL blocking is still present at the TCP level. All HTTP/2 streams share one TCP connection, so if a segment is lost, *all* streams are blocked at the TCP layer waiting for retransmission. HTTP/2 only eliminates HoL blocking at the HTTP layer, not the transport layer.

**QUIC/HTTP/3's full solution:** QUIC is built on UDP and implements multiple independent streams at the transport layer. A lost packet only blocks the specific stream whose data was in that packet, not all streams. This is why HTTP/3 over QUIC is significantly more performant on lossy networks (mobile, satellite).

---

### "What is the Nagle algorithm? When should you disable it?"

**Nagle's algorithm (RFC 896):** To prevent many tiny segments ("tinygrams"), buffer outgoing data and only send a new segment if: (1) the buffered data is at least MSS, OR (2) all previously sent data has been acknowledged. This coalesces many small `write()` calls into fewer large segments.

**Disable with `TCP_NODELAY` when:**
- Interactive applications where latency matters more than throughput: SSH, telnet, remote desktop, online games. A 40ms buffer delay in SSH makes typing feel sluggish.
- Protocols with request-response patterns where both request and response fit in one segment: you must send the request immediately to trigger the response, or Nagle will delay the last bytes of the request until the previous response is ACKed (the "Nagle interaction" — a notorious source of 40ms latency in HTTP/1.0 over keep-alive).

**Keep Nagle enabled when:** bulk file transfer, log shipping, or any write-heavy workload where throughput matters more than latency.

---

### "What happens when TCP's window is 0? How is it resolved?"

When the receiver's buffer is full, it advertises `rwnd=0`. The sender must stop sending data. But now neither side will send a segment: the sender is blocked, and the receiver has no reason to send an ACK (no new data to acknowledge). This is a **deadlock**.

**Resolution — the Zero Window Probe:** When `rwnd` transitions to 0, the sender starts a **persist timer** (RFC 793 §3.7). When it fires, the sender transmits a **1-byte probe** — a segment with one byte of data (out-of-window). The receiver must send an ACK in response (even though it rejects the data). The ACK includes the current `rwnd`. If `rwnd` is still 0, the probe is retried with exponential backoff (up to the RTO maximum). When `rwnd` becomes non-zero, the persist timer is cancelled and normal data flow resumes.

**Important:** The probe is sent regardless of the congestion window. The `cwnd` limit does not apply to persist probes.

---

### "How does TCP handle packet reordering? What's the difference between reordering and loss?"

**Reordering:** Segment N+1 arrives before segment N. TCP places N+1 in the reorder buffer (`BTreeMap<seq, bytes>`) and sends a duplicate ACK (ACK for N — the last in-order byte). When N arrives, it's assembled contiguously and all buffered bytes are delivered.

**The problem:** 3 duplicate ACKs triggers **fast retransmit** — the sender retransmits segment N immediately. But if N was merely delayed (not lost), the retransmit is spurious. The retransmit trigger (3 dup ACKs) was chosen as a compromise: more than 2 dup ACKs to tolerate 2-packet reordering (common on multipath networks), but fewer than 4 to react quickly to real loss.

**RFC 4653** (Improving the Robustness of TCP to Non-Congestion Events) proposes increasing the dup ACK threshold dynamically based on observed reordering. RACK (RFC 8985) uses time-based loss detection instead of dup ACK counts, making it robust to reordering by design.

---

## Advanced Implementation Patterns

### Pattern: Timer Wheel for Retransmit Management

For implementations with many simultaneous connections (100k+), replace `BinaryHeap` timers with a hierarchical timing wheel:

```rust
/// A simple single-level timing wheel with 1ms resolution, 8192 buckets (8.192 seconds).
/// For full coverage, add a second level that handles 8s–8192s.
pub struct TimingWheel {
    buckets: Vec<Vec<ConnId>>,
    current_tick: usize,
    tick_duration: Duration,
}

impl TimingWheel {
    pub fn new(num_buckets: usize, tick_duration: Duration) -> Self {
        Self {
            buckets: vec![Vec::new(); num_buckets],
            current_tick: 0,
            tick_duration,
        }
    }

    pub fn insert(&mut self, conn_id: ConnId, delay: Duration) {
        let ticks = (delay.as_nanos() / self.tick_duration.as_nanos()) as usize;
        let bucket = (self.current_tick + ticks) % self.buckets.len();
        self.buckets[bucket].push(conn_id);
    }

    /// Advance the wheel by one tick, returning expired connection IDs.
    pub fn tick(&mut self) -> Vec<ConnId> {
        self.current_tick = (self.current_tick + 1) % self.buckets.len();
        std::mem::take(&mut self.buckets[self.current_tick])
    }
}
```

Insert: O(1). Expire: O(1) amortized. This is how FreeBSD's callout wheel, Linux's timer wheel, and the Tokio `DelayQueue` work internally.

---

### Pattern: Connection Table with Consistent Hashing

For educational implementations, a `HashMap<FourTuple, Tcb>` is fine. For anything handling tens of thousands of connections, consistent hashing into a fixed-size table avoids rehashing:

```rust
/// Lock-free connection table using a flat array with open addressing.
/// FourTuple is (src_ip: u32, src_port: u16, dst_ip: u32, dst_port: u16) = 12 bytes.
pub struct ConnTable {
    slots: Vec<Option<(FourTuple, Tcb)>>,
    mask: usize,  // slots.len() - 1, assumes power-of-two size
}

impl ConnTable {
    pub fn get(&self, key: &FourTuple) -> Option<&Tcb> {
        let mut idx = self.hash(key) & self.mask;
        loop {
            match &self.slots[idx] {
                None => return None,  // empty slot: key not present
                Some((k, v)) if k == key => return Some(v),
                _ => idx = (idx + 1) & self.mask,  // linear probe
            }
        }
    }

    fn hash(&self, key: &FourTuple) -> usize {
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;
        let mut h = DefaultHasher::new();
        key.hash(&mut h);
        h.finish() as usize
    }
}
```

---

### Pattern: Zero-Allocation Packet Parsing

Most packet parsing implementations allocate a `Vec<u8>` for the payload or clone header fields. For high-throughput paths, parse in-place using a cursor over a shared buffer:

```rust
/// Parse an Ethernet frame by storing a reference into the buffer — zero allocation.
pub struct EthernetFrame<'a> {
    data: &'a [u8],
}

impl<'a> EthernetFrame<'a> {
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, ParseError> {
        if data.len() < 14 { return Err(ParseError::TooShort); }
        Ok(Self { data })
    }

    /// Returns a zero-copy slice of the destination MAC address.
    #[inline]
    pub fn dst_mac(&self) -> &[u8; 6] {
        self.data[0..6].try_into().unwrap()
    }

    #[inline]
    pub fn src_mac(&self) -> &[u8; 6] {
        self.data[6..12].try_into().unwrap()
    }

    #[inline]
    pub fn ethertype(&self) -> u16 {
        u16::from_be_bytes([self.data[12], self.data[13]])
    }

    /// Returns a zero-copy slice of the Ethernet payload.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        &self.data[14..]
    }
}
```

The `'a` lifetime ties the parsed frame to the underlying buffer — the compiler enforces that you don't modify the buffer while the frame exists. No allocation, no copies.

---

### Pattern: Compile-Time Packet Layout Verification

Use Rust's `const` evaluation to assert packet header sizes at compile time, catching off-by-one errors before runtime:

```rust
#[repr(C, packed)]
struct IpHeader {
    version_ihl:    u8,
    dscp_ecn:       u8,
    total_length:   u16,
    identification: u16,
    flags_fragment: u16,
    ttl:            u8,
    protocol:       u8,
    checksum:       u16,
    src_addr:       u32,
    dst_addr:       u32,
}

// This assertion is evaluated at compile time — if the struct is the wrong
// size, the build fails with a clear error message.
const _: () = assert!(
    std::mem::size_of::<IpHeader>() == 20,
    "IpHeader must be exactly 20 bytes (RFC 791 §3.1)"
);

#[repr(C, packed)]
struct TcpHeader {
    src_port:   u16,
    dst_port:   u16,
    seq_num:    u32,
    ack_num:    u32,
    data_offset_reserved_flags: u16,
    window:     u16,
    checksum:   u16,
    urgent_ptr: u16,
}

const _: () = assert!(
    std::mem::size_of::<TcpHeader>() == 20,
    "TcpHeader base must be exactly 20 bytes (RFC 793 §3.1)"
);
```

---

## Extending the Curriculum: Self-Directed Projects

After completing the 12-week curriculum, here are structured self-directed projects that build directly on your foundation:

### Project A: Raw Packet Sniffer (1 week)

Build a passive network monitor using a `TAP` device (Layer 2) that logs all traffic on your local network. No packet injection, just capture and decode.

**Learning objectives:**
- Understand promiscuous mode and how Wireshark works internally
- Parse ARP, DHCP, DNS, and HTTP packets by hand
- Build a terminal UI with live connection statistics

**Tech:** TAP device, `crossterm` for TUI, `pcap` file format for exporting captures.

---

### Project B: Minimal VPN (3 weeks)

Build a point-to-point VPN that tunnels IP traffic between two machines over UDP, with symmetric-key encryption. This is essentially a simplified WireGuard.

**Architecture:**
```
Machine A                                     Machine B
────────                                     ────────
App → TUN (10.0.0.1)                         App → TUN (10.0.0.2)
  → encrypt(ChaCha20-Poly1305, preshared_key)  → decrypt
  → UDP → internet                            ← UDP ← internet
```

**Learning objectives:**
- Understand how WireGuard and OpenVPN work at the packet level
- Apply symmetric encryption to a real protocol
- Handle key exchange (use `x25519-dalek` for DH, skip IKE complexity)

---

### Project C: TCP Load Balancer (2 weeks)

Build an L4 (TCP-level) load balancer that accepts connections on one IP and forwards them to a pool of backend servers. Unlike an HTTP proxy (L7), this operates at the TCP level: the load balancer proxies the raw byte stream, not the HTTP request.

```
Client → tcp-lb:80 → [backend-1:8080, backend-2:8080, backend-3:8080]
```

**Learning objectives:**
- Understand how HAProxy, AWS NLB, and GCP TCP load balancers work
- Implement connection tracking (source IP affinity)
- Handle backend health checks (TCP ping)

---

### Project D: QUIC Micro-Implementation (4 weeks)

Build a minimal subset of QUIC (RFC 9000): single-stream, no TLS (use plaintext for learning), connection establishment and reliable data transfer.

**Why QUIC after TCP?** QUIC reimplements everything you built in this curriculum, but over UDP with modern improvements. Understanding TCP first makes QUIC's design choices immediately clear rather than mysterious.

**Minimal QUIC packet format:**
```
[1-byte header: 0x00=Initial, 0x01=Data, 0x02=Ack, 0x03=Close]
[8-byte connection_id]
[4-byte packet_number]
[variable: payload or ACK ranges]
```

---

### Project E: Integrate with Tokio (1 week)

Wrap your `TcpListener`/`TcpStream` in a `tokio` compatible async interface, so existing async Rust applications can use your stack instead of the OS TCP:

```rust
// Target API — identical to tokio::net::TcpStream
use tcp_stack_async::TcpListener;

#[tokio::main]
async fn main() {
    let listener = TcpListener::bind("192.168.0.2:8080").await.unwrap();
    loop {
        let (mut stream, addr) = listener.accept().await.unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0; 4096];
            let n = stream.read(&mut buf).await.unwrap();
            stream.write_all(&buf[..n]).await.unwrap();
        });
    }
}
```

**Learning objectives:** understand `Poll`, `Waker`, and the async executor model. Your stack becomes a drop-in replacement for `tokio::net::TcpListener`.

---

## Community and Ecosystem

### Where to Ask Questions

If you get stuck on any week of the curriculum, these are the best places to find help:

| Community | Best for | Link |
|---|---|---|
| **Rust Users Forum** | Rust-specific questions (borrow checker, async, `unsafe`) | [users.rust-lang.org](https://users.rust-lang.org) |
| **Rust Discord #systems** | Real-time discussion of low-level Rust | [discord.gg/rust-lang](https://discord.gg/rust-lang) |
| **CS144 Piazza (public)** | Questions about the TCP labs that share this project's goals | Archived at cs144.github.io |
| **Networking StackExchange** | Protocol-level questions ("why does RFC 793 say X?") | [networkengineering.stackexchange.com](https://networkengineering.stackexchange.com) |
| **Jon Gjengset's Discord** | Questions about his TCP-in-Rust stream (most directly relevant) | Linked in his YouTube channel |
| **This repo's Discussions tab** | Questions specific to this codebase | github.com/Mannava-Daasaradhi/tcp-stack/discussions |

### Conference Talks Worth Watching

These talks will deepen your understanding of topics covered in the curriculum:

| Talk | Speaker | Length | What You'll Learn |
|---|---|---|---|
| [TCP in Rust (full stream)](https://www.youtube.com/watch?v=bzja9fQWzdA) | Jon Gjengset | 4h | The closest existing resource to this project. Watch before or during Week 5–8. |
| [How TCP/IP Works](https://www.youtube.com/watch?v=HCHFX5O1IaQ) | Fastly | 45m | High-level overview with good visual diagrams. Watch before Week 1. |
| [Linux Networking Internals](https://www.netdevconf.info/) | Various (netdev conf) | Varies | How the Linux kernel's TCP stack works. Useful context after Week 10. |
| [QUIC: A UDP-Based Multiplexed and Secure Transport](https://www.youtube.com/watch?v=BazWd_iWpAA) | Jana Iyengar (IETF) | 50m | Where TCP goes next. Watch after completing Week 12. |
| [BBR: Congestion-Based Congestion Control](https://www.youtube.com/watch?v=tCKrGFRuVSU) | Neal Cardwell (Google) | 40m | The engineering behind BBR. Watch after Week 8 (congestion control). |
| [The Story of Getting SSH Port 22](https://www.ssh.com/academy/ssh/port) | Tatu Ylönen | Article | Why SSH uses port 22 — the IANA port assignment process. |

### Related Open Source Projects to Study

After completing this curriculum, these codebases are worth reading as the next level of study:

| Project | Language | What to Study | Link |
|---|---|---|---|
| **smoltcp** | Rust | Production embedded TCP — no_std, zero alloc, poll-based | [github.com/smoltcp-rs/smoltcp](https://github.com/smoltcp-rs/smoltcp) |
| **mio** | Rust | The epoll/kqueue abstraction your event loop needs | [github.com/tokio-rs/mio](https://github.com/tokio-rs/mio) |
| **tokio** | Rust | How async/await maps to epoll on Linux | [github.com/tokio-rs/tokio](https://github.com/tokio-rs/tokio) |
| **tun2socks** | Go | Production userspace TCP-to-SOCKS proxy | [github.com/xjasonlyu/tun2socks](https://github.com/xjasonlyu/tun2socks) |
| **WireGuard (kernel)** | C | TUN-based VPN — real production use of the exact TUN interface you learned | [git.zx2c4.com/wireguard-linux](https://git.zx2c4.com/wireguard-linux) |
| **lwIP** | C | The reference embedded TCP stack used in billions of IoT devices | [savannah.nongnu.org/projects/lwip](https://savannah.nongnu.org/projects/lwip/) |
| **net-next (Linux)** | C | The Linux kernel's TCP stack itself — `net/ipv4/tcp*.c` | [github.com/torvalds/linux](https://github.com/torvalds/linux/tree/master/net/ipv4) |

---

## Supplementary RFC Reading List

These RFCs are beyond the core curriculum but reward careful reading once you have a working stack. Each is linked to the IETF's RFC editor.

### Performance and Optimization

| RFC | Title | Why It Matters |
|---|---|---|
| [RFC 1323](https://www.rfc-editor.org/rfc/rfc1323) | TCP Extensions for High Performance | Window scaling, timestamps, PAWS |
| [RFC 4898](https://www.rfc-editor.org/rfc/rfc4898) | TCP Extended Statistics MIB | How to measure TCP performance correctly |
| [RFC 7413](https://www.rfc-editor.org/rfc/rfc7413) | TCP Fast Open | 0-RTT for repeat connections |
| [RFC 8985](https://www.rfc-editor.org/rfc/rfc8985) | RACK-TLP Loss Detection | Better loss detection than dup ACK counting |
| [RFC 9293](https://www.rfc-editor.org/rfc/rfc9293) | Transmission Control Protocol (updated) | The 2022 revision of RFC 793 — consolidates 30 years of updates |

### Congestion Control

| RFC | Title | Why It Matters |
|---|---|---|
| [RFC 5681](https://www.rfc-editor.org/rfc/rfc5681) | TCP Congestion Control | The AIMD standard — required reading for Week 8 |
| [RFC 6298](https://www.rfc-editor.org/rfc/rfc6298) | Computing TCP's Retransmission Timer | Jacobson/Karels algorithm — required for Week 6 |
| [RFC 3168](https://www.rfc-editor.org/rfc/rfc3168) | Explicit Congestion Notification (ECN) | Congestion signaling without packet loss |
| [RFC 8312](https://www.rfc-editor.org/rfc/rfc8312) | CUBIC for Fast Long-Distance Networks | Current Linux default algorithm |
| [RFC 9002](https://www.rfc-editor.org/rfc/rfc9002) | QUIC Loss Detection and Congestion Control | QUIC's congestion control — very readable after RFC 5681 |

### Security

| RFC | Title | Why It Matters |
|---|---|---|
| [RFC 5961](https://www.rfc-editor.org/rfc/rfc5961) | Improving Robustness to Blind In-Window Attacks | RST and SYN validation |
| [RFC 6528](https://www.rfc-editor.org/rfc/rfc6528) | Defending Against Sequence Number Attacks | Cryptographic ISN generation |
| [RFC 1337](https://www.rfc-editor.org/rfc/rfc1337) | TIME-WAIT Assassination Hazards | RST segments in TIME_WAIT |
| [RFC 4987](https://www.rfc-editor.org/rfc/rfc4987) | TCP SYN Flooding Attacks and Common Mitigations | SYN cookies |

### Protocol Extensions

| RFC | Title | Why It Matters |
|---|---|---|
| [RFC 2018](https://www.rfc-editor.org/rfc/rfc2018) | TCP Selective Acknowledgment Options | SACK blocks in ACKs |
| [RFC 896](https://www.rfc-editor.org/rfc/rfc896) | Congestion Control in IP/TCP Internetworks | Nagle's original paper |
| [RFC 4960](https://www.rfc-editor.org/rfc/rfc4960) | Stream Control Transmission Protocol (SCTP) | TCP's sibling — multi-homing and multi-streaming |
| [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000) | QUIC: A UDP-Based Multiplexed and Secure Transport | The future of TCP-like transport |
| [RFC 8684](https://www.rfc-editor.org/rfc/rfc8684) | Multipath TCP (MPTCP) | TCP over multiple simultaneous paths |

---

## Debugging Reference Card

A quick-reference card for the most common debugging commands used throughout the curriculum. Print this or bookmark it.

### TUN Device Setup

```bash
# Open the TUN device (done automatically by tcp-stack, listed here for manual debugging)
sudo ip tuntap add dev tun0 mode tun
sudo ip link set tun0 up
sudo ip addr add 192.168.0.2/24 dev tun0

# Check the TUN device is up and configured
ip link show tun0
ip addr show tun0
ip route show dev tun0

# Tear down (useful when your stack crashes and leaves the device open)
sudo ip tuntap del dev tun0 mode tun
```

---

### Live Packet Inspection

```bash
# Capture all traffic on the TUN interface
sudo tcpdump -i tun0 -n -v

# Capture with full hex dump (for byte-level debugging)
sudo tcpdump -i tun0 -n -X

# Capture only TCP SYN packets (connection attempts)
sudo tcpdump -i tun0 -n 'tcp[tcpflags] & tcp-syn != 0'

# Capture only your specific port
sudo tcpdump -i tun0 -n 'tcp port 8080'

# Capture ARP only (for ARP debugging)
sudo tcpdump -i tun0 -n arp

# Capture ICMP only (for ping debugging)
sudo tcpdump -i tun0 -n icmp

# Save to pcap file for Wireshark analysis
sudo tcpdump -i tun0 -w /tmp/capture.pcap

# Open saved capture in Wireshark
wireshark /tmp/capture.pcap
```

---

### Network Condition Simulation

```bash
# Add 100ms round-trip delay
sudo tc qdisc add dev tun0 root netem delay 50ms

# Add 5% packet loss
sudo tc qdisc add dev tun0 root netem loss 5%

# Add delay + loss together
sudo tc qdisc add dev tun0 root netem delay 50ms loss 5%

# Add 10ms jitter (delay varies ±10ms)
sudo tc qdisc add dev tun0 root netem delay 50ms 10ms

# Add 10% packet reordering
sudo tc qdisc add dev tun0 root netem delay 10ms reorder 10% 25%

# Simulate a 1 Mbps bandwidth cap
sudo tc qdisc add dev tun0 root tbf rate 1mbit burst 32kbit latency 400ms

# Show current netem settings
tc qdisc show dev tun0

# Remove all traffic shaping
sudo tc qdisc del dev tun0 root

# Combine: rate limit + loss + delay (realistic mobile network simulation)
sudo tc qdisc add dev tun0 root netem delay 80ms 20ms loss 3% rate 10mbit
```

---

### Connection State Inspection

```bash
# Show all TCP connections (including TIME_WAIT)
ss -tan

# Show connections in a specific state
ss -tan state established
ss -tan state time-wait

# Show connections to/from a specific port
ss -tan 'sport = :8080'

# Show with memory info (useful for buffer overflow debugging)
ss -tanm

# Count connections by state
ss -tan | awk '{print $1}' | sort | uniq -c | sort -rn

# Show kernel TCP statistics (retransmits, errors, etc.)
netstat -s | grep -i tcp

# Show per-connection detailed TCP info
ss -tani dst 192.168.0.1
```

---

### Firewall Rules for Stack Isolation

```bash
# Drop kernel RSTs on your stack's port (prevents the kernel racing your stack)
sudo iptables -A INPUT  -p tcp --dport 8080 -j DROP
sudo iptables -A OUTPUT -p tcp --sport 8080 -j DROP

# View current iptables rules
sudo iptables -L -n --line-numbers

# Remove a specific rule by line number
sudo iptables -D INPUT 1

# Remove all rules (careful!)
sudo iptables -F

# Log packets before dropping (useful for debugging what the kernel sees)
sudo iptables -A INPUT -p tcp --dport 8080 -j LOG --log-prefix "KERNEL-INPUT: "
sudo iptables -A INPUT -p tcp --dport 8080 -j DROP
# View the log: sudo dmesg | grep KERNEL-INPUT
```

---

### Rust-Specific Debugging Commands

```bash
# Build with maximum debug info
cargo build --profile dev

# Build release with debug symbols (for profiling)
cargo build --release --debug  # or: CARGO_PROFILE_RELEASE_DEBUG=true cargo build --release

# Run with backtraces on panic
RUST_BACKTRACE=1 ./target/release/tcp-stack

# Run with full backtraces
RUST_BACKTRACE=full ./target/release/tcp-stack

# Run under Valgrind (memory error detection — slow but thorough)
valgrind --tool=memcheck --leak-check=full ./target/debug/tcp-stack

# Run under AddressSanitizer (faster than Valgrind)
RUSTFLAGS="-Z sanitizer=address" cargo +nightly build && ./target/debug/tcp-stack

# Generate a flamegraph
cargo install flamegraph
sudo cargo flamegraph --bin tcp-stack -- --iperf3-mode
# Opens flamegraph.svg

# Check assembly for a specific function (verify vectorization)
cargo install cargo-asm
cargo asm "tcp_stack::ip::checksum"
```

---

## Glossary Extended

This extends the [Glossary](#glossary) with additional terms introduced in the advanced sections above.

| Term | Definition |
|---|---|
| **AIMD** | Additive Increase Multiplicative Decrease. The core TCP congestion control algorithm: increase `cwnd` by 1 MSS per RTT (additive), halve `cwnd` on congestion (multiplicative). Proven by Chiu & Jain (1989) to converge to fairness and efficiency. |
| **BBR** | Bottleneck Bandwidth and RTT. Google's model-based congestion control algorithm (RFC 9002 for QUIC, also available in Linux kernel 4.9+). Controls sending rate by estimating the bottleneck bandwidth, rather than reacting to packet loss. |
| **CUBIC** | The default Linux congestion control algorithm since 2006. Uses a cubic function for window growth (faster recovery than AIMD on long-RTT links). RFC 8312. |
| **Delayed ACK** | A TCP optimization: instead of sending an ACK for every segment, wait up to 40–200ms for a second segment to arrive and piggyback both ACKs into one response. Reduces ACK traffic by ~50% but adds latency. Disabled with `TCP_QUICKACK`. |
| **ECN** | Explicit Congestion Notification (RFC 3168). A mechanism where congested routers mark packets (via IP header bits) instead of dropping them. The receiver echoes the congestion signal back to the sender via TCP header bits. Allows congestion response without data loss. |
| **FACK** | Forward ACK. An extension to SACK that estimates how many segments are in flight, enabling more aggressive loss recovery. Largely superseded by RACK. |
| **Four-tuple** | The 4-tuple `(src_ip, src_port, dst_ip, dst_port)` that uniquely identifies a TCP connection. All TCP segment routing uses this tuple to look up the right TCB. |
| **HoL Blocking** | Head-of-Line Blocking. When a lost segment at position N blocks the delivery of all subsequent segments N+1, N+2, ..., even if they arrived intact. Inherent in TCP's in-order delivery guarantee. QUIC eliminates it at the transport level. |
| **Karn's Algorithm** | Rule: never sample RTT for retransmitted segments (RFC 6298 §4). You can't determine whether the ACK is for the original or the retransmission, so any measurement would be biased. |
| **PAWS** | Protection Against Wrapped Sequence numbers (RFC 1323). Uses TCP timestamps to reject old segments that happen to fall within the current window after a sequence number wrap. Important on 10+ Gbps links. |
| **PMTU** | Path MTU Discovery (RFC 1191). The process of discovering the smallest MTU along the path from source to destination, to avoid IP fragmentation mid-network. |
| **QUIC** | Quick UDP Internet Connections (RFC 9000). A UDP-based transport protocol developed by Google. Provides TCP-like reliability with 0-RTT setup, built-in TLS 1.3, and stream multiplexing without HoL blocking. Underlies HTTP/3. |
| **RACK** | Recent ACKnowledgment. A loss detection algorithm (RFC 8985) that uses timestamps rather than duplicate ACK counting. More robust to packet reordering than the classic algorithm. |
| **SYN Cookie** | A stateless SYN flood defense (RFC 4987). Encodes the TCB state into the ISN as a cryptographic hash, so the server doesn't need to allocate memory until the final ACK arrives. Enabled automatically by Linux under SYN flood conditions (`net.ipv4.tcp_syncookies`). |
| **Silly Window Syndrome** | Performance degradation when the sender sends many tiny segments due to a small advertised window. Nagle's algorithm (sender-side) and Clark's algorithm (receiver-side) prevent this. |
| **TSO** | TCP Segmentation Offload. A NIC feature that lets the OS pass large (64KB) buffers to the NIC, which then splits them into 1460-byte segments in hardware. Reduces CPU overhead for bulk transfers. |
| **WireGuard** | A modern, audited VPN protocol that uses TUN devices and UDP encapsulation — conceptually very similar to what you built in Project B above. |
| **Zero Window** | `rwnd = 0`. The receiver's buffer is full and it cannot accept more data. The sender must stop sending and start the persist timer to probe for window updates. |

---

## Appendix A: The RFC 793 State Machine in Full

RFC 793 Figure 6 specifies the complete TCP state machine. This is reproduced below in ASCII art with each transition labeled with the event that triggers it and the action taken.

```
                              +---------+
                              | CLOSED  |<───────────────────────────────────┐
                              +---------+                                     │
                    passive         │ active                                  │
                    open            │ open/                                   │
                    ───────         │ send SYN                                │
              ┌─────────────┐       │                                         │
              ▼             │       ▼                                         │
         +---------+        │  +---------+                                   │
         | LISTEN  |        │  |SYN_SENT |<──────────┐                       │
         +---------+        │  +---------+           │                       │
              │             │       │                │                       │
  rcv SYN     │             │  rcv  │  snd SYN, ACK │                       │
  snd SYN,ACK │    ┌────────┘  SYN-ACK              │                       │
              │    │ snd SYN   snd ACK               │                       │
              ▼    ▼               │                 │                       │
         +──────────────+          │                 │ snd SYN               │
         |SYN_RECEIVED  |◄─────────┘                 │                       │
         +──────────────+                            │                       │
              │                                      │                       │
  rcv ACK     │                                      │                       │
  of SYN      │                                      │                       │
              ▼                                      │                       │
         +-----------+                               │                       │
     ┌──►| ESTABLISHED|◄──────────────────────────────┘                      │
     │   +-----------+                                                        │
     │        │                                                               │
     │        │ close/                                                        │
     │        │ snd FIN                                                       │
     │        ▼                                                               │
     │   +-----------+       rcv FIN/snd ACK        +-----------+            │
     │   | FIN_WAIT_1|────────────────────────────►| CLOSING   |            │
     │   +-----------+                              +-----------+            │
     │        │                                          │                   │
     │   rcv  │ rcv ACK of FIN                           │ rcv ACK of FIN   │
     │   FIN  │                                          ▼                   │
     │   snd  ▼                                     +-----------+            │
     │   ACK +-----------+   rcv ACK of FIN         | TIME_WAIT |            │
     │       | FIN_WAIT_2|──────────────────────────►|           |           │
     │       +-----------+                          +-----------+            │
     │                                                   │                   │
     │                                             2MSL  │                   │
     │   +-----------+                            timer  │                   │
     │   | CLOSE_WAIT|                             expires                   │
     │   +-----------+                                   └───────────────────┘
     │        │
     │   close│
     │   snd  │ FIN
     │        ▼
     │   +-----------+        rcv ACK of FIN
     └───| LAST_ACK  |────────────────────────── CLOSED
         +-----------+
```

Key observations for your implementation:

1. **ESTABLISHED has the most incoming edges.** It can be reached from `SYN_SENT` (active open) or `SYN_RECEIVED` (passive open). It can only be left via FIN (close), RST (reset), or timeout.

2. **TIME_WAIT is only entered by the active closer.** The passive closer goes through `CLOSE_WAIT → LAST_ACK → CLOSED` — no TIME_WAIT. This is important: if your server calls `close()` in response to the client's FIN, it is the passive closer and will NOT enter TIME_WAIT.

3. **`CLOSING` is rare.** It only occurs when both sides send FIN simultaneously before either receives the other's FIN. In practice, this happens in fewer than 0.1% of connection closes.

4. **`LISTEN` is not per-connection.** It represents the server socket, not an individual connection. When a SYN arrives, the listener spawns a new TCB in `SYN_RECEIVED` while remaining in `LISTEN` for future connections.

---

## Appendix B: IP, TCP, and ICMP Header Layouts at a Glance

### IPv4 Header (RFC 791 §3.1) — 20 bytes minimum

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├─────────────────────────────────────────────────────────────────┤
│Version(4)│  IHL  │DSCP (6) │ECN(2)│         Total Length       │
├─────────────────────────────────────────────────────────────────┤
│           Identification             │ Flags(3)│ Fragment Offset│
├─────────────────────────────────────────────────────────────────┤
│  Time to Live    │    Protocol      │        Header Checksum    │
├─────────────────────────────────────────────────────────────────┤
│                       Source IP Address                          │
├─────────────────────────────────────────────────────────────────┤
│                    Destination IP Address                         │
├─────────────────────────────────────────────────────────────────┤
│                    Options (if IHL > 5)                          │
└─────────────────────────────────────────────────────────────────┘

Flags bits: [Reserved=0][Don't Fragment (DF)][More Fragments (MF)]
Protocol: 1=ICMP, 6=TCP, 17=UDP
```

**IHL (Internet Header Length):** Header length in 32-bit words. IHL=5 → 20 bytes (no options). IHL=15 → 60 bytes (maximum options). Always: actual header bytes = IHL × 4.

---

### TCP Header (RFC 793 §3.1) — 20 bytes minimum

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├─────────────────────────────────────────────────────────────────┤
│           Source Port              │       Destination Port     │
├─────────────────────────────────────────────────────────────────┤
│                        Sequence Number                           │
├─────────────────────────────────────────────────────────────────┤
│                    Acknowledgment Number                         │
├─────────────────────────────────────────────────────────────────┤
│Data│ Res│C│E│U│A│P│R│S│F│         Window Size                  │
│Offs│    │W│C│R│C│S│S│Y│I│                                      │
│    │    │R│E│G│K│H│T│N│N│                                      │
├─────────────────────────────────────────────────────────────────┤
│            Checksum               │        Urgent Pointer        │
├─────────────────────────────────────────────────────────────────┤
│                    Options (if Data Offset > 5)                  │
└─────────────────────────────────────────────────────────────────┘

Flag bits (9 total): CWR, ECE, URG, ACK, PSH, RST, SYN, FIN
Data Offset: header length in 32-bit words (same as IP's IHL)
```

**Checksum pseudo-header:** TCP's checksum covers a 12-byte pseudo-header prepended to the TCP segment: `[src_ip: u32][dst_ip: u32][zeros: u8][proto: u8=6][tcp_length: u16]`. This binds the checksum to the IP addresses, preventing a segment from being "redirected" to a different host without detection.

---

### ICMP Echo Request/Reply (RFC 792) — 8 bytes header

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├─────────────────────────────────────────────────────────────────┤
│     Type (8=request / 0=reply)    │     Code (0 for echo)      │
├─────────────────────────────────────────────────────────────────┤
│            Checksum               │          Identifier        │
├─────────────────────────────────────────────────────────────────┤
│        Sequence Number            │   Data (variable length)   │
└─────────────────────────────────────────────────────────────────┘
```

**To send a reply:** Swap src/dst IP in the IP header. Change Type from 8 to 0. Leave Identifier and Sequence unchanged. Recompute the ICMP checksum over the ICMP header + data only (IP header checksum is separate). Leave all data bytes unchanged.

---

### ARP Packet (RFC 826) — 28 bytes for IPv4-over-Ethernet

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├─────────────────────────────────────────────────────────────────┤
│  Hardware Type (1=Ethernet)       │  Protocol Type (0x0800=IPv4)│
├─────────────────────────────────────────────────────────────────┤
│  HW Addr Len (6) │ Proto Addr Len (4)│   Operation (1=req, 2=reply)│
├─────────────────────────────────────────────────────────────────┤
│                   Sender MAC Address (6 bytes)                   │
├───────────────────────────────────┬─────────────────────────────┤
│    (cont.)                        │  Sender IP Address (partial) │
├─────────────────────────────────────────────────────────────────┤
│             Sender IP Address (cont.) / Target MAC (partial)     │
├─────────────────────────────────────────────────────────────────┤
│                 Target MAC Address (cont., 6 bytes)               │
├─────────────────────────────────────────────────────────────────┤
│                   Target IP Address (4 bytes)                     │
└─────────────────────────────────────────────────────────────────┘
```

**For an ARP Request:** Target MAC = `ff:ff:ff:ff:ff:ff` (broadcast). Target IP = the IP you're looking up. Sender MAC + IP = your MAC + IP.

**For an ARP Reply:** Swap sender/target. Set your MAC as the sender MAC. EtherType in the Ethernet header = `0x0806`.

---

*Built with RFC 793, a lot of Wireshark, and unreasonable amounts of patience.*
*"The entire internet runs on this. Now so does your laptop."*


---

## Changelog

All notable changes to `tcp-stack` are documented in this section. Versions follow [Semantic Versioning](https://semver.org/).

### [Unreleased]

- Nagle's algorithm (`TCP_NODELAY` socket option)
- `SO_REUSEADDR` / `SO_REUSEPORT` for TIME_WAIT recycling
- TCP keepalive probes (`SO_KEEPALIVE`)
- Improved SACK-based selective retransmission (retransmit only lost segments)
- RFC 1323 TCP timestamps for PAWS protection

### [1.0.0] — Initial Release

**Added:**
- TUN/TAP virtual NIC setup via `ioctl(IFF_TUN | IFF_NO_PI)` on Linux
- Ethernet frame parsing: destination MAC, source MAC, EtherType dispatch
- ARP (RFC 826): request parsing, reply generation, IPv4→MAC cache with TTL
- IPv4 (RFC 791): header parsing, checksum verification and generation, fragmentation + reassembly, TTL decrement
- ICMP (RFC 792): echo request/reply (ping), time exceeded generation
- TCP (RFC 793): all 11 state machine states, three-way handshake (active and passive open), reliable delivery with sequence numbers and cumulative ACKs, receive reorder buffer, retransmission timer with exponential backoff (RFC 6298), flow control with receive window advertisement, zero-window probes with persist timer, window scaling negotiation (RFC 1323), congestion control: slow start + AIMD + fast retransmit (RFC 5681), TCP teardown: active/passive/simultaneous close, RST handling with in-window sequence validation (RFC 5961), SACK-permitted advertisement during handshake (RFC 2018)
- `TcpListener` / `TcpStream` public API with POSIX socket semantics
- Minimal HTTP/1.0 server example
- Environment variable + `tcp-stack.toml` configuration system
- packetdrill test suite: 10 scripts covering handshake through teardown
- Criterion benchmarks for throughput and round-trip latency
- GitHub Actions CI pipeline

**Known Limitations (v1.0.0):**
- No Nagle's algorithm (sends immediately on every `write()`)
- No `SO_REUSEADDR` (60-second restart penalty after crash)
- Retransmission is go-back-N from `SND.UNA`, not SACK-guided
- Linux only (no macOS `utun`, no BSD support)
- Single-threaded event loop (no connection parallelism)

---

## Security Considerations

This section documents known security properties and limitations of `tcp-stack`. It is intended for users deploying this stack in environments where security matters.

### Sequence Number Randomization

Initial Sequence Numbers (ISN) are generated using the RFC 6528 formula:

```
ISN = SipHash-2-4(src_ip || src_port || dst_ip || dst_port || secret_key) + clock_counter
```

where `clock_counter` increments at 250,000 per second (≈4 µs per tick). The secret key is generated at startup using `getrandom()` (reads from `/dev/urandom`). This prevents ISN prediction attacks described in RFC 6528.

**Do not** replace this with a simple counter or timestamp-only ISN — this makes connections trivially forgeable by an off-path attacker.

### RST Injection Defense (RFC 5961)

RST segments are accepted only if the sequence number exactly equals `RCV.NXT` (not merely within the receive window). This defends against blind RST injection attacks. If the RST's sequence number is within the window but not equal to `RCV.NXT`, a challenge ACK is sent instead.

```rust
// RFC 5961 §3.2: Blind Reset Attack Using the RST Bit
if segment.flags.rst {
    if segment.seq == self.rcv_nxt {
        // Exact match: legitimate RST
        self.state = TcpState::Closed;
    } else if seq_in_window(segment.seq, self.rcv_nxt, self.rcv_wnd) {
        // Within window but not exact: send challenge ACK, drop RST
        self.send_ack();
    }
    return Ok(());
}
```

### SYN Flood Partial Defense

`tcp-stack` does **not** implement SYN cookies (RFC 4987). Under a SYN flood, the `SYN_RECEIVED` table will fill up and legitimate connections will be refused once the backlog limit is reached. This is acceptable for a learning project. For production use, implement SYN cookies: encode the TCB state into the ISN as a keyed hash so no state is allocated until the final ACK arrives.

### No TLS

`tcp-stack` provides no encryption or authentication. All data is transmitted in plaintext. Do not use this stack to transmit sensitive data without wrapping `TcpStream` with a TLS library such as `rustls`. See the [Roadmap](#roadmap) for a TLS 1.3 integration sketch.

### Privilege Requirements

Creating a TUN device requires `CAP_NET_ADMIN`. The binary must either run as root or have this capability granted via `setcap`:

```bash
sudo setcap cap_net_admin=eip target/release/tcp-stack
```

After capability grant, the binary no longer needs `sudo`. Avoid running the entire process as root if possible — grant only the minimum necessary capability.

### Threat Model

`tcp-stack` is designed for **educational use on a local virtual network** (TUN interface at `192.168.0.2/24`). It is **not** designed to be exposed to untrusted networks. Absent features: SYN cookie defense, ICMP rate limiting, TCP amplification protection.

---

## Platform Notes

### Linux (Primary Platform)

`tcp-stack` is developed and tested on Linux. All CI runs on Ubuntu 22.04 LTS (kernel 5.15+). Any Linux kernel >= 3.x that supports `IFF_TUN` should work.

**Verified distributions:**
- Ubuntu 20.04, 22.04, 24.04
- Debian 11 (Bullseye), 12 (Bookworm)
- Arch Linux (rolling)
- Fedora 38+
- Alpine Linux 3.18+ (with `iproute2` installed)

### WSL2 (Windows Subsystem for Linux 2)

WSL2 runs a real Linux kernel, so TUN devices work — with caveats:

```bash
# Check your WSL2 kernel version (need 5.15+ for reliable TUN support)
uname -r

# WSL2 does not forward packets between the TUN interface and the Windows host by default.
# Use socat or a port forwarder if you need to reach your stack from Windows.
```

WSL1 does **not** work — it translates Linux syscalls to Win32 and does not support `ioctl(IFF_TUN)`.

### macOS

macOS does not have `/dev/net/tun`. It has `utun` devices (accessible via `AF_SYSTEM` socket + `CTLIOCGINFO` ioctl). Porting `tun.rs` to macOS requires:

1. Open a `PF_SYSTEM` socket with `SYSPROTO_CONTROL`
2. Resolve the `utun` control ID using `CTLIOCGINFO`
3. `connect()` the socket with `sc_id` set to the resolved ID and `sc_unit` set to your desired `utunN` number

The [tun](https://crates.io/crates/tun) crate on crates.io abstracts this cross-platform. macOS support is tracked in the [Roadmap](#roadmap).

### Raspberry Pi / ARM Linux

ARM Linux is fully supported — there are no x86-specific assumptions. The `u16::from_be_bytes` / `to_be_bytes` conversions handle endianness correctly on all architectures. CI does not currently test ARM (tracked as a future CI target).

---

## Performance Optimization Guide

### Baseline: Where the CPU Time Goes

Run a flamegraph to identify your bottleneck before optimizing:

```bash
cargo install flamegraph
sudo cargo flamegraph --bin tcp-stack -- --iperf3-mode
# Opens flamegraph.svg in the current directory
```

On a typical unoptimized implementation, the hottest functions are:

| Function | Typical % of CPU | Optimization |
|---|---|---|
| `ip::checksum()` | 20–35% | SIMD, hand-rolled loop |
| `tcp::checksum()` | 15–25% | Same as IP checksum |
| `RecvBuffer::insert()` | 10–20% | BTreeMap operations — consider a ring buffer for in-order data |
| `HashMap::get()` (connection lookup) | 5–15% | AHash instead of SipHash for the connection table |
| `tun::read()` / `tun::write()` | 5–10% | Batch reads with `readv()` / `writev()` (scatter-gather I/O) |

### Optimizing the Checksum

The IP and TCP checksums are computed as a 16-bit one's complement sum over the header bytes. The naive implementation is a byte loop; the optimized version processes 8 bytes at a time using `u64` loads:

```rust
/// One's complement checksum, RFC 1071.
/// Processes 8 bytes per iteration to minimize branch overhead.
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u64 = 0;
    let mut chunks = data.chunks_exact(8);
    for chunk in chunks.by_ref() {
        sum += u64::from_ne_bytes(chunk.try_into().unwrap());
    }
    // Handle remaining bytes (0-7)
    let remainder = chunks.remainder();
    if !remainder.is_empty() {
        let mut buf = [0u8; 8];
        buf[..remainder.len()].copy_from_slice(remainder);
        sum += u64::from_ne_bytes(buf);
    }
    // Fold 64-bit sum into 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}
```

On a modern x86 CPU, this typically achieves ~10 GB/s throughput for checksum alone, compared to ~2 GB/s for the byte-by-byte version.

### Using AHash for Connection Lookups

The standard `HashMap` uses SipHash-1-3 for DoS resistance. For an internal connection table not exposed to untrusted keys, AHash is ~3x faster:

```toml
# Cargo.toml
[dependencies]
ahash = "0.8"
```

```rust
use ahash::AHashMap;

// Replace:
let mut table: HashMap<FourTuple, Tcb> = HashMap::new();
// With:
let mut table: AHashMap<FourTuple, Tcb> = AHashMap::new();
```

### Scatter-Gather I/O (`readv` / `writev`)

Instead of a single `read()` per packet, batch multiple TUN reads into one `readv()` call:

```rust
use std::os::unix::io::AsRawFd;
use libc::{readv, iovec};

// Prepare 16 buffers of 1504 bytes each
let mut bufs: Vec<[u8; 1504]> = vec![[0u8; 1504]; 16];
let iovecs: Vec<iovec> = bufs.iter_mut()
    .map(|b| iovec { iov_base: b.as_mut_ptr() as *mut _, iov_len: b.len() })
    .collect();

let total_read = unsafe {
    readv(tun_fd.as_raw_fd(), iovecs.as_ptr(), iovecs.len() as i32)
};
```

This reduces `syscall` overhead by up to 16x on packet-intensive workloads.

### Send Buffer: Ring Buffer vs Vec

The default `send_buf.rs` uses a `Vec<u8>` with a logical window tracked by `SND.UNA` / `SND.NXT`. For high throughput, replace with a fixed-capacity ring buffer that avoids any heap reallocation:

```rust
pub struct RingBuffer {
    data: Box<[u8]>,   // fixed-size heap allocation, never grows
    head: usize,       // read pointer (oldest unACKed byte)
    tail: usize,       // write pointer (next byte to write)
    capacity: usize,   // always power of two for bitmasking
}

impl RingBuffer {
    pub fn push(&mut self, bytes: &[u8]) -> usize {
        let available = self.capacity - (self.tail - self.head);
        let n = bytes.len().min(available);
        // wrap-around-aware copy omitted for brevity
        self.tail += n;
        n
    }

    pub fn pop(&mut self, n: usize) {
        self.head += n;  // advance past ACKed bytes
    }
}
```

A power-of-two capacity means head/tail indices can be masked instead of modulo'd: `index & (capacity - 1)`.

---

## Integration Examples

### Serving Files over HTTP

```rust
use tcp_stack::{TcpListener, TcpStream};
use std::io::{Read, Write};
use std::fs;

fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind("192.168.0.2:8080")?;
    println!("File server listening on 192.168.0.2:8080");

    loop {
        let (mut stream, peer) = listener.accept()?;
        println!("[http] connection from {}", peer);

        let mut req_buf = [0u8; 4096];
        let n = stream.read(&mut req_buf)?;
        let request = String::from_utf8_lossy(&req_buf[..n]);

        let path = request.lines().next()
            .and_then(|l| l.split_whitespace().nth(1))
            .unwrap_or("/");

        let (status, body) = match path {
            "/" => ("200 OK", b"Hello from tcp-stack!\n".to_vec()),
            "/readme" => {
                match fs::read("README.md") {
                    Ok(data) => ("200 OK", data),
                    Err(_)   => ("404 Not Found", b"File not found\n".to_vec()),
                }
            }
            _ => ("404 Not Found", b"Not found\n".to_vec()),
        };

        let response = format!(
            "HTTP/1.0 {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            status,
            body.len()
        );
        stream.write_all(response.as_bytes())?;
        stream.write_all(&body)?;
        stream.shutdown(std::net::Shutdown::Write)?;
    }
}
```

### Echo Server (RFC 862)

```rust
use tcp_stack::TcpListener;
use std::io::{Read, Write};
use std::thread;

fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind("192.168.0.2:7")?; // Port 7: echo
    println!("Echo server on 192.168.0.2:7");

    loop {
        let (stream, addr) = listener.accept()?;
        thread::spawn(move || {
            let mut stream = stream;
            let mut buf = [0u8; 4096];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => { if stream.write_all(&buf[..n]).is_err() { break; } }
                    Err(_) => break,
                }
            }
        });
    }
}
```

Test with: `nc 192.168.0.2 7` — everything you type is echoed back.

### Multi-threaded Connection Handler

```rust
use tcp_stack::TcpListener;
use std::io::{Read, Write};
use std::sync::Arc;
use std::thread;

fn main() -> std::io::Result<()> {
    let listener = Arc::new(TcpListener::bind("192.168.0.2:8080")?);

    let handles: Vec<_> = (0..4).map(|id| {
        let listener = Arc::clone(&listener);
        thread::spawn(move || {
            loop {
                match listener.accept() {
                    Ok((mut stream, addr)) => {
                        println!("[worker {}] accepted {}", id, addr);
                        let mut buf = [0u8; 8192];
                        if stream.read(&mut buf).is_ok() {
                            let _ = stream.write_all(
                                b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK"
                            );
                            let _ = stream.shutdown(std::net::Shutdown::Write);
                        }
                    }
                    Err(e) => eprintln!("[worker {}] accept error: {}", id, e),
                }
            }
        })
    }).collect();

    for h in handles { h.join().unwrap(); }
    Ok(())
}
```

---

## Wireshark & tcpdump Field Reference

### TCP Flags Quick Reference

| Flag | Hex | Wireshark filter | Meaning |
|---|---|---|---|
| FIN | 0x01 | `tcp.flags.fin == 1` | Sender finished sending data |
| SYN | 0x02 | `tcp.flags.syn == 1` | Synchronize sequence numbers |
| RST | 0x04 | `tcp.flags.reset == 1` | Reset connection |
| PSH | 0x08 | `tcp.flags.push == 1` | Push data to application |
| ACK | 0x10 | `tcp.flags.ack == 1` | Acknowledgment field valid |
| URG | 0x20 | `tcp.flags.urg == 1` | Urgent pointer valid |
| ECE | 0x40 | `tcp.flags.ecn == 1` | ECN-Echo |
| CWR | 0x80 | `tcp.flags.cwr == 1` | Congestion Window Reduced |

Common combinations: SYN=`0x02`, SYN-ACK=`0x12`, ACK=`0x10`, FIN-ACK=`0x11`, RST-ACK=`0x14`, PSH-ACK=`0x18`.

### ICMP Type/Code Quick Reference

| Type | Code | Meaning |
|---|---|---|
| 0 | 0 | Echo Reply (ping reply) |
| 3 | 0 | Destination Unreachable — Network Unreachable |
| 3 | 1 | Destination Unreachable — Host Unreachable |
| 3 | 3 | Destination Unreachable — Port Unreachable |
| 3 | 4 | Destination Unreachable — Fragmentation Needed (PMTU) |
| 8 | 0 | Echo Request (ping) |
| 11 | 0 | Time Exceeded — TTL Expired in Transit |
| 11 | 1 | Time Exceeded — Fragment Reassembly Timeout |

### Ethernet EtherType Quick Reference

| EtherType | Hex | Protocol |
|---|---|---|
| IPv4 | `0x0800` | Internet Protocol version 4 |
| ARP | `0x0806` | Address Resolution Protocol |
| IPv6 | `0x86DD` | Internet Protocol version 6 |
| VLAN | `0x8100` | IEEE 802.1Q VLAN tag |

---

## Recommended Development Workflow

### The Three-Terminal Setup

Open three terminal windows side by side:

```
Terminal 1 (your stack):             Terminal 2 (test):           Terminal 3 (packets):
─────────────────────────────        ─────────────────────        ───────────────────
LOG_LEVEL=debug \                    ping 192.168.0.2             sudo tcpdump -i tun0
  ./target/debug/tcp-stack           curl http://192.168.0.2:8080/  -n -vvv
```

The workflow: make a change → `cargo build` → restart stack → run test → read capture.

### Using `cargo watch` for Faster Iteration

```bash
cargo install cargo-watch
cargo watch -x 'build' -s 'sudo ./target/debug/tcp-stack'
```

### Iterative Week-by-Week Testing Checklist

**Week 1:**
- [ ] `ping 192.168.0.2` causes "ARP request" to appear in your stdout
- [ ] Binary runs without panicking on a basic `ping` workload

**Week 2:**
- [ ] `ping 192.168.0.2` succeeds (ICMP echo reply reaches the sender)
- [ ] `tcpdump -i tun0 icmp` shows type=8 request and type=0 reply

**Week 3–4:**
- [ ] `ip link show tun0` shows your interface up
- [ ] Fragmented pings reassembled without data loss: `ping -s 2000 192.168.0.2`

**Week 5–6:**
- [ ] `telnet 192.168.0.2 8080` connects (three-way handshake completes)
- [ ] Wireshark shows SYN → SYN-ACK → ACK with correct sequence numbers
- [ ] After disconnect: Wireshark shows FIN → ACK → FIN → ACK, no RSTs

**Week 7–8:**
- [ ] `iperf3 -c 192.168.0.2` completes without hanging
- [ ] Wireshark shows congestion window growth (increasing segment sizes)
- [ ] Simulated loss (`tc netem loss 5%`) triggers fast retransmit in Wireshark

**Week 9–10:**
- [ ] `curl http://192.168.0.2:8080/` returns an HTTP response
- [ ] Multiple simultaneous `curl` requests (`curl ... & curl ... &`) all succeed

**Week 11:**
- [ ] All 10 packetdrill test scripts pass: `sudo packetdrill tests/packetdrill/*.pkt`
- [ ] `cargo test` passes (unit tests)
- [ ] Flamegraph generated and hottest function identified

**Week 12:**
- [ ] `asciinema` or GIF demo recorded and linked in README
- [ ] Benchmark table present in README with comparison to kernel TCP
- [ ] GitHub Actions CI badge is green
- [ ] Blog post draft written

---

## Acknowledgements & Credits

`tcp-stack` was built on the shoulders of giants. Every major design decision traces directly to one of the following sources.

### RFC Authors

- **Jon Postel** — RFC 791 (IPv4), RFC 792 (ICMP), RFC 793 (TCP). Postel wrote TCP in 1981 and it remains the dominant transport protocol of the internet forty years later.
- **Dave Plummer** — RFC 826 (ARP, 1982).
- **Van Jacobson** — Invented slow start, fast retransmit, fast recovery, and the Jacobson/Karels RTT estimation algorithm (1988). Saved the internet from congestion collapse.
- **Bob Braden** — RFC 1122 (Requirements for Internet Hosts), clarifying dozens of TCP implementation requirements.
- **Sally Floyd** — RFC 5681 (TCP Congestion Control), RFC 3168 (ECN), and lifelong contributor to TCP correctness research.
- **Mark Allman, Vern Paxson** — RFC 6298 (Retransmission Timer). Formalized the correct RTO algorithm.

### Reference Implementations

| Project | Language | What it taught us |
|---|---|---|
| [smoltcp](https://github.com/smoltcp-rs/smoltcp) | Rust | `no_std` TCP, clean state machine design, zero-allocation parsing |
| [lwIP](https://savannah.nongnu.org/projects/lwip/) | C | Embedded TCP design, TCB layout, buffer management |
| [Linux `net/ipv4/tcp.c`](https://elixir.bootlin.com/linux/latest/source/net/ipv4/tcp.c) | C | The production reference: RACK, CUBIC, TSO, GRO |
| [saminiir/level-ip](https://github.com/saminiir/level-ip) | C | The original blog series inspiration |
| [jonhoo/rust-tcp](https://github.com/jonhoo/rust-tcp) | Rust | The live-coded TCP implementation that inspired this project's architecture |

### Teaching Resources

- **Jon Gjengset** — [Live-coded TCP in Rust (YouTube, 8 hours)](https://www.youtube.com/watch?v=bzja9fQWzdA) — the single best video resource for understanding TCP implementation in Rust. This project's architecture borrows heavily from his TCB design.
- **W. Richard Stevens** — *TCP/IP Illustrated, Vol. 1* — the canonical reference text. Every concept in this project is traced to a chapter in Stevens.
- **Beej's Guide to Network Programming** — [beej.us/guide/bgnet](https://beej.us/guide/bgnet/) — the best free introduction to socket programming concepts.
- **saminiir.com** — "Let's code a TCP/IP stack" series — the C implementation walkthrough that proved a userspace TCP stack is within reach of an individual developer in weeks.

### Tools

- [Wireshark](https://www.wireshark.org/) — packet analysis without which debugging this stack would have taken 10x longer
- [packetdrill](https://github.com/google/packetdrill) — Google's TCP test harness, used for the regression test suite
- [cargo-flamegraph](https://github.com/flamegraph-rs/flamegraph) — Rust profiling, used to find the checksum bottleneck
- [tc-netem](https://man7.org/linux/man-pages/man8/tc-netem.8.html) — Linux traffic control, used to simulate packet loss and delay for congestion control testing
- [iperf3](https://iperf.fr/) — throughput benchmarking

### Academic Papers

| Paper | Authors | Contribution |
|---|---|---|
| [Congestion Avoidance and Control (1988)](https://ee.lbl.gov/papers/congavoid.pdf) | Van Jacobson | Slow start, congestion avoidance, RTT estimation |
| [Analysis of the Increase and Decrease Algorithms for Congestion Avoidance (1989)](https://www.cs.utexas.edu/users/lam/NRL/blaze/papers/chiu89.pdf) | Chiu & Jain | Proof that AIMD converges to fairness and efficiency |
| [CUBIC: A New TCP-Friendly High-Speed TCP Variant (2008)](https://dl.acm.org/doi/10.1145/1400097.1400105) | Ha, Rhee & Xu | CUBIC congestion control (Linux default since 2006) |
| [BBR: Congestion-Based Congestion Control (2016)](https://queue.acm.org/detail.cfm?id=3022184) | Cardwell et al. | BBR model-based congestion control (Google) |
| [RACK: A Time-Based Fast Loss Detection Algorithm for TCP (RFC 8985)](https://www.rfc-editor.org/rfc/rfc8985) | Cheng et al. | Time-based loss detection, robust to reordering |

---

## License

`tcp-stack` is licensed under the **MIT License**.

```
MIT License

Copyright (c) 2024 tcp-stack contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

SPDX identifier: `MIT`  
Full license text: [LICENSE](LICENSE)

---

## CI & Release Process

### GitHub Actions Pipeline

The CI pipeline (`.github/workflows/ci.yml`) runs on every push and pull request:

```yaml
# Summary of CI steps (see actual file for complete YAML)
jobs:
  build-and-test:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with: { toolchain: "1.78", components: "clippy, rustfmt" }
      - run: cargo fmt --check
      - run: cargo clippy -- -D warnings
      - run: cargo build --release
      - run: cargo test
      - name: Install packetdrill
        run: |
          git clone https://github.com/google/packetdrill
          cd packetdrill/gtests/net/packetdrill && ./configure && make && sudo make install
      - run: sudo setcap cap_net_admin=eip target/release/tcp-stack
      - run: sudo packetdrill tests/packetdrill/*.pkt
      - run: cargo bench -- --test
```

### Tagging a Release

```bash
# 1. Update version in Cargo.toml: version = "1.1.0"

# 2. Add CHANGELOG entry for [1.1.0] with today's date

# 3. Commit
git add Cargo.toml README.md
git commit -m "chore: release v1.1.0"

# 4. Tag
git tag -a v1.1.0 -m "Release v1.1.0 — Nagle's algorithm, SO_REUSEADDR"

# 5. Push
git push origin main --tags
```

GitHub Actions will automatically build the release binary and attach it to the GitHub Release on tag push (if configured).

---

## Comparison: tcp-stack vs Kernel TCP vs smoltcp

| Feature | tcp-stack (this project) | Linux kernel TCP | smoltcp |
|---|---|---|---|
| **Language** | Rust (safe) | C | Rust (safe, `no_std`) |
| **Environment** | Userspace via TUN | Kernel space | Embedded / userspace |
| **Congestion control** | AIMD (RFC 5681) | CUBIC (default), BBR, RENO | None (embedded design) |
| **Retransmission** | Go-back-N from `SND.UNA` | RACK (RFC 8985), SACK-guided | Timeout-based |
| **Window scaling** | Yes (RFC 1323) | Yes | Yes |
| **Timestamps** | Yes (RFC 1323) | Yes | Yes |
| **SACK** | Advertised, not used for selective retransmit | Full SACK (RFC 2018) | No |
| **Fast retransmit** | 3 dup ACKs (RFC 5681) | 3 dup ACKs + RACK | Timeout only |
| **Nagle's algorithm** | No (v1.0) | Yes | Yes |
| **`SO_REUSEADDR`** | No (v1.0) | Yes | N/A |
| **SYN cookies** | No | Yes (auto under flood) | N/A |
| **IPv6** | No (roadmap) | Yes | Yes |
| **UDP** | No (roadmap) | Yes | Yes |
| **Async API** | No (roadmap) | epoll / io_uring | Yes (poll-based) |
| **Throughput (loopback)** | ~500 MB/s | ~10–20 GB/s | ~200 MB/s |
| **Lines of code** | ~3,500 | ~25,000 (`tcp.c` alone) | ~18,000 |
| **Educational value** | High | Low (hard to follow) | Medium |

**Key takeaway:** `tcp-stack` is intentionally less featureful than production stacks. Every missing feature is a clearly scoped extension in the [Roadmap](#roadmap). The goal is not to rival Linux TCP — it is to understand it.

---

## Quick Reference Card

```
┌──────────────────────────────────────────────────────────────────────┐
│                    tcp-stack Quick Reference                          │
├──────────────────────────────────────────────────────────────────────┤
│  BUILD & RUN                                                          │
│  cargo build --release                                                │
│  sudo setcap cap_net_admin=eip target/release/tcp-stack               │
│  ./target/release/tcp-stack                                           │
├──────────────────────────────────────────────────────────────────────┤
│  TEST COMMANDS                                                        │
│  ping 192.168.0.2                     # Week 2: ICMP                  │
│  telnet 192.168.0.2 8080              # Week 5: TCP handshake          │
│  curl http://192.168.0.2:8080/        # Week 10: Full HTTP             │
│  iperf3 -c 192.168.0.2               # Week 11: Throughput            │
│  sudo packetdrill tests/packetdrill/*.pkt  # Week 11: Regression       │
├──────────────────────────────────────────────────────────────────────┤
│  PACKET CAPTURE                                                       │
│  sudo tcpdump -i tun0 -n -vvv         # All traffic                   │
│  sudo tcpdump -i tun0 -n icmp         # ICMP only                     │
│  sudo tcpdump -i tun0 -n tcp port 8080 # Your port only              │
│  sudo tcpdump -i tun0 -w /tmp/out.pcap # Save for Wireshark           │
├──────────────────────────────────────────────────────────────────────┤
│  IPTABLES (stop kernel from racing your stack)                        │
│  sudo iptables -A INPUT -p tcp --dport 8080 -j DROP                   │
│  sudo iptables -A OUTPUT -p tcp --sport 8080 -j DROP                  │
│  sudo iptables -F   # remove all rules when done                      │
├──────────────────────────────────────────────────────────────────────┤
│  NETWORK SIMULATION (tc-netem)                                        │
│  sudo tc qdisc add dev tun0 root netem delay 50ms                     │
│  sudo tc qdisc add dev tun0 root netem loss 5%                        │
│  sudo tc qdisc add dev tun0 root netem delay 50ms loss 5%             │
│  sudo tc qdisc del dev tun0 root  # remove all shaping                │
├──────────────────────────────────────────────────────────────────────┤
│  LOG LEVELS                                                           │
│  LOG_LEVEL=error   # only errors                                      │
│  LOG_LEVEL=info    # default                                          │
│  LOG_LEVEL=debug   # state transitions                                │
│  LOG_LEVEL=trace   # every packet header                              │
├──────────────────────────────────────────────────────────────────────┤
│  KEY RFC SECTIONS                                                     │
│  RFC 793 §3.2   TCB variables         RFC 793 §3.4   handshake        │
│  RFC 793 §3.5   teardown              RFC 793 §3.7   data transfer    │
│  RFC 6298 §2    RTO algorithm         RFC 5681 §3    congestion ctrl  │
│  RFC 1323 §2    window scaling        RFC 2018 §3    SACK             │
└──────────────────────────────────────────────────────────────────────┘
```

---



## Extended Deep Dive: Packet Parsing in Rust

### Zero-Copy Parsing Philosophy

One of the most important design decisions in a high-performance network stack is how you parse packets. Naive parsing copies bytes into structs. Production stacks parse *in place* by interpreting raw byte slices as typed views. Here is how to approach this in Rust:

```rust
/// A zero-copy view of a raw Ethernet frame.
/// No allocation. No copy. Just pointer arithmetic over the original buffer.
pub struct EthernetFrame<'a> {
    raw: &'a [u8],
}

impl<'a> EthernetFrame<'a> {
    pub fn from_bytes(raw: &'a [u8]) -> Result<Self, ParseError> {
        if raw.len() < 14 {
            return Err(ParseError::TooShort { need: 14, got: raw.len() });
        }
        Ok(Self { raw })
    }

    #[inline]
    pub fn dst_mac(&self) -> &[u8; 6] {
        self.raw[0..6].try_into().unwrap()
    }

    #[inline]
    pub fn src_mac(&self) -> &[u8; 6] {
        self.raw[6..12].try_into().unwrap()
    }

    #[inline]
    pub fn ethertype(&self) -> EtherType {
        EtherType::from(u16::from_be_bytes([self.raw[12], self.raw[13]]))
    }

    #[inline]
    pub fn payload(&self) -> &[u8] {
        &self.raw[14..]
    }
}
```

This pattern — a lifetime-tied view over a borrowed byte slice — eliminates heap allocation on the hot path entirely. Apply the same pattern to `Ipv4Header<'a>` and `TcpHeader<'a>`.

### Endianness — The Bug That Bites Everyone

Network protocols use **big-endian** (network byte order). x86/ARM are **little-endian**. Every multi-byte field you read from a packet *must* be byte-swapped:

```rust
// WRONG — little-endian on x86, silent bug
let total_len = u16::from_ne_bytes([buf[2], buf[3]]);

// RIGHT — always explicit big-endian for network fields
let total_len = u16::from_be_bytes([buf[2], buf[3]]);
```

Rust's `u16::from_be_bytes`, `u32::from_be_bytes` are your friends. Never use `from_ne_bytes` for network data. This is the single most common source of bugs in Week 3.

### Checksum Computation — The Complete Reference

The **Internet checksum** (RFC 1071) is used by IP, ICMP, TCP, and UDP. The algorithm:

1. Sum all 16-bit words (treating the data as big-endian `u16` values).
2. Add any carry bits back into the low 16 bits (one's complement addition).
3. Take the bitwise NOT of the result.

A value of `0xFFFF` and `0x0000` are both treated as "zero checksum" in some contexts — TCP uses `0x0000` to mean "no checksum" for certain offloads, but you should always compute and verify.

```rust
pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut acc: u32 = 0;
    let mut chunks = data.chunks_exact(2);

    for chunk in chunks.by_ref() {
        acc += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    // Handle odd byte
    if let Some(&last) = chunks.remainder().first() {
        acc += (last as u32) << 8;
    }
    // Fold carry bits
    while acc > 0xFFFF {
        acc = (acc & 0xFFFF) + (acc >> 16);
    }
    !(acc as u16)
}

/// TCP pseudo-header checksum (RFC 793 §3.1)
pub fn tcp_checksum(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    tcp_segment: &[u8],
) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + tcp_segment.len());
    pseudo.extend_from_slice(&src_ip.octets());
    pseudo.extend_from_slice(&dst_ip.octets());
    pseudo.push(0x00);             // reserved
    pseudo.push(0x06);             // protocol = TCP
    pseudo.extend_from_slice(&(tcp_segment.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(tcp_segment);
    internet_checksum(&pseudo)
}
```

**Verification:** When verifying an incoming packet, compute the checksum over the entire data including the checksum field. The result should be `0x0000` (all ones sum) if valid.

---

## Extended Deep Dive: The TCP State Machine — Every Transition

The TCP state machine in RFC 793 has 11 states. Below is the complete annotated transition table including every event and the resulting action. This is the implementation blueprint for `src/tcp/state.rs`.

```
State         Event / Condition                   Action                        Next State
─────────────────────────────────────────────────────────────────────────────────────────
CLOSED        passive open (listen)               create TCB, alloc RCV.BUF     LISTEN
CLOSED        active open (connect)               SND SYN, init ISS             SYN_SENT
CLOSED        any segment arrives                 SND RST                        CLOSED

LISTEN        RCV SYN                             SND SYN+ACK                   SYN_RECEIVED
LISTEN        RCV RST                             ignore                         LISTEN
LISTEN        RCV ACK                             SND RST                        LISTEN
LISTEN        active open (send)                  SND SYN                        SYN_SENT

SYN_SENT      RCV SYN+ACK (our SYN acked)         SND ACK                        ESTABLISHED
SYN_SENT      RCV SYN (simultaneous open)         SND SYN+ACK                   SYN_RECEIVED
SYN_SENT      timeout                             SND SYN (retry), or give up    CLOSED

SYN_RECEIVED  RCV ACK of SYN                      notify accept queue            ESTABLISHED
SYN_RECEIVED  RCV RST                             deallocate TCB                 LISTEN (if passive)
SYN_RECEIVED  close() called                      SND FIN                        FIN_WAIT_1

ESTABLISHED   RCV FIN                             SND ACK                        CLOSE_WAIT
ESTABLISHED   close() called                      SND FIN                        FIN_WAIT_1
ESTABLISHED   RCV RST                             deliver error to app            CLOSED

FIN_WAIT_1    RCV ACK of FIN                      —                              FIN_WAIT_2
FIN_WAIT_1    RCV FIN (simultaneous close)        SND ACK                        CLOSING
FIN_WAIT_1    RCV FIN+ACK                         SND ACK                        TIME_WAIT

FIN_WAIT_2    RCV FIN                             SND ACK                        TIME_WAIT

CLOSING       RCV ACK of FIN                      —                              TIME_WAIT

TIME_WAIT     2*MSL timer expires                 deallocate TCB                 CLOSED

CLOSE_WAIT    close() called                      SND FIN                        LAST_ACK

LAST_ACK      RCV ACK of FIN                      deallocate TCB                 CLOSED
```

### Rust Implementation Skeleton

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

impl TcpState {
    /// Returns true if this state allows receiving data segments from the remote.
    pub fn can_receive_data(&self) -> bool {
        matches!(self, Self::Established | Self::FinWait1 | Self::FinWait2)
    }

    /// Returns true if the application can still write data.
    pub fn app_can_write(&self) -> bool {
        matches!(self, Self::Established | Self::CloseWait)
    }

    /// Returns true if the application can still read data.
    pub fn app_can_read(&self) -> bool {
        matches!(
            self,
            Self::Established | Self::FinWait1 | Self::FinWait2 | Self::CloseWait
        )
    }
}
```

---

## Extended Deep Dive: Sequence Number Space

Sequence numbers are the heart of TCP reliability. Understanding the sequence number space is the prerequisite for implementing everything in Phase 3.

### The Four Key Variables (RFC 793 §3.2)

```
Send sequence space:
  SND.UNA = oldest unacknowledged sequence number
  SND.NXT = next sequence number to be sent
  SND.WND = send window (how many bytes peer will accept)

Receive sequence space:
  RCV.NXT = next sequence number expected from peer
  RCV.WND = receive window (how many bytes we'll accept)
```

### Segment Acceptability Test

Before processing any incoming segment, you must validate it. An invalid segment is silently dropped (or RST is sent). From RFC 793 §3.3:

```
Segment length  | Window size | Test
────────────────┼─────────────┼────────────────────────────────────────
     0          |     0       | SEG.SEQ == RCV.NXT
     0          |    >0       | RCV.NXT <= SEG.SEQ < RCV.NXT + RCV.WND
    >0          |     0       | not acceptable (zero-window)
    >0          |    >0       | RCV.NXT <= SEG.SEQ < RCV.NXT + RCV.WND
                               OR
                               RCV.NXT <= SEG.SEQ + SEG.LEN-1 < RCV.NXT + RCV.WND
```

In Rust, wrapping arithmetic handles sequence number wraparound at `2^32`:

```rust
/// Wrapping comparison: is `a` before `b` in sequence number space?
#[inline]
pub fn seq_lt(a: u32, b: u32) -> bool {
    (a as i32).wrapping_sub(b as i32) < 0
}

/// Is `seq` within the window [start, start+window)?
pub fn in_window(seq: u32, start: u32, window: u32) -> bool {
    seq_lt(seq.wrapping_sub(start), window)
}
```

### Initial Sequence Number (ISN) Selection

RFC 793 suggests basing the ISN on a 32-bit clock that wraps every ~4.5 hours. Modern implementations use a cryptographic approach (RFC 6528) to prevent sequence number prediction attacks:

```rust
use std::time::{SystemTime, UNIX_EPOCH};

/// RFC 6528-inspired ISN generation (simplified; use SipHash in production).
pub fn generate_isn(src: SocketAddr, dst: SocketAddr, secret: u64) -> u32 {
    use std::hash::{Hash, Hasher};
    use std::collections::hash_map::DefaultHasher;

    let mut hasher = DefaultHasher::new();
    src.hash(&mut hasher);
    dst.hash(&mut hasher);
    secret.hash(&mut hasher);

    let hash = hasher.finish() as u32;
    let clock = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u32;

    hash.wrapping_add(clock)
}
```

---

## Extended Deep Dive: Retransmission Timer (RFC 6298)

Implementing the RTO (Retransmission Timeout) algorithm correctly is one of the hardest parts of TCP. RFC 6298 defines the Jacobson/Karels algorithm (1988) — still in use today unchanged.

### The Algorithm

```
Variables (per-connection):
  SRTT  = Smoothed RTT estimate
  RTTVAR = RTT variance estimate
  RTO = Retransmission timeout (min 1s, max 60s)

On first RTT measurement R:
  SRTT   = R
  RTTVAR = R / 2
  RTO    = SRTT + max(G, K * RTTVAR)   where K=4, G=clock granularity

On subsequent RTT measurement R':
  RTTVAR = (1 - beta)  * RTTVAR + beta  * |SRTT - R'|
  SRTT   = (1 - alpha) * SRTT   + alpha * R'
  RTO    = SRTT + max(G, K * RTTVAR)
  
  where alpha=1/8, beta=1/4 (integer: >>3 and >>2)

On retransmission (Karn's algorithm):
  Do NOT update SRTT/RTTVAR with retransmitted segment ACKs.
  RTO = min(RTO * 2, 60s)   (exponential backoff)
```

```rust
pub struct RttEstimator {
    srtt: Option<f64>,      // None until first measurement
    rttvar: f64,
    rto: Duration,
}

impl RttEstimator {
    const ALPHA: f64 = 1.0 / 8.0;
    const BETA: f64 = 1.0 / 4.0;
    const K: f64 = 4.0;
    const MIN_RTO: Duration = Duration::from_secs(1);
    const MAX_RTO: Duration = Duration::from_secs(60);

    pub fn update(&mut self, rtt_sample: Duration) {
        let r = rtt_sample.as_secs_f64();
        match self.srtt {
            None => {
                self.srtt = Some(r);
                self.rttvar = r / 2.0;
            }
            Some(ref mut srtt) => {
                self.rttvar = (1.0 - Self::BETA) * self.rttvar
                    + Self::BETA * (*srtt - r).abs();
                *srtt = (1.0 - Self::ALPHA) * *srtt + Self::ALPHA * r;
            }
        }
        let srtt = self.srtt.unwrap();
        let rto_secs = srtt + Self::K * self.rttvar;
        self.rto = Duration::from_secs_f64(rto_secs)
            .max(Self::MIN_RTO)
            .min(Self::MAX_RTO);
    }

    pub fn backoff(&mut self) {
        self.rto = (self.rto * 2).min(Self::MAX_RTO);
    }

    pub fn rto(&self) -> Duration {
        self.rto
    }
}
```

---

## Extended Deep Dive: Congestion Control — The Complete Picture

RFC 5681 defines the core TCP congestion control algorithm. Understanding this is essential for Week 8 and for any systems programming interview.

### The Four Phases

```
Phase            Trigger                   Behavior
─────────────────────────────────────────────────────────────────
Slow Start       Connection start, or      cwnd increases by 1 MSS per ACK
                 after RTO timeout          (doubles every RTT until ssthresh)

Congestion       cwnd >= ssthresh          cwnd increases by 1 MSS per RTT
Avoidance                                  (linear: cwnd += MSS*MSS/cwnd per ACK)

Fast Retransmit  3 duplicate ACKs          Immediately retransmit lost segment
                                            ssthresh = max(FlightSize/2, 2*MSS)
                                            cwnd = ssthresh + 3*MSS

Fast Recovery    After fast retransmit     cwnd += 1 MSS per duplicate ACK
                 until new ACK arrives      on new ACK: cwnd = ssthresh, exit
```

### Key Variable: `FlightSize`

```
FlightSize = SND.NXT - SND.UNA
```

This is the amount of data sent but not yet acknowledged — the number of bytes "in flight" in the network.

### Implementation

```rust
pub struct CongestionController {
    cwnd: u32,       // congestion window in bytes
    ssthresh: u32,   // slow start threshold
    dup_ack_count: u32,
    in_fast_recovery: bool,
}

const MSS: u32 = 1460; // Maximum Segment Size

impl CongestionController {
    pub fn new() -> Self {
        Self {
            cwnd: MSS,           // start with 1 MSS (RFC 3390 allows 10 MSS IW)
            ssthresh: u32::MAX,  // effectively infinite — slow start runs freely
            dup_ack_count: 0,
            in_fast_recovery: false,
        }
    }

    /// Call on each new ACK that advances SND.UNA.
    pub fn on_new_ack(&mut self, bytes_acked: u32) {
        if self.in_fast_recovery {
            self.cwnd = self.ssthresh;
            self.in_fast_recovery = false;
            self.dup_ack_count = 0;
            return;
        }
        if self.cwnd < self.ssthresh {
            // Slow start: increase by bytes_acked (up to MSS per ACK)
            self.cwnd = self.cwnd.saturating_add(bytes_acked.min(MSS));
        } else {
            // Congestion avoidance: increase by MSS per RTT
            // Approximation: += MSS * (bytes_acked / cwnd)
            self.cwnd = self.cwnd.saturating_add(MSS * bytes_acked / self.cwnd);
        }
    }

    /// Call on each duplicate ACK.
    pub fn on_dup_ack(&mut self, flight_size: u32) {
        self.dup_ack_count += 1;
        if self.dup_ack_count == 3 {
            // Trigger fast retransmit + enter fast recovery
            self.ssthresh = (flight_size / 2).max(2 * MSS);
            self.cwnd = self.ssthresh + 3 * MSS;
            self.in_fast_recovery = true;
        } else if self.in_fast_recovery {
            self.cwnd += MSS; // inflate by 1 MSS per dup ACK
        }
    }

    /// Call on RTO timeout (hard loss signal).
    pub fn on_timeout(&mut self, flight_size: u32) {
        self.ssthresh = (flight_size / 2).max(2 * MSS);
        self.cwnd = MSS; // drop to 1 MSS — restart slow start
        self.dup_ack_count = 0;
        self.in_fast_recovery = false;
    }

    /// How many bytes can we send right now?
    pub fn send_limit(&self, snd_wnd: u32) -> u32 {
        self.cwnd.min(snd_wnd)
    }
}
```

---

## Extended Deep Dive: Flow Control — The Receive Window

Flow control prevents a fast sender from overwhelming a slow receiver. RFC 793 defines the receive window (`RCV.WND`) as the amount of buffer space the receiver has available.

### Window Advertisement

Every ACK segment carries the current `RCV.WND` value. The sender must not have more than `SND.WND` bytes of unacknowledged data in flight at any time:

```
Sender constraint: SND.NXT - SND.UNA <= min(cwnd, SND.WND)
```

### Zero-Window Probing

When `SND.WND` drops to zero, the sender stops transmitting. But how does it know when the window reopens? The sender sends a **zero-window probe**: a 1-byte segment beyond `SND.UNA`. The receiver will ACK it with the current window. If the window is still zero, the sender backs off exponentially and retries.

```rust
pub struct ZeroWindowProber {
    probe_interval: Duration,
    attempts: u32,
}

impl ZeroWindowProber {
    pub fn next_probe_interval(&mut self) -> Duration {
        // Exponential backoff capped at 60 seconds (RFC 793 recommends this)
        let interval = self.probe_interval * (1 << self.attempts.min(6));
        self.attempts += 1;
        interval.min(Duration::from_secs(60))
    }

    pub fn reset(&mut self) {
        self.attempts = 0;
        self.probe_interval = Duration::from_secs(1);
    }
}
```

### Window Scaling (RFC 1323)

The original TCP window field is 16 bits, meaning maximum 65,535 bytes. On modern networks with high bandwidth-delay products (e.g., 1Gbps × 100ms RTT = 12.5MB), this is cripplingly small. RFC 1323 adds a **Window Scale** option negotiated in the SYN/SYN-ACK handshake:

```
Actual window = Window field << Window Scale
```

Valid scale values: 0–14. A scale of 14 gives a maximum window of 65535 × 2^14 = ~1GB.

```rust
pub fn parse_tcp_options(opts: &[u8]) -> TcpOptions {
    let mut out = TcpOptions::default();
    let mut i = 0;
    while i < opts.len() {
        match opts[i] {
            0 => break,           // EOL
            1 => i += 1,          // NOP
            2 if i + 3 < opts.len() => {
                // Maximum Segment Size
                out.mss = Some(u16::from_be_bytes([opts[i+2], opts[i+3]]));
                i += 4;
            }
            3 if i + 2 < opts.len() => {
                // Window Scale
                out.window_scale = Some(opts[i+2]);
                i += 3;
            }
            8 if i + 9 < opts.len() => {
                // Timestamps
                out.ts_val = Some(u32::from_be_bytes(opts[i+2..i+6].try_into().unwrap()));
                out.ts_ecr = Some(u32::from_be_bytes(opts[i+6..i+10].try_into().unwrap()));
                i += 10;
            }
            _ => {
                // Unknown option with length byte
                if i + 1 < opts.len() {
                    i += opts[i+1] as usize;
                } else {
                    break;
                }
            }
        }
    }
    out
}
```

---

## Extended Deep Dive: The Send Buffer

The send buffer is a circular byte buffer that stores data written by the application until it is acknowledged by the receiver.

### Key Invariants

```
Buffer layout:
  [acked | unacked (in flight) | unsent | free space]
    ↑           ↑                  ↑
  SND.UNA     SND.NXT             buf_tail

On new ACK: advance SND.UNA, freeing space at the front.
On send:    advance SND.NXT, consuming space from the back.
On retransmit: re-read from SND.UNA without advancing pointers.
```

```rust
pub struct SendBuffer {
    data: Box<[u8]>,
    head: usize,       // index of SND.UNA in data[]
    tail: usize,       // index of next write position
    una: u32,          // absolute sequence number of SND.UNA
    nxt: u32,          // absolute sequence number of SND.NXT
    cap: usize,        // data.len()
}

impl SendBuffer {
    pub fn new(capacity: usize, initial_seq: u32) -> Self {
        Self {
            data: vec![0u8; capacity].into_boxed_slice(),
            head: 0,
            tail: 0,
            una: initial_seq,
            nxt: initial_seq,
            cap: capacity,
        }
    }

    /// Bytes available for the application to write.
    pub fn free_space(&self) -> usize {
        self.cap - self.len()
    }

    /// Total bytes buffered (unacked + unsent).
    pub fn len(&self) -> usize {
        self.tail.wrapping_sub(self.head) % self.cap
    }

    /// Bytes in flight (sent but not acked).
    pub fn in_flight(&self) -> u32 {
        self.nxt.wrapping_sub(self.una)
    }

    /// Write application data into buffer.
    pub fn write(&mut self, data: &[u8]) -> usize {
        let n = data.len().min(self.free_space());
        for (i, &b) in data[..n].iter().enumerate() {
            self.data[(self.tail + i) % self.cap] = b;
        }
        self.tail = (self.tail + n) % self.cap;
        n
    }

    /// Get a slice of up to `limit` unsent bytes for transmission.
    pub fn next_to_send(&self, limit: usize) -> &[u8] {
        let offset = self.nxt.wrapping_sub(self.una) as usize;
        let available = self.len().saturating_sub(offset);
        let n = available.min(limit);
        // Note: this is simplified — real impl handles wraparound
        let start = (self.head + offset) % self.cap;
        &self.data[start..start + n]
    }

    /// Acknowledge bytes up to (and including) `ack_seq - 1`.
    pub fn acknowledge(&mut self, ack_seq: u32) {
        let newly_acked = ack_seq.wrapping_sub(self.una);
        self.head = (self.head + newly_acked as usize) % self.cap;
        self.una = ack_seq;
    }
}
```

---

## Extended Deep Dive: Receive Buffer and Out-of-Order Handling

TCP must handle out-of-order segments gracefully. If segment with seq=1000 arrives before segment with seq=500, you must buffer it and deliver data to the application only when the gap is filled.

### The Reorder Queue

```rust
use std::collections::BTreeMap;

pub struct RecvBuffer {
    /// Data ready to deliver to the application (contiguous from RCV.NXT).
    ready: Vec<u8>,
    /// Out-of-order segments keyed by their start sequence number.
    ooo: BTreeMap<u32, Vec<u8>>,
    /// Next sequence number expected.
    rcv_nxt: u32,
    /// Receive window size.
    window: u32,
}

impl RecvBuffer {
    pub fn receive_segment(&mut self, seq: u32, data: &[u8]) {
        if seq == self.rcv_nxt {
            // In-order: deliver immediately
            self.ready.extend_from_slice(data);
            self.rcv_nxt = self.rcv_nxt.wrapping_add(data.len() as u32);
            // Check if any OOO segments can now be delivered
            self.drain_ooo();
        } else if seq_gt(seq, self.rcv_nxt) {
            // Out-of-order: store for later
            self.ooo.entry(seq).or_insert_with(|| data.to_vec());
        }
        // else: duplicate or already-acked segment — discard
    }

    fn drain_ooo(&mut self) {
        loop {
            match self.ooo.range(self.rcv_nxt..).next().map(|(&k, _)| k) {
                Some(seq) if seq == self.rcv_nxt => {
                    let data = self.ooo.remove(&seq).unwrap();
                    self.ready.extend_from_slice(&data);
                    self.rcv_nxt = self.rcv_nxt.wrapping_add(data.len() as u32);
                }
                _ => break,
            }
        }
    }

    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.ready.len());
        buf[..n].copy_from_slice(&self.ready[..n]);
        self.ready.drain(..n);
        n
    }

    pub fn advertised_window(&self) -> u32 {
        (self.window as usize).saturating_sub(self.ready.len()) as u32
    }
}

fn seq_gt(a: u32, b: u32) -> bool {
    (a as i32).wrapping_sub(b as i32) > 0
}
```

---

## Extended Deep Dive: Building the HTTP Server — Week 10 in Full

The capstone application for Phase 4 is a minimal HTTP/1.0 server that uses your `TcpListener`/`TcpStream` API. Here is the complete implementation with connection handling, request parsing, and response serialization:

```rust
// examples/http_server.rs

use tcp_stack::api::{TcpListener, TcpStream};
use std::io::{Read, Write};

fn handle_connection(mut stream: TcpStream) {
    let mut buf = [0u8; 4096];
    let n = match stream.read(&mut buf) {
        Ok(n) if n > 0 => n,
        _ => return,
    };

    let request = std::str::from_utf8(&buf[..n]).unwrap_or("");
    let (method, path) = parse_request_line(request);

    let (status, body) = match (method, path) {
        ("GET", "/")         => ("200 OK", "Hello from tcp-stack!\n"),
        ("GET", "/health")   => ("200 OK", "ok\n"),
        ("GET", _)           => ("404 Not Found", "Not Found\n"),
        _                    => ("405 Method Not Allowed", "Method Not Allowed\n"),
    };

    let response = format!(
        "HTTP/1.0 {status}\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len()
    );

    let _ = stream.write_all(response.as_bytes());
    let _ = stream.shutdown();
}

fn parse_request_line(req: &str) -> (&str, &str) {
    let mut parts = req.split_whitespace();
    let method = parts.next().unwrap_or("GET");
    let path   = parts.next().unwrap_or("/");
    (method, path)
}

fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind("192.168.0.2:8080")?;
    println!("[http] Listening on http://192.168.0.2:8080/");

    loop {
        let stream = listener.accept()?;
        println!("[http] New connection");
        // For a real server, spawn a thread here:
        // std::thread::spawn(move || handle_connection(stream));
        handle_connection(stream);
    }
}
```

---

## Extended Deep Dive: Wireshark Recipes for TCP Debugging

Wireshark is your most powerful debugging tool throughout this project. Here are the most useful filters and techniques for each phase.

### Essential Filters

```
# All traffic on your TUN interface
sudo wireshark -i tun0

# Filter by protocol
arp
icmp
tcp

# Filter by port
tcp.port == 8080

# Filter by IP
ip.addr == 192.168.0.2

# SYN packets only (new connection attempts)
tcp.flags.syn == 1 && tcp.flags.ack == 0

# FIN packets (teardown)
tcp.flags.fin == 1

# RST packets (abrupt reset — often indicates a bug)
tcp.flags.rst == 1

# Retransmissions (Wireshark detects these automatically)
tcp.analysis.retransmission

# Zero-window
tcp.analysis.zero_window

# Duplicate ACKs
tcp.analysis.duplicate_ack

# Show TCP stream in order (right-click → Follow → TCP Stream)
```

### Decode TCP Options in Wireshark

In a SYN or SYN-ACK, expand the TCP layer and look for:
- **Maximum segment size**: your stack should advertise 1460 (Ethernet MTU 1500 - 20 IP - 20 TCP)
- **Window scale**: should match what you negotiate in the handshake
- **Timestamps**: present if RFC 1323 is implemented
- **SACK Permitted**: should be advertised even if you don't use selective retransmit

### Save and Replay Captures

```bash
# Save a capture during your test
sudo tcpdump -i tun0 -w /tmp/test_$(date +%s).pcap

# View it later
wireshark /tmp/test_*.pcap

# Compare two captures (before and after a fix)
tshark -r before.pcap -T fields -e tcp.analysis.retransmission | wc -l
tshark -r after.pcap  -T fields -e tcp.analysis.retransmission | wc -l
```

---

## Extended Deep Dive: Writing Packetdrill Tests

Packetdrill lets you write deterministic TCP test scripts. The syntax is straightforward: `+time` sets relative timing, `>` injects packets *into* your stack, `<` asserts packets your stack *emits*.

### Anatomy of a Packetdrill Script

```
# handshake.pkt — Test the three-way handshake

# Set up: your stack is the server at 192.0.2.1:8080
// Stack server IP and port (filled in by packetdrill)
0.000 socket(..., SOCK_STREAM, IPPROTO_TCP) = 3
0.000 bind(3, ..., ...) = 0
0.000 listen(3, 1) = 0

// Client (192.0.2.2) sends SYN
0.100 > S 0:0(0) win 65535 <mss 1460,sackOK,nop,wscale 6>

// Your stack must reply with SYN-ACK
0.100 < S. 0:0(0) ack 1 win 65535

// Client sends ACK to complete the handshake
0.200 > . 1:1(0) ack 1 win 65535

// Connection must now be ESTABLISHED; accept() must unblock
0.300 accept(3, ..., ...) = 4
```

### Complete Test Suite for This Project

```
tests/packetdrill/
├── 01_handshake.pkt          # Three-way handshake
├── 02_data_transfer.pkt      # Send and receive data
├── 03_retransmit_rto.pkt     # Segment dropped, RTO fires
├── 04_fast_retransmit.pkt    # 3 dup ACKs trigger retransmit
├── 05_fast_recovery.pkt      # Recovery without ssthresh halving twice
├── 06_zero_window.pkt        # Window goes to zero, probe and reopen
├── 07_simultaneous_close.pkt # Both sides send FIN simultaneously
├── 08_rst_handling.pkt       # RST in ESTABLISHED closes connection
├── 09_time_wait.pkt          # TIME_WAIT absorbs duplicate FINs
└── 10_window_scale.pkt       # Large transfer with window scaling
```

### Running Tests in CI

```bash
# Build with debug logging disabled (faster)
cargo build --release

# Grant CAP_NET_ADMIN so your binary can open TUN
sudo setcap cap_net_admin=eip target/release/tcp-stack

# Run all packetdrill tests
sudo packetdrill tests/packetdrill/*.pkt

# Run a single test verbosely
sudo packetdrill --verbose tests/packetdrill/03_retransmit_rto.pkt
```

---

## Extended Deep Dive: Performance Profiling

After Week 11 you have benchmarks. Here is how to interpret them and where to find the performance-critical paths.

### Flamegraph Analysis

```bash
# Install
cargo install flamegraph

# Profile a throughput run (requires perf)
sudo cargo flamegraph --bin tcp-stack -- --bench-mode

# Open in browser
firefox flamegraph.svg
```

**Common hot paths you will see:**

| Function | Why it's hot | Optimization |
|---|---|---|
| `internet_checksum` | Called for every IP, TCP, ICMP packet | SIMD, unrolled loops, or `crc32` hardware if available |
| `RecvBuffer::drain_ooo` | BTreeMap iteration on every ACK | Switch to a ring buffer with a bitmap for OOO tracking |
| `HashMap::get` (TCB lookup) | Called for every incoming TCP segment | Pre-hash key; use `AHashMap` instead of std HashMap |
| `Vec::extend_from_slice` in recv | Copies payload bytes into receive buffer | Map application buffer directly into recv ring |
| `TUN fd read()` | System call on every packet | Batch reads with `readv()` or `TUNSETQUEUE` multi-queue |

### Throughput Measurement

```bash
# Install iperf3
sudo apt-get install iperf3

# On your stack side (server mode) — your code runs the TcpListener
# iperf3 will connect from the host side through the TUN interface

iperf3 -s -B 192.168.0.2 -p 9999

# From another terminal (host-side client)
iperf3 -c 192.168.0.2 -p 9999 -t 30 -P 1

# Expected output for a non-optimized stack:
# [ ID] Interval       Transfer    Bitrate
# [  5]  0.00-30.00 s  14.7 GBytes  4.21 Gbits/sec  (loopback)
# [ actual userspace TCP stack ]: ~200-800 MB/s depending on implementation
```

### Latency Measurement

```bash
# Measure round-trip time at the TCP level using RFC 1323 timestamps
# (if you've implemented the Timestamps option)
# Otherwise, use ping for ICMP RTT as a proxy.

ping -c 100 192.168.0.2 | tail -1
# rtt min/avg/max/mdev = 0.042/0.051/0.091/0.008 ms
```

---

## Extended Deep Dive: Common Bugs and How to Fix Them

This is a curated list of the bugs that almost every implementer hits, with exact symptoms and fixes.

### Bug 1 — Checksum Wrong on First Packet

**Symptom:** Wireshark shows `[BAD CHECKSUM]` on your very first outgoing packet.  
**Cause:** Forgetting to zero the checksum field before computing it, or computing it over the wrong byte range.  
**Fix:**
```rust
// Before computing checksum, zero the checksum field
header[10] = 0;
header[11] = 0;
let csum = internet_checksum(&header);
header[10..12].copy_from_slice(&csum.to_be_bytes());
```

### Bug 2 — Ping Works, TCP Doesn't Connect

**Symptom:** `ping` succeeds but `telnet 192.168.0.2 8080` immediately gets `Connection refused`.  
**Cause:** The Linux kernel is also receiving the SYN and sending an RST because *it* owns that port, not your stack.  
**Fix:** Block the kernel from responding on your port:
```bash
sudo iptables -A INPUT -i tun0 -p tcp --dport 8080 -j DROP
sudo iptables -A OUTPUT -o tun0 -p tcp --sport 8080 -j DROP
```

### Bug 3 — SYN-ACK Sent, But Client Gets No Response

**Symptom:** Wireshark shows your SYN-ACK leaving tun0, but `telnet` says "No route to host".  
**Cause:** ARP cache miss. The kernel doesn't know your MAC address for the reverse path yet because you may have sent the SYN-ACK using the wrong source MAC.  
**Fix:** Ensure your ARP reply correctly sets the sender MAC to your TUN device's MAC, and your IP packet source IP matches what the ARP cache expects.

### Bug 4 — Data Transfer Stalls After ~64KB

**Symptom:** `curl` downloads 65,535 bytes of a large file, then hangs indefinitely.  
**Cause:** The receive window filled up. You filled `RCV.BUF` but never sent an updated window advertisement to the sender, so the sender stopped.  
**Fix:** After `read()` drains data from the receive buffer, send an ACK with the updated `RCV.WND` value even if there is no new data to ACK.

### Bug 5 — RST Storms After Connection Closes

**Symptom:** Wireshark shows dozens of RST packets after a `curl` completes.  
**Cause:** You're not implementing TIME_WAIT. After LAST_ACK → CLOSED, a delayed duplicate FIN arrives and your stack sends RST because the TCB no longer exists. The remote retransmits, you RST again, loop.  
**Fix:** Implement TIME_WAIT (2 × MSL = 2 × 60s = 120s). Keep the TCB in TIME_WAIT state. Drop packets silently during TIME_WAIT.

### Bug 6 — Retransmission Timer Never Fires

**Symptom:** A dropped packet causes the connection to hang forever with no retransmit.  
**Cause:** Timer not being checked in the main event loop. The RTO is computed but never triggered.  
**Fix:** In your main polling loop, after processing incoming packets, iterate over all active TCBs and check if `now >= tcb.rto_deadline`. If so, retransmit from `SND.UNA` and back off:
```rust
for tcb in connections.values_mut() {
    if tcb.retransmit_timer.is_expired(Instant::now()) {
        tcb.retransmit_from_una();
        tcb.congestion.on_timeout(tcb.send_buf.in_flight());
        tcb.rtt.backoff();
        tcb.retransmit_timer.reset(tcb.rtt.rto());
    }
}
```

### Bug 7 — Fast Retransmit Triggers on ACK Reordering

**Symptom:** One legitimate dup ACK (caused by a reordered packet, not a loss) causes unnecessary retransmit, halving `ssthresh`.  
**Cause:** Dup ACK counter is too sensitive.  
**Fix:** Only trigger fast retransmit on exactly 3 consecutive duplicate ACKs for the same sequence number. Reset the counter on any new ACK:
```rust
if ack_seq > self.snd_una {
    self.dup_ack_count = 0; // New ACK — reset counter
} else if ack_seq == self.snd_una {
    self.dup_ack_count += 1;
    if self.dup_ack_count == 3 {
        self.do_fast_retransmit();
    }
}
```

---

## Extended Deep Dive: macOS and WSL2 Notes

### macOS

macOS does not have `/dev/net/tun`. It uses the `utun` kernel extension instead. The API differs:

```rust
// macOS: open a utun device
// fd = socket(AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)
// Connect with: struct sockaddr_ctl { ... sc_id = utun_id, ... }
// Use UTUN_CONTROL_NAME = "com.apple.net.utun_control"
```

The `tun-tap` crate handles cross-platform TUN/TAP abstraction. Alternatively, use `utun` crate for macOS. The rest of the stack (Ethernet parsing upward) is identical.

### WSL2

WSL2 runs a real Linux kernel. TUN devices work, but with caveats:
- You may need to enable `CONFIG_TUN` if using a custom kernel.
- The TUN device is inside the WSL2 VM, not visible from Windows. Wireshark on the Windows host cannot see it — use `tcpdump` inside WSL2 instead.
- Network namespaces and iptables work normally inside WSL2.

```bash
# Check TUN support in WSL2
zcat /proc/config.gz | grep CONFIG_TUN
# CONFIG_TUN=m (loadable module) or CONFIG_TUN=y (built-in) — both fine

# Load TUN module if needed
sudo modprobe tun
```

---

## Extended Deep Dive: Async Architecture (Roadmap Item)

The current implementation uses a single-threaded blocking event loop. The roadmap lists async API as a planned feature. Here is what that migration looks like conceptually.

### Current: Blocking Event Loop

```
loop {
    poll(tun_fd + timer fds)  ← blocks until I/O ready
    read packet
    process packet
    write responses
}
```

### Future: Tokio-based Async

```rust
// Concept sketch — not in v1.0

use tokio::io::unix::AsyncFd;

pub struct AsyncTcpListener {
    tun: AsyncFd<TunDevice>,
    connections: Arc<Mutex<HashMap<FourTuple, Tcb>>>,
}

impl AsyncTcpListener {
    pub async fn accept(&self) -> io::Result<AsyncTcpStream> {
        loop {
            self.tun.readable().await?.clear_ready();
            // process packet, check accept queue
            if let Some(conn) = self.try_accept() {
                return Ok(conn);
            }
        }
    }
}
```

The challenge: TCP timer management in async Rust. The `tokio::time::sleep` approach works but requires careful cancellation when ACKs arrive before the RTO fires. Libraries like `tokio-util` provide timer wheels that map well onto the TCP timer model.

---

## Appendix A — TCP Header Field Reference

Complete field-by-field TCP header reference for implementers:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├─────────────────────────────────┬─────────────────────────────────┤
│         Source Port             │       Destination Port          │
├─────────────────────────────────┴─────────────────────────────────┤
│                        Sequence Number                             │
├────────────────────────────────────────────────────────────────────┤
│                     Acknowledgment Number                          │
├───────┬───┬─┬─┬─┬─┬─┬─┬─┬─┬───────────────────────────────────────┤
│ Data  │   │C│E│U│A│P│R│S│F│           Window Size                 │
│Offset │Res│W│C│R│C│S│S│Y│I│                                        │
│       │   │R│E│G│K│H│T│N│N│                                        │
├───────┴───┴─┴─┴─┴─┴─┴─┴─┴─┴───────────────────────────────────────┤
│            Checksum             │         Urgent Pointer           │
├─────────────────────────────────┴─────────────────────────────────┤
│                    Options (0–320 bits, variable)                  │
└────────────────────────────────────────────────────────────────────┘
```

| Field | Bits | Description | Implementation Notes |
|---|---|---|---|
| Source Port | 16 | Sender's port number | Key part of 4-tuple for TCB lookup |
| Dest Port | 16 | Receiver's port number | Key part of 4-tuple for TCB lookup |
| Sequence Number | 32 | Byte offset of first data byte in this segment | `SEG.SEQ` in RFC 793 |
| Acknowledgment Number | 32 | Next expected byte from peer (valid only if ACK flag set) | `SEG.ACK` in RFC 793 |
| Data Offset | 4 | Header length in 32-bit words (min 5 = 20 bytes) | Multiply by 4 to get byte length of header |
| Reserved | 3 | Must be zero | Ignore on receive |
| CWR | 1 | Congestion Window Reduced (ECN, RFC 3168) | v1.0: ignore |
| ECE | 1 | ECN-Echo (RFC 3168) | v1.0: ignore |
| URG | 1 | Urgent Pointer field significant | v1.0: ignore (rare in practice) |
| ACK | 1 | Acknowledgment Number field significant | Almost always set except in the very first SYN |
| PSH | 1 | Push: deliver to application immediately | Honor on receive; set on final byte of your write |
| RST | 1 | Reset the connection | Validate in-window before acting on; v1.0 abort TCB |
| SYN | 1 | Synchronize sequence numbers | Only in LISTEN and SYN_SENT processing |
| FIN | 1 | No more data from sender | Trigger FIN_WAIT / CLOSE_WAIT transition |
| Window | 16 | Receive window size (bytes peer will accept) | Multiply by window scale if negotiated |
| Checksum | 16 | One's complement over pseudo-header + segment | Must be verified on receive; computed on send |
| Urgent Pointer | 16 | Points to urgent data (if URG set) | v1.0: ignore |
| Options | 0–320 | Variable-length TLV options | Parse MSS, WSOPT, TSOPT, SACK-Permitted |

---

## Appendix B — IP Header Field Reference

| Field | Bits | Description | Implementation Notes |
|---|---|---|---|
| Version | 4 | IP version (4 for IPv4) | Assert == 4; drop otherwise |
| IHL | 4 | Header length in 32-bit words | Multiply by 4 for byte offset to payload |
| DSCP | 6 | Differentiated Services Code Point | Ignore in v1.0 |
| ECN | 2 | Explicit Congestion Notification | Ignore in v1.0 |
| Total Length | 16 | Total length of packet (header + data) | Use to determine end of payload |
| Identification | 16 | Fragment group identifier | Required for reassembly |
| Flags | 3 | Bit 0: reserved. Bit 1: DF (Don't Fragment). Bit 2: MF (More Fragments) | Check MF + Fragment Offset for reassembly |
| Fragment Offset | 13 | Offset of this fragment in 8-byte units | Multiply by 8 for byte offset |
| TTL | 8 | Time To Live (hop limit) | Decrement on forward; send ICMP Time Exceeded at 0 |
| Protocol | 8 | Upper-layer protocol (1=ICMP, 6=TCP, 17=UDP) | Use to dispatch to correct handler |
| Header Checksum | 16 | One's complement checksum over IP header only | Verify on receive; compute on send (zero the field first) |
| Source Address | 32 | Sender's IP address | 4-tuple key for TCP |
| Destination Address | 32 | Receiver's IP address | Must match your TUN device IP to process |
| Options | 0–320 | Rarely used (Strict Source Route, Record Route, etc.) | Ignore in v1.0 |

---

## Appendix C — ARP Packet Layout

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├─────────────────────────────────┬─────────────────────────────────┤
│       Hardware Type (1=ETH)     │     Protocol Type (0x0800=IP)   │
├──────────────────┬──────────────┼─────────────────────────────────┤
│ HW Addr Len (6)  │ Proto Len (4)│     Operation (1=Req, 2=Reply)  │
├──────────────────┴──────────────┴─────────────────────────────────┤
│                     Sender Hardware Address (6 bytes)              │
├────────────────────────────────────────────────────────────────────┤
│                      Sender Protocol Address (4 bytes)             │
├────────────────────────────────────────────────────────────────────┤
│                     Target Hardware Address (6 bytes)              │
├────────────────────────────────────────────────────────────────────┤
│                      Target Protocol Address (4 bytes)             │
└────────────────────────────────────────────────────────────────────┘
Total: 28 bytes for IPv4 over Ethernet
```

**Parsing in Rust:**

```rust
#[derive(Debug)]
pub struct ArpPacket {
    pub hw_type: u16,         // 1 = Ethernet
    pub proto_type: u16,      // 0x0800 = IPv4
    pub hw_len: u8,           // 6 for MAC
    pub proto_len: u8,        // 4 for IPv4
    pub operation: ArpOp,     // Request or Reply
    pub sender_mac: [u8; 6],
    pub sender_ip: Ipv4Addr,
    pub target_mac: [u8; 6],
    pub target_ip: Ipv4Addr,
}

#[repr(u16)]
#[derive(Debug, PartialEq)]
pub enum ArpOp { Request = 1, Reply = 2 }

impl ArpPacket {
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < 28 { return None; }
        Some(Self {
            hw_type:    u16::from_be_bytes([b[0], b[1]]),
            proto_type: u16::from_be_bytes([b[2], b[3]]),
            hw_len:     b[4],
            proto_len:  b[5],
            operation:  match u16::from_be_bytes([b[6], b[7]]) {
                            1 => ArpOp::Request,
                            2 => ArpOp::Reply,
                            _ => return None,
                        },
            sender_mac: b[8..14].try_into().unwrap(),
            sender_ip:  Ipv4Addr::new(b[14], b[15], b[16], b[17]),
            target_mac: b[18..24].try_into().unwrap(),
            target_ip:  Ipv4Addr::new(b[24], b[25], b[26], b[27]),
        })
    }

    pub fn to_bytes(&self) -> [u8; 28] {
        let mut b = [0u8; 28];
        b[0..2].copy_from_slice(&self.hw_type.to_be_bytes());
        b[2..4].copy_from_slice(&self.proto_type.to_be_bytes());
        b[4] = self.hw_len;
        b[5] = self.proto_len;
        b[6..8].copy_from_slice(&(self.operation as u16).to_be_bytes());
        b[8..14].copy_from_slice(&self.sender_mac);
        b[14..18].copy_from_slice(&self.sender_ip.octets());
        b[18..24].copy_from_slice(&self.target_mac);
        b[24..28].copy_from_slice(&self.target_ip.octets());
        b
    }
}
```

---

## Appendix D — ICMP Reference

| Type | Code | Name | Direction | Notes |
|---|---|---|---|---|
| 0 | 0 | Echo Reply | → you send | Response to type 8 |
| 3 | 0 | Destination Network Unreachable | ← receive | Routing failure |
| 3 | 1 | Destination Host Unreachable | ← receive | Host down |
| 3 | 3 | Destination Port Unreachable | ← receive | UDP port closed |
| 3 | 4 | Fragmentation Needed, DF Set | ← receive | PMTUD signal |
| 8 | 0 | Echo Request | ← receive | Incoming ping |
| 11 | 0 | Time Exceeded (TTL = 0 in transit) | → you send | When you decrement TTL to 0 |
| 11 | 1 | Time Exceeded (Fragment Reassembly) | → you send | Reassembly timeout |

**ICMP message format:**
```
Bytes 0–1: Type, Code
Bytes 2–3: Checksum (over ICMP header + data, including pseudo-header for ICMPv6)
Bytes 4–7: Identifier + Sequence Number (for Echo; 0 for error messages)
Bytes 8+:  Payload (echo: original data; error: original IP header + 8 bytes of original payload)
```

---

## Appendix E — Environment Variables Reference

| Variable | Default | Description |
|---|---|---|
| `LOG_LEVEL` | `info` | Log verbosity: `error`, `warn`, `info`, `debug`, `trace` |
| `TUN_DEVICE` | `tun0` | Name of the TUN interface to create |
| `TUN_IP` | `192.168.0.2` | IP address to assign to the TUN device |
| `TUN_NETMASK` | `255.255.255.0` | Subnet mask for TUN device |
| `TUN_MTU` | `1500` | MTU for the TUN device (affects MSS: MTU - 40) |
| `TCP_LISTEN_PORT` | `8080` | Port for the built-in HTTP server |
| `TCP_RECV_BUF_SIZE` | `65536` | Per-connection receive buffer size in bytes |
| `TCP_SEND_BUF_SIZE` | `65536` | Per-connection send buffer size in bytes |
| `TCP_ACCEPT_BACKLOG` | `128` | Maximum pending connections in accept queue |
| `TCP_TIME_WAIT_SECS` | `120` | TIME_WAIT duration (RFC 793: 2 × MSL = 2 × 60s) |
| `TCP_RTO_MIN_MS` | `1000` | Minimum retransmission timeout (RFC 6298: 1s) |
| `TCP_RTO_MAX_MS` | `60000` | Maximum retransmission timeout |
| `TCP_CONNECT_TIMEOUT_MS` | `75000` | Total timeout for SYN retransmission (RFC 793: ~75s) |
| `ARP_CACHE_TIMEOUT_SECS` | `300` | How long ARP cache entries are kept (Linux default: 60s) |

---

## Appendix F — Rust Crate Dependency Reference

A minimal `Cargo.toml` for this project and what each dependency does:

```toml
[package]
name = "tcp-stack"
version = "1.0.0"
edition = "2021"
rust-version = "1.78"

[dependencies]
# Logging
log     = "0.4"          # The log facade (log::info!, log::debug!, etc.)
env_logger = "0.11"      # Reads LOG_LEVEL env var, writes to stderr

# Error handling
thiserror = "1"          # Derive macro for error enums
anyhow    = "1"          # Convenient error propagation in main/bin code

# Networking types
std::net = { path = "" } # Ipv4Addr, SocketAddr — in stdlib, no dep needed

# Optionally for event loop
mio = { version = "0.8", features = ["os-poll", "net"] }  # Non-blocking I/O

# Optionally for benchmarks only
[dev-dependencies]
criterion = { version = "0.5", features = ["html_reports"] }
```

**Why no `tokio` in v1.0?**  
Async Rust adds significant complexity — `Pin`, `Poll`, `Waker`, `Future` state machines. For a learning project, the event loop in `mio` is simpler, maps more directly to what the kernel does (epoll), and avoids hiding the I/O model under abstractions. Async is listed in the [Roadmap](#roadmap) as a future enhancement.

---

## Appendix G — Systems Programming Reading Path

This project assumes intermediate Rust and basic C knowledge. If you need to fill gaps, here is the recommended reading order:

### Before You Start

1. **[The Rust Book](https://doc.rust-lang.org/book/)** — Chapters 1–15, 17–19. Especially: ownership, lifetimes, traits, error handling, iterators.
2. **[Rust by Example](https://doc.rust-lang.org/rust-by-example/)** — Practical code snippets for everything in The Book.
3. **[The Linux Programming Interface](https://man7.org/tlpi/)** — Michael Kerrisk. Chapters 1–6 (file I/O), 11 (system limits), 56–61 (sockets). Expensive but irreplaceable.

### During the Project

4. **[Computer Networks: A Top-Down Approach](https://gaia.cs.umass.edu/kurose_ross/index.php)** — Kurose & Ross. Read Chapter 3 (Transport Layer: TCP) cover to cover before Week 5.
5. **[TCP/IP Illustrated, Volume 1](https://www.pearson.com/us/higher-education/program/Stevens-TCP-IP-Illustrated-Volume-1-The-Protocols-2nd-Edition/PGM106896.html)** — W. Richard Stevens. The definitive byte-level protocol reference. Use as a desk reference alongside RFC 793.
6. **[RFC 793](https://www.rfc-editor.org/rfc/rfc793)** — TCP. Read the entire RFC, not just the parts you think you need.
7. **[RFC 6298](https://www.rfc-editor.org/rfc/rfc6298)** — RTO Computation. Four pages. Read before Week 7.
8. **[RFC 5681](https://www.rfc-editor.org/rfc/rfc5681)** — TCP Congestion Control. Eight pages. Read before Week 8.

### After You Finish

9. **[The Design and Implementation of the FreeBSD Operating System](https://www.pearson.com/us/higher-education/program/Mc-Kusick-The-Design-and-Implementation-of-the-Free-B-S-D-Operating-System-2nd-Edition/PGM237346.html)** — McKusick & Neville-Neil. How a real production network stack is structured.
10. **[Linux Kernel Networking: Implementation and Theory](https://www.apress.com/gp/book/9781430261964)** — Rami Rosen. Deep dive into the Linux TCP implementation you just replicated.
11. **[High Performance Browser Networking](https://hpbn.co/)** — Ilya Grigorik. Free online. See your work from the application layer perspective.
12. **[Russ Cox's blog (swtch.com)](https://swtch.com/~rsc/)** — systems programming at its finest.

---

## Appendix H — Glossary Extended

| Term | Definition |
|---|---|
| **ACK** | Acknowledgment. A TCP flag indicating that the Acknowledgment Number field is valid. |
| **AIMD** | Additive Increase, Multiplicative Decrease. The core congestion avoidance policy: increase `cwnd` linearly on success, halve it on loss. |
| **ARP** | Address Resolution Protocol. Maps Layer 3 IP addresses to Layer 2 MAC addresses on the same subnet. |
| **backlog** | The maximum number of completed (ESTABLISHED) connections waiting in the accept queue. Configurable via `listen(fd, backlog)`. |
| **big-endian** | Byte order where the most significant byte is stored at the lowest address. Used by all network protocols (hence "network byte order"). |
| **cwnd** | Congestion Window. The sender's self-imposed limit on unacknowledged bytes, managed by the congestion controller. |
| **Data Offset** | The TCP header field specifying where the payload starts (in 32-bit words from the beginning of the TCP header). |
| **dupACK** | Duplicate ACK. An ACK that acknowledges the same sequence number as a previous ACK. Three consecutive dupACKs trigger fast retransmit. |
| **EtherType** | A 2-byte field in the Ethernet header identifying the upper-layer protocol: `0x0800`=IPv4, `0x0806`=ARP, `0x86DD`=IPv6. |
| **FIN** | Finish. A TCP flag sent to signal that the sender has no more data to transmit. Initiates half-close. |
| **FIN_WAIT_1** | TCP state: local side has sent FIN, waiting for ACK or remote FIN. |
| **FIN_WAIT_2** | TCP state: local FIN has been ACKed, waiting for remote FIN. |
| **FlightSize** | `SND.NXT - SND.UNA`. The number of bytes sent but not yet acknowledged. |
| **four-tuple** | `(src_ip, src_port, dst_ip, dst_port)`. Uniquely identifies a TCP connection. Used as the key in the TCB HashMap. |
| **fragmentation** | Breaking an IP datagram into smaller pieces (fragments) to fit within the MTU of a link. Each fragment carries a Fragment Offset. |
| **go-back-N** | A retransmission strategy where all segments from the lost one are retransmitted. Simpler than selective repeat but less efficient. |
| **ICMP** | Internet Control Message Protocol. Carries diagnostic messages (ping, TTL exceeded, unreachable). Encapsulated in IP with protocol=1. |
| **IHL** | Internet Header Length. 4-bit field in IP header giving the header length in 32-bit words (min 5 = 20 bytes). |
| **ISN** | Initial Sequence Number. A randomly chosen starting value for a TCP connection's sequence numbers. Prevents collisions with old connections. |
| **ioctl** | A Linux system call for device-specific control operations. Used to configure TUN devices, network interfaces, etc. |
| **Karn's algorithm** | Rule that RTT samples from retransmitted segments must not be used to update SRTT/RTTVAR, preventing ambiguity about which transmission was ACKed. |
| **keep-alive** | Optional TCP mechanism: periodically send a probe segment to detect dead connections. Not implemented in v1.0. |
| **LAST_ACK** | TCP state: passive closer has sent FIN, waiting for the final ACK. |
| **LISTEN** | TCP state: socket is bound and waiting for incoming SYNs. The server state after `bind()` + `listen()`. |
| **MAC address** | Media Access Control address. 6-byte hardware identifier for a network interface. Used in Ethernet frames. |
| **MSL** | Maximum Segment Lifetime. The maximum time a TCP segment can remain in the network. RFC 793 suggests 2 minutes. TIME_WAIT = 2 × MSL. |
| **MSS** | Maximum Segment Size. The largest amount of data TCP will send in a single segment. Negotiated in the SYN options. Typically 1460 bytes (MTU 1500 - 40). |
| **MTU** | Maximum Transmission Unit. The largest frame a link can carry. Ethernet standard MTU is 1500 bytes. |
| **nagle's algorithm** | Coalesces small writes into fewer, larger TCP segments. Reduces chatty protocols' overhead. Not in v1.0; listed in roadmap. |
| **one's complement** | The arithmetic used by the Internet checksum: addition where carries wrap back into the low bits, and the final result is bitwise-NOT. |
| **out-of-order** | A TCP segment that arrives with a sequence number ahead of `RCV.NXT`. Must be buffered until the gap is filled. |
| **packetdrill** | A TCP/IP stack testing tool by Google. Scripts inject packets and assert expected responses. Used for protocol conformance testing. |
| **PMTUD** | Path MTU Discovery. TCP can discover the smallest MTU along a path using ICMP "Fragmentation Needed" messages and the IP Don't Fragment flag. |
| **PSH** | Push flag. Instructs the receiver to deliver buffered data to the application immediately. Set on the last segment of a write. |
| **pseudo-header** | A virtual header prepended to the TCP/UDP data for checksum computation purposes. Contains src IP, dst IP, protocol, and segment length. |
| **reassembly** | Reconstructing an original IP datagram from its received fragments, using the Identification, Fragment Offset, and MF flag. |
| **receive window** | `RCV.WND`. The amount of buffer space available at the receiver. Advertised in every outgoing segment. Throttles the sender's output. |
| **retransmit** | Re-sending a segment that was presumed lost (either by RTO timeout or three duplicate ACKs). |
| **RFC** | Request For Comments. The IETF documents that define Internet protocols. Standards-track RFCs are authoritative specifications. |
| **RST** | Reset. A TCP flag that immediately terminates a connection, discarding all buffered data. |
| **RTO** | Retransmission Timeout. The time after which an unacknowledged segment is retransmitted. Computed by Jacobson/Karels algorithm (RFC 6298). |
| **RTT** | Round-Trip Time. The time for a packet to travel from sender to receiver and back. Used to compute RTO. |
| **RTTVAR** | RTT Variance. The exponentially weighted variance of RTT samples. Used in RTO computation. |
| **SACK** | Selective ACKnowledgment. A TCP option (RFC 2018) where the receiver reports non-contiguous blocks of received data. |
| **send buffer** | A circular buffer storing data written by the application until it is acknowledged. Tracks `SND.UNA` and `SND.NXT`. |
| **slow start** | The initial phase of TCP congestion control where `cwnd` grows exponentially (doubled each RTT) until it reaches `ssthresh`. |
| **SND.NXT** | Send Next. The sequence number of the next byte to be sent. |
| **SND.UNA** | Send Unacknowledged. The sequence number of the oldest unacknowledged byte. Advances when ACKs arrive. |
| **SND.WND** | Send Window. The receiver's advertised window — how many bytes beyond `SND.UNA` the sender may transmit. |
| **SRTT** | Smoothed RTT. An exponentially weighted moving average of RTT samples. Used in RTO computation. |
| **ssthresh** | Slow Start Threshold. The `cwnd` value at which TCP transitions from slow start to congestion avoidance. |
| **SYN** | Synchronize. The TCP flag used to initiate a connection. A SYN segment carries the sender's ISN. |
| **SYN flood** | A DoS attack where an attacker sends many SYN packets to exhaust server connection state. Mitigated by SYN cookies (not in v1.0). |
| **SYN_RECEIVED** | TCP state: a SYN was received and SYN-ACK sent; waiting for the client's ACK to complete the handshake. |
| **SYN_SENT** | TCP state: a SYN has been sent (active open); waiting for SYN-ACK from the server. |
| **TAP** | A virtual Layer 2 network device. Like TUN but delivers Ethernet frames (with MAC headers) rather than raw IP packets. |
| **TCB** | Transmission Control Block. The data structure holding all state for one TCP connection: sequence numbers, buffers, timers, state. |
| **TIME_WAIT** | TCP state: both sides have closed. The connection lingers for 2 × MSL to absorb delayed duplicate packets. |
| **TUN** | A virtual Layer 3 network device. Delivers raw IP packets to a userspace process via a file descriptor. |
| **URG** | Urgent flag. Marks that the Urgent Pointer field is significant. Rarely used; not implemented in v1.0. |
| **window scale** | RFC 1323 option that multiplies the advertised window by a power of 2 (up to 2^14), allowing windows > 65535 bytes. |
| **zero-window** | `SND.WND = 0`. The sender must stop transmitting. Detected when the receiver's buffer is full. Triggers zero-window probing. |

---

## Appendix I — Interview Questions This Project Prepares You For

After completing this project, you will be able to answer these questions with depth and specific implementation experience:

### Network Fundamentals

- "Walk me through what happens at each layer of the stack when you run `curl https://example.com`."
- "What is ARP? When does it get invoked and what does it return?"
- "What is the difference between a TUN and a TAP device?"
- "How does IP fragmentation work, and why is it generally avoided today?"
- "What is the purpose of ICMP? Give three examples of ICMP messages you've worked with."

### TCP Internals

- "Explain the TCP three-way handshake. What is the purpose of each message?"
- "What is the Transmission Control Block? What fields does it contain?"
- "How does TCP guarantee reliable delivery? Walk me through the sequence/acknowledgment mechanism."
- "What is the difference between flow control and congestion control?"
- "Explain slow start. What is `ssthresh`? When does it change?"
- "What triggers fast retransmit? What happens to `cwnd` when it fires?"
- "Why does TIME_WAIT exist? What problems would occur without it?"
- "What is the RTO timer? How is it computed?"
- "What is Karn's algorithm and why is it necessary?"
- "How does window scaling work? Why is it needed?"

### Systems Programming

- "What is a file descriptor? How does `read()` on a TUN fd work?"
- "What is `ioctl`? Give an example of when you'd use it."
- "What is endianness? How do you handle it in network protocol parsing?"
- "What is the one's complement checksum and how do you verify it?"
- "How would you implement a circular buffer? What are the key invariants?"
- "How do you handle wrapping arithmetic on 32-bit sequence numbers in Rust?"

### Rust Systems Programming

- "How does Rust's ownership system help with buffer management in a network stack?"
- "What are the tradeoffs between zero-copy parsing and owning parsed structs?"
- "How would you profile a Rust network application for throughput bottlenecks?"
- "When would you choose `mio` over `tokio` for an event-driven server?"

---

## Appendix J — Final Project Checklist

Use this checklist before tagging `v1.0.0`:

### Correctness
- [ ] ARP: responds to requests for own IP, caches sender mappings
- [ ] ICMP: replies to echo requests with correct checksum
- [ ] IP: validates header checksum on receive, computes on send
- [ ] IP: handles fragmented packets (both in and out)
- [ ] TCP: correct three-way handshake (SYN, SYN-ACK, ACK)
- [ ] TCP: reliable data transfer with sequence numbers and ACKs
- [ ] TCP: retransmits on RTO timeout with exponential backoff
- [ ] TCP: fast retransmit on 3 duplicate ACKs
- [ ] TCP: congestion control (slow start, AIMD, fast recovery)
- [ ] TCP: flow control (receive window, zero-window probe)
- [ ] TCP: window scaling (RFC 1323)
- [ ] TCP: graceful teardown (FIN/ACK/FIN/ACK)
- [ ] TCP: RST handling (in-window validation)
- [ ] TCP: TIME_WAIT (2 × MSL, absorbs retransmitted FINs)
- [ ] API: TcpListener::bind, accept, TcpStream::read, write, shutdown
- [ ] App: HTTP/1.0 server serves a response to `curl`

### Testing
- [ ] All packetdrill tests pass (`10/10`)
- [ ] `ping -c 100 192.168.0.2` returns 100 replies, 0% loss
- [ ] `curl http://192.168.0.2:8080/` returns correct response
- [ ] `iperf3` throughput test runs without errors
- [ ] Simultaneous `curl` from 3 terminals works

### Quality
- [ ] `cargo fmt --check` passes
- [ ] `cargo clippy -- -D warnings` passes
- [ ] `cargo test` passes
- [ ] No `unwrap()` on packet parsing paths (use `?` or graceful drop)
- [ ] Malformed packets are dropped without panic
- [ ] LOG_LEVEL=trace produces useful output for every packet

### Documentation
- [ ] README complete with architecture diagram and benchmark table
- [ ] `ARCHITECTURE.md` explains key design decisions
- [ ] All public types and functions have `///` doc comments
- [ ] `cargo doc --open` generates useful documentation

### CI / Release
- [ ] GitHub Actions CI runs on every push
- [ ] All CI checks pass on main branch
- [ ] `CHANGELOG.md` has v1.0.0 entry
- [ ] Tagged: `git tag v1.0.0`
- [ ] Demo GIF or `asciinema` recording embedded in README

---

*Built with RFC 793, a lot of Wireshark, and unreasonable amounts of patience.*
*"The best way to understand a protocol is to implement it. You now have."*

---

## Appendix K — What This README Got Wrong (Gap Analysis)

The following issues were identified after review. Each represents a gap in correctness, completeness, or accuracy that will bite real implementors.

---

### 1. The macOS Section Is Missing

The prerequisites table states "macOS requires `utun` — see [macOS]" but no macOS section exists anywhere in this document. That link is dead. The actual path on macOS is non-trivial: you need to open a `utun` device via `socket(AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)` and the `CTLIOCGINFO` ioctl, which is completely different from the Linux TUN path. Either write this section or remove the reference entirely.

---

### 2. WSL2 Caveats Are Promised But Never Delivered

The prerequisites table says "WSL2 works with caveats (see FAQ)." The FAQ contains no WSL2 content. The actual caveats are significant and will block someone on day one:

- TUN device access requires WSL2 kernel 5.15+ with `CONFIG_TUN=m` compiled in (not all distros ship this).
- `tc netem` (used in Week 6 and Week 8 milestones for packet loss simulation) does not work inside WSL2 network namespaces without additional kernel config.
- The network interface created by WSL2 sits behind a NAT; the `192.168.0.2` setup may conflict with WSL2's own virtual adapter range.

Document these or remove the claim.

---

### 3. `CHANGELOG.md` Is Required by the Checklist but Absent from the Project Structure

Appendix J demands a `CHANGELOG.md` with a v1.0.0 entry as a release criterion. The project structure in the Project Structure section does not include `CHANGELOG.md`. Someone doing a clean implementation from this README will hit the checklist requirement with no prior guidance that the file needed to exist. Add it to the project structure tree.

---

### 4. Karn's Algorithm Is in the Interview Questions but Never Taught

Appendix I lists "What is Karn's algorithm and why is it necessary?" as an expected interview outcome of this project. Karn's algorithm does not appear anywhere in the 12-week curriculum. The RTT estimation section in Week 6 implements Jacobson/Karels correctly but omits the critical constraint: **do not update RTT samples using retransmitted segments**, because you cannot know which transmission an ACK is acknowledging.

An implementation following this README as written will compute incorrect SRTT/RTTVAR under packet loss, leading to RTO values that are systematically too short or too long. Add Karn's algorithm to Week 6 alongside the Jacobson/Karels code. Reference: RFC 6298 §3, rule (5.7).

---

### 5. The ISN Code Sample Uses Non-Cryptographic Randomness

Week 5 correctly identifies that the ISN must be cryptographically random, citing 1990s TCP sequence prediction attacks. But the code sample uses `rand::thread_rng().gen()`, which is **not** a cryptographically secure RNG. In Rust, `rand::thread_rng()` is documented as "suitable for simulation" — it is seeded from OS entropy but is not guaranteed CSPRNG behavior across platforms or future `rand` versions.

The correct approach is `rand::rngs::OsRng` or, better, the RFC 6528 construction (hash of source/dest 4-tuple + secret key + timestamp). Fix the sample:

```rust
use rand::rngs::OsRng;
use rand::RngCore;
fn gen_isn() -> u32 { OsRng.next_u32() }
```

Also add a reference to RFC 6528 for the full production-grade ISN algorithm.

---

### 6. No Acknowledgment of Overlapping Segment Attacks or RFC 4953

The Known Limitations section documents missing features (Nagle, CUBIC, etc.) but says nothing about attack surface. A "production-grade understanding" project should at minimum acknowledge:

- **Overlapping segment reassembly ambiguity** (Ptacek & Newsham, 1998): different TCP stacks handle overlapping out-of-order segments differently, which IDS systems historically exploited. Your receive buffer's reorder logic in Week 6 makes an implicit policy choice here — document it.
- **SYN flood**: mentioned in the glossary but not addressed. SYN cookies (RFC 4938) are the mitigation; the reader should know why they aren't implemented and what the consequence is.
- **RST injection**: the Week 5 note to validate RST sequence numbers per RFC 5961 is correct but buried. It should be a named limitation with a test case.

Add a Security Considerations section or expand Known Limitations to cover these. Reference: RFC 4953 — Defending TCP Against Spoofing Attacks.

---

### 7. Latent Bug in `send_window()`: Window Scaling Not Applied Before Cast

The flow control code sample in Week 7 is:

```rust
fn send_window(&self) -> usize {
    let rwnd = self.peer_rwnd as usize;
    let cwnd = self.cwnd;
    let in_flight = (self.snd_nxt.wrapping_sub(self.snd_una)) as usize;
    min(rwnd, cwnd).saturating_sub(in_flight)
}
```

If `peer_rwnd` is stored as the raw wire value (a `u16`) and window scaling has been negotiated, the effective window is `peer_rwnd << scale_factor`, which can far exceed `u16::MAX` (65535 bytes). As written, the cast silently caps the sender's window at 65535 bytes regardless of the negotiated scale factor, breaking high-throughput connections on modern networks. The stored field must be either the pre-scaled value, or the scale factor must be applied here explicitly. Add a comment and a note in Week 7.

---

### 8. No Context for Why You're Implementing Reno, Not CUBIC or BBR

The congestion control curriculum teaches RFC 5681 (NewReno) as *the* congestion control algorithm. No mention is made that:

- Linux has defaulted to **CUBIC** since kernel 2.6.19 (2006).
- **BBR** (Bottleneck Bandwidth and Round-trip propagation time) has been the recommended algorithm for high-bandwidth paths since 2016.
- NewReno is what RFC 793-era TCP did; teaching it as the end state leaves the reader unaware that real-world TCP looks substantially different.

Add a paragraph at the end of Week 8 contextualizing NewReno as the correct learning foundation while pointing to RFC 8312 (CUBIC) and the 2016 BBR paper as natural next steps. This costs two sentences and prevents a false impression of the state of the art.

---

### 9. No Guidance on Creating the `asciinema` Recording

The final checklist (Appendix J) requires a "Demo GIF or `asciinema` recording embedded in README" as a release criterion. There is no guidance anywhere in the project on how to create one. Add a brief note:

```bash
# Install
sudo apt-get install asciinema

# Record
asciinema rec demo.cast

# Convert to GIF for embedding (requires agg)
cargo install --git https://github.com/asciinema/agg
agg demo.cast demo.gif
```

Then embed in README with: `![demo](demo.gif)`

This is a minor but real gap — someone will hit the checklist item with no idea what tool to use.