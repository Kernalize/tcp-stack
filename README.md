# tcp-stack

[![CI](https://github.com/Kernalize/tcp-stack/actions/workflows/ci.yml/badge.svg)](https://github.com/Kernalize/tcp-stack/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-stable-orange.svg)](https://www.rust-lang.org/)
![Tests](https://img.shields.io/badge/tests-151%20passing-brightgreen.svg)

A **TCP/IP stack built from scratch in Rust**, running in userspace over a Linux TUN device. It
hand-parses and hand-builds Ethernet-free IPv4, ICMP, UDP, and TCP — no smol/embassy/std-net doing
the protocol work — and implements enough of TCP (RFC 9293 + 6298 + 5681) that a stock `ping`,
`nc`, and `curl` interoperate with it: handshake, reliable in-order transfer, adaptive
retransmission, flow control, out-of-order reassembly, congestion control, and clean teardown.

It is also **thoroughly documented**: every feature ships with a heavily-commented reference module
and a from-first-principles chapter in [`docs/`](docs/) (`doc1-book.md` … `doc29-book.md`), compiled
into a single-volume [`docs/BOOK.md`](docs/BOOK.md).

> Status: the full TCP **connection lifecycle**, modern loss recovery, a socket API, and RFC
> 5961/1337 robustness — plus both **CUBIC and BBR** congestion control — are implemented and
> unit-tested (151 tests, offline). What's *not* done is live conformance/throughput testing — see
> [Limitations](#limitations).

## What works

| # | Feature | RFC | Doc |
|----:|---------|-----|------|
| 1 | Receive packets; decode IPv4 + ICMP + peek TCP | 791 / 792 | doc1 |
| 2 | Internet checksum; reply to pings | 1071 | doc2 |
| 3 | TCP three-way handshake (passive + active open), randomized ISN | 9293 / 6528 | doc3 |
| 4 | Data transfer: accept, ACK, echo | 9293 | doc4 |
| 5 | Passive close (FIN → LAST_ACK → CLOSED) | 9293 | doc5 |
| 6 | Reliability: non-blocking event loop, retransmission queue, **adaptive RTO** (Karn's) | 6298 | doc6 |
| 7 | Active close + TIME_WAIT (full teardown, both sides) | 9293 | doc7 |
| 8 | Flow control (track peer window, advertise our own) | 9293 | doc8 |
| 9 | Out-of-order **reassembly** (buffer + deliver contiguous) | 9293 | doc9 |
| 10 | **Congestion control**: slow start, AIMD, fast retransmit/recovery | 5681 | doc10 |
| 11 | Socket-style read/write API + send buffer + tiny **HTTP/1.0** server | 9293 | doc11 |
| 12 | Retransmit control segments (SYN, SYN-ACK, FIN) + exponential RTO backoff | 9293 / 6298 | doc12 |
| 13 | **Nagle's algorithm** + the `TCP_NODELAY` escape hatch | 896 / 9293 | doc13 |
| 14 | **Zero-window probes** (the persist timer) | 9293 | doc14 |
| 15 | **TCP options** framework + **MSS** negotiation | 9293 | doc15 |
| 16 | **Timestamps**: per-ACK RTT measurement + PAWS | 7323 | doc16 |
| 17 | **Window scaling** (SND.WND widened to 32 bits) | 7323 | doc17 |
| 18 | **SACK**: selective-ACK blocks + hole-only retransmission | 2018 | doc18 |
| 19 | **Finish the state machine**: half-close via a distinct **CLOSE_WAIT**, data+FIN, **RFC 5961** RST/SYN challenge ACKs + RFC 1337 | 9293 / 5961 / 1337 | doc19 |
| 20 | **NewReno**: recover from *multiple* losses per window via partial-ACK handling (no RTO stall) | 6582 | doc20 |
| 21 | **SACK loss recovery**: `pipe` estimator + `IsLost`, retransmit every hole and refill in one RTT | 6675 | doc21 |
| 22 | **Socket API**: blocking `TcpListener`/`TcpStream` (loopback-tested), active half-close, keep-alive HTTP/1.1 | 9293 / 9112 | doc22 |
| 23 | **Robustness**: RFC 5961 §5 blind-data ACK check + randomized challenge-ACK throttle (CVE-2016-5696) + reaper timeouts | 5961 | doc23 |
| 24 | **RACK-TLP**: time-based loss detection + Tail Loss Probe — fast tail-loss recovery, reordering tolerance | 8985 | doc24 |
| 25 | **CUBIC**: cubic-curve congestion avoidance for fat pipes (β = 0.7, RTT-independent) | 8312 / 9438 | doc25 |
| 26 | **Keepalive** (`SO_KEEPALIVE`): probe an idle connection to detect a vanished peer | 9293 | doc26 |
| 27 | **SYN cookies**: survive a SYN flood — encode the handshake in the SYN-ACK ISN, allocate no TCB until a valid cookie returns | 4987 | doc27 |
| 28 | **BBR**: model-based congestion control — BtlBw/RTprop filters + STARTUP/DRAIN/PROBE_BW/PROBE_RTT; the live server's controller | (BBR draft) | doc28 |
| 29 | **Multi-connection `TcpServer`**: demux a 4-tuple connection table over one transport — many connections at once | 9293 | doc29 |

Plus: UDP echo, and `RST` for segments to unknown/closed connections.

## Architecture

A single-threaded, non-blocking event loop (`src/main.rs`) drives a table of per-connection TCBs.
Protocol logic lives in focused modules:

```text
src/
  main.rs        event loop: TUN I/O, timers, connection table, the echo/HTTP application
  ip.rs          IPv4 parse + header checksum
  icmp.rs        ICMP parse + echo reply
  udp.rs         UDP parse + pseudo-header checksum + echo
  tcp.rs         the heart: TcpHeader, the Connection state machine, retransmission queue,
                 send/receive buffers, the socket-style write/take_received/poll_transmit API
  seq.rs         32-bit wrapping sequence-number arithmetic (RFC 1982 serial numbers)
  rtt.rs         RTT estimator + adaptive RTO (RFC 6298)
  reassembly.rs  out-of-order receive buffer
  congestion.rs  loss-based control: slow start, fast recovery, NewReno + CUBIC (5681/6582/8312)
  bbr.rs         model-based control: BtlBw/RTprop filters + STARTUP/DRAIN/PROBE_BW/PROBE_RTT
  http.rs        HTTP/1.x request parsing + keep-alive responder (used by main's server)
  socket.rs      TcpListener/TcpStream façade + multi-connection TcpServer over a PacketIo trait
  utils.rs       the shared Internet checksum
```

The low-level "socket API" is `Connection::{write, take_received, poll_transmit}` + the event loop;
`socket.rs` wraps it in a blocking, `std::net`-shaped `TcpListener`/`TcpStream` over a `PacketIo`
transport trait (loopback-tested offline; see `docs/doc22-book.md`), plus a multi-connection
`TcpServer` that demuxes a 4-tuple connection table over one transport — many concurrent
connections at once, the same way `main` does for the live stack.

## Build & test

Linux-only (needs `/dev/net/tun` + `CAP_NET_ADMIN`); developed from Windows via WSL2. Build
artifacts go to a native-fs target dir (see `.cargo/config.toml`) so `setcap` works.

```bash
# Verify correctness offline — no sudo, no TUN, no network:
cargo test          # 151 unit tests: parsers vs known packets, the state machine, RTT/cwnd math,
                    # reassembly, retransmission, options (MSS/timestamps/wscale/SACK), and a
                    # differential check against `etherparse`
cargo clippy        # clean
```

## Run it live

Needs Linux with `/dev/net/tun` (run via WSL2 on Windows). Step-by-step environment setup:
[`docs/setup-windows.md`](docs/setup-windows.md) · [`docs/setup-kali.md`](docs/setup-kali.md). An
optional Docker workflow lives in [`scripts/`](scripts/) (`dev.sh` / `new_terminal.sh`).

```bash
# Terminal 1 — run the stack (the target dir is set to native fs in .cargo/config.toml so
# setcap works — /mnt/c can't hold Linux xattrs):
cargo build
BIN=~/.tcp-stack-target/debug/tcp-stack
sudo setcap cap_net_admin=eip "$BIN" && "$BIN"

# Terminal 2 — wire up the interface, then talk to it:
sudo ip addr add 192.168.0.1/24 dev tun0 && sudo ip link set tun0 up
ping 192.168.0.2                  # ICMP echo reply (0% loss)
nc 192.168.0.2 8080               # TCP echo: type a line, get it back
curl http://192.168.0.2:8080/     # HTTP/1.0 200 OK, then a clean close

# See reliability engage under loss:
sudo tc qdisc add dev tun0 root netem loss 5% reorder 25% 50%
# ...retransmissions + reassembly keep the connection intact; remove with:
sudo tc qdisc del dev tun0 root
```

## Limitations

This is a correct, tested *core*, not a production stack. The congestion-control family is now
complete — both the loss-based **CUBIC** (Doc 25) over NewReno + RFC 6675 SACK recovery (Docs 20–21)
with **RACK-TLP** time-based loss detection (Doc 24), and the model-based **BBR** (`src/bbr.rs`:
BtlBw/RTprop filters + STARTUP→DRAIN→PROBE_BW→PROBE_RTT, which the live server now runs) — alongside
RFC 5961 RST/SYN/data challenge ACKs (Docs 19, 23) throttled per CVE-2016-5696, CLOSE_WAIT/FIN_WAIT_2
reaping (Doc 23), `SO_KEEPALIVE` (Doc 26), and **SYN cookies** for SYN-flood survival (Doc 27). The
socket façade (`src/socket.rs`) ships both the single-connection blocking `TcpListener`/`TcpStream`
(Doc 22) and a **multi-connection `TcpServer`** that demuxes a connection table over one transport.

What remains is not algorithm work but live exercise, which needs sudo/TUN and a real network rather
than offline unit tests:

- **Live conformance + load testing:** `packetdrill` against the kernel, `iperf3` throughput under
  `tc netem`, profiling/flamegraphs.
- **Rate-paced transmission:** BBR computes a pacing rate (`pacing_rate_bps`, surfaced by the live
  server), but the sender is still window-limited — actually pacing sends to that rate is the natural
  next step and only matters under bulk transfer, which the echo server never drives.

## Built from scratch

Every protocol here is hand-implemented directly from the RFCs — no protocol library does the work.
The `docs/*-book.md` chapters derive each feature from first principles (mental model → mechanism →
header/byte layout → the Rust → verification → a "why this, not that" rationale), and each ends with
a from-blank rebuild checklist and exercises, so the implementation can be reconstructed module by
module. Design rules enforced throughout: time is injected (`now_ms`), never read from a clock, so
every timer is unit-testable without sleeping; sequence comparisons go through `seq::` (the space
wraps); and shared helpers live once. Correctness is proven offline — 151 unit tests, clippy-clean
under `-D warnings`, run in CI on every push.

## License

[MIT](LICENSE).
