# tcp-stack

A **TCP/IP stack built from scratch in Rust**, running in userspace over a Linux TUN device. It
hand-parses and hand-builds Ethernet-free IPv4, ICMP, UDP, and TCP — no smol/embassy/std-net doing
the protocol work — and implements enough of TCP (RFC 9293 + 6298 + 5681) that a stock `ping`,
`nc`, and `curl` interoperate with it: handshake, reliable in-order transfer, adaptive
retransmission, flow control, out-of-order reassembly, congestion control, and clean teardown.

It is also a **teaching project**: every feature ships with a heavily-commented reference module
and a from-scratch chapter in [`docs/`](docs/) (`day1-book.md` … `day18-book.md`).

> Status: the full TCP **connection lifecycle**, modern loss recovery, a socket API, and RFC
> 5961/1337 robustness are implemented and unit-tested (129 tests, offline). What's *not* done is
> live conformance/throughput testing and breadth (CUBIC, RACK-TLP, SYN cookies, keepalive) — see
> [Limitations](#limitations).

## What works

| Day | Feature | RFC | Book |
|----:|---------|-----|------|
| 1 | Receive packets; decode IPv4 + ICMP + peek TCP | 791 / 792 | day1 |
| 2 | Internet checksum; reply to pings | 1071 | day2 |
| 3 | TCP three-way handshake (passive + active open), randomized ISN | 9293 / 6528 | day3 |
| 4 | Data transfer: accept, ACK, echo | 9293 | day4 |
| 5 | Passive close (FIN → LAST_ACK → CLOSED) | 9293 | day5 |
| 6 | Reliability: non-blocking event loop, retransmission queue, **adaptive RTO** (Karn's) | 6298 | day6 |
| 7 | Active close + TIME_WAIT (full teardown, both sides) | 9293 | day7 |
| 8 | Flow control (track peer window, advertise our own) | 9293 | day8 |
| 9 | Out-of-order **reassembly** (buffer + deliver contiguous) | 9293 | day9 |
| 10 | **Congestion control**: slow start, AIMD, fast retransmit/recovery | 5681 | day10 |
| 11 | Socket-style read/write API + send buffer + tiny **HTTP/1.0** server | 9293 | day11 |
| 12 | Retransmit control segments (SYN, SYN-ACK, FIN) + exponential RTO backoff | 9293 / 6298 | day12 |
| 13 | **Nagle's algorithm** + the `TCP_NODELAY` escape hatch | 896 / 9293 | day13 |
| 14 | **Zero-window probes** (the persist timer) | 9293 | day14 |
| 15 | **TCP options** framework + **MSS** negotiation | 9293 | day15 |
| 16 | **Timestamps**: per-ACK RTT measurement + PAWS | 7323 | day16 |
| 17 | **Window scaling** (SND.WND widened to 32 bits) | 7323 | day17 |
| 18 | **SACK**: selective-ACK blocks + hole-only retransmission | 2018 | day18 |
| 19 | **Finish the state machine**: half-close via a distinct **CLOSE_WAIT**, data+FIN, **RFC 5961** RST/SYN challenge ACKs + RFC 1337 | 9293 / 5961 / 1337 | day19 |
| 20 | **NewReno**: recover from *multiple* losses per window via partial-ACK handling (no RTO stall) | 6582 | day20 |
| 21 | **SACK loss recovery**: `pipe` estimator + `IsLost`, retransmit every hole and refill in one RTT | 6675 | day21 |
| 22 | **Socket API**: blocking `TcpListener`/`TcpStream` (loopback-tested), active half-close, keep-alive HTTP/1.1 | 9293 / 9112 | day22 |
| 23 | **Robustness**: RFC 5961 §5 blind-data ACK check + randomized challenge-ACK throttle (CVE-2016-5696) + reaper timeouts | 5961 | day23 |

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
  congestion.rs  congestion control: slow start, AIMD, fast recovery + NewReno partial-ACK (5681/6582)
  http.rs        HTTP/1.x request parsing + keep-alive responder (used by main's server)
  socket.rs      blocking TcpListener/TcpStream façade over a PacketIo trait (embeddable; loopback-tested)
  utils.rs       the shared Internet checksum
```

The low-level "socket API" is `Connection::{write, take_received, poll_transmit}` + the event loop;
`socket.rs` wraps it in a blocking, `std::net`-shaped `TcpListener`/`TcpStream` over a `PacketIo`
transport trait — single-connection and loopback-tested offline (see `docs/day22-book.md`).

## Build & test

Linux-only (needs `/dev/net/tun` + `CAP_NET_ADMIN`); developed from Windows via WSL2. Build
artifacts go to a native-fs target dir (see `.cargo/config.toml`) so `setcap` works.

```bash
# Verify correctness offline — no sudo, no TUN, no network:
cargo test          # 101 unit tests: parsers vs known packets, the state machine, RTT/cwnd math,
                    # reassembly, retransmission, options (MSS/timestamps/wscale/SACK), and a
                    # differential check against `etherparse`
cargo clippy        # clean
```

## Run it live

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

This is a correct, tested *core*, not a production stack. Not yet implemented (all are genuine
TCP features, several are exercises in the day-books):

- **Hardening:** CUBIC/BBR-class congestion control (we ship **NewReno** over RFC 5681 Reno, Day 20)
  and RACK-TLP/tail-loss probing (we ship the RFC 6675 `pipe`/`IsLost` core, Day 21, with the RTO as
  the tail-loss fallback). RFC 5961 RST/SYN/data challenge ACKs (Days 19, 23) are throttled per
  CVE-2016-5696, and CLOSE_WAIT/FIN_WAIT_2 are reaped (Day 23); still missing are **SYN cookies**
  (SYN-flood defence) and **`SO_KEEPALIVE`**.
- **A multi-connection socket facade.** We ship a single-connection blocking `TcpListener`/`TcpStream`
  over a `PacketIo` trait (Day 22, loopback-tested) and keep-alive HTTP/1.1, but the façade demuxes
  one connection at a time and isn't wired into `main` (which keeps its own multi-protocol loop).
- **Live conformance + load testing:** `packetdrill` against the kernel, `iperf3` throughput under
  `tc netem`, profiling/flamegraphs (needs sudo/TUN and live runs).

## Learning OS

This repo follows a "from scratch" learning discipline: the cores are meant
to be hand-typed, with the `docs/*-book.md` chapters as the guide. Each book ends with a
blank-file rebuild checklist and exercises.
