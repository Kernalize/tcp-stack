# tcp-stack

A **TCP/IP stack built from scratch in Rust**, running in userspace over a Linux TUN device. It
hand-parses and hand-builds Ethernet-free IPv4, ICMP, UDP, and TCP — no smol/embassy/std-net doing
the protocol work — and implements enough of TCP (RFC 9293 + 6298 + 5681) that a stock `ping`,
`nc`, and `curl` interoperate with it: handshake, reliable in-order transfer, adaptive
retransmission, flow control, out-of-order reassembly, congestion control, and clean teardown.

It is also a **teaching project**: every feature ships with a heavily-commented reference module
and a from-scratch chapter in [`docs/`](docs/) (`day1-book.md` … `day18-book.md`).

> Status: the full TCP **connection lifecycle** is implemented and unit-tested (101 tests, offline).
> What's *not* done is breadth/robustness hardening and live conformance/throughput testing — see
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
  congestion.rs  congestion control state machine (RFC 5681)
  utils.rs       the shared Internet checksum
```

The "socket API" is `Connection::{write, take_received, poll_transmit}` + the event loop; a
blocking `TcpListener`/`TcpStream` veneer is left as an exercise (see `docs/day11-book.md` §11).

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

- **Hardening:** RFC 5961 in-window RST/SYN validation, a distinct CLOSE_WAIT (today we fuse it
  with the FIN-ACK on the echo path), half-close, and modern congestion control (NewReno/CUBIC —
  we ship RFC 5681 Reno). SACK uses the pragmatic "skip SACKed ranges, resend only the holes" of
  RFC 2018, not the full RFC 6675 scoreboard/pipe estimator.
- **A blocking `TcpListener`/`TcpStream`** facade and multi-request/keep-alive HTTP.
- **Live conformance + load testing:** `packetdrill` against the kernel, `iperf3` throughput under
  `tc netem`, profiling/flamegraphs (needs sudo/TUN and live runs).
- Outgoing data is not yet segmented below one delivered run; the HTTP responder matches the
  request line rather than buffering full headers.

## Learning OS

This repo follows a "from scratch" learning discipline: the cores are meant
to be hand-typed, with the `docs/*-book.md` chapters as the guide. Each book ends with a
blank-file rebuild checklist and exercises.
