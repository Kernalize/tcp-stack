//! tcp-stack — a userspace TCP/IP stack built from scratch over a Linux TUN device.
//!
//! Progress:
//!   Day 1 — receive packets, DECODE IPv4 + ICMP + peek TCP            (docs/day1-book.md)
//!   Day 2 — Internet checksum + REPLY to pings (ping succeeds)        (docs/day2-book.md)
//!   Day 3 — TCP three-way handshake (SYN→SYN-ACK→ESTABLISHED)         (docs/day3-book.md)
//!   Day 4 — TCP data transfer: accept + ACK + echo data back          (docs/day4-book.md)
//!   Day 5 — TCP teardown: FIN handling → LAST_ACK → CLOSED            (docs/day5-book.md)
//!   Day 6 — reliability: non-blocking event loop + retransmission + adaptive RTO (docs/day6-book.md)
//!   Day 7 — active close + TIME_WAIT (full RFC 9293 teardown, both sides)   (docs/day7-book.md)
//!   Day 8 — flow control: track the peer's window + advertise our own       (docs/day8-book.md)
//!   Day 9 — out-of-order reassembly: buffer + deliver contiguous data       (docs/day9-book.md)
//!   Day 10 — congestion control: slow start + AIMD + fast recovery (RFC 5681)(docs/day10-book.md)
//!   Day 11 — socket-style read/write API + send buffer + tiny HTTP/1.0 server (docs/day11-book.md)
//!   Day 12 — retransmit the control segments too: SYN, SYN-ACK, FIN (docs/day12-book.md)
//!   Day 13 — Nagle's algorithm + TCP_NODELAY: coalesce small writes (docs/day13-book.md)
//!   Day 14 — zero-window probes (persist timer): break the flow-control deadlock (docs/day14-book.md)
//!   Day 15 — TCP options: MSS negotiation + segment outgoing data to it (docs/day15-book.md)
//!   Day 16 — TCP timestamps: per-ACK RTT measurement + PAWS (RFC 7323) (docs/day16-book.md)
//!   Day 17 — window scaling: honor the peer's scaled window, SND.WND→u32 (docs/day17-book.md)
//!   Day 18 — SACK: negotiate SACK-Permitted, emit SACK blocks for out-of-order data, and
//!            retransmit only the holes a peer's SACK blocks reveal (docs/day18-book.md, RFC 2018)
//!   Day 19 — finish the state machine: real half-close via CLOSE_WAIT (distinct from LAST_ACK)
//!            + RFC 5961 in-window RST/SYN validation with challenge ACKs (docs/day19-book.md)
//!   Day 20 — NewReno: recover from MULTIPLE losses in one window via partial-ACK handling, no RTO
//!            stall (docs/day20-book.md, RFC 6582)
//!   Day 21 — SACK loss recovery: pipe estimator + IsLost, retransmit every hole and fill the pipe
//!            in one round trip (docs/day21-book.md, RFC 6675)
//!   Day 22 — socket API: blocking TcpListener/TcpStream over a PacketIo trait (loopback-tested),
//!            active half-close (recv in FIN_WAIT_2), keep-alive HTTP/1.1 (docs/day22-book.md)
//!   Day 23 — robustness: RFC 5961 §5 blind-data ACK acceptability + randomized challenge-ACK
//!            throttle (CVE-2016-5696) + CLOSE_WAIT/FIN_WAIT_2 reaper timeouts (docs/day23-book.md)
//!   Day 24 — RACK-TLP: time-based loss detection + Tail Loss Probe — fast tail-loss recovery and
//!            reordering tolerance (docs/day24-book.md, RFC 8985)
//!   Day 25 — CUBIC: cubic-curve congestion avoidance (β = 0.7, RTT-independent) that fills fat
//!            pipes far faster than Reno's slope (docs/day25-book.md, RFC 8312/9438)
//!   Day 26 — keepalive (SO_KEEPALIVE): probe an idle ESTABLISHED connection to detect a vanished
//!            peer (docs/day26-book.md, RFC 9293 §3.8.4)
//! The full TCP lifecycle works end to end — a stock ping, nc, and curl all interoperate — with
//! reliability (data AND control segments), an adaptive RTO, flow + congestion control, reassembly,
//! and clean teardown, all unit-tested. Remaining work is breadth/robustness + live conformance
//! testing; see docs/day12-book.md §12.
//!
//! The flow is always: `iface.recv()` a buffer → interpret → optionally build a reply
//! buffer → `iface.send()`. This file is the wiring; protocol logic lives in the modules.
//!
//! Build/run/test: see README.md.  `cargo test` proves it offline.

mod congestion; // congestion control: slow start + AIMD + fast recovery (used by tcp)
mod http; // Day 22: HTTP/1.x request parsing + keep-alive responder (used by the server below)
mod icmp; // ICMP: parse + echo reply
mod ip; // IPv4: parse + header checksum + (used by tcp) checksum writer
mod reassembly; // out-of-order receive buffer (used by tcp)
mod rtt; // RTT estimation + adaptive RTO (RFC 6298)
mod seq; // 32-bit wrapping sequence-number arithmetic (used by tcp)
mod socket; // Day 22: blocking TcpListener/TcpStream façade over Connection (embeddable; day22-book)
mod tcp; // TCP: parse + connection state machine (handshake)
mod udp; // UDP: parse + pseudo-header checksum (stateless)
mod utils; // Internet checksum (shared)

// `ethernet` and `arp` exist as files but stay unwired (TAP-only path).

use std::collections::HashMap;

use etherparse::Ipv4HeaderSlice;
use tun_tap::{Iface, Mode};

fn protocol_name(protocol: u8) -> &'static str {
    match protocol {
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        _ => "unknown",
    }
}

// Day 22: HTTP/1.x request handling (full header buffering + keep-alive) lives in `src/http.rs`;
// the per-connection request buffer and serving loop are wired into the TCP handler in `main`.

fn main() -> std::io::Result<()> {
    // without_packet_info: no 4-byte TUN PI header, so buf[0] is the IP version nibble. §3.
    let iface = Iface::without_packet_info("tun0", Mode::Tun)?;

    println!("✓ TUN interface up: {}", iface.name());
    println!("→ In another terminal:");
    println!("    sudo ip addr add 192.168.0.1/24 dev {}", iface.name());
    println!("    sudo ip link set {} up", iface.name());
    println!("    ping 192.168.0.2            # ICMP echo reply (0% loss)");
    println!("    nc 192.168.0.2 8080         # TCP echo: type a line, get it back");
    println!("    curl http://192.168.0.2:8080/   # HTTP/1.1 200 OK (keep-alive; --http1.0 to close)");
    println!("──────────────────────────────────────────────");

    // The connection table: one TCB per active 4-tuple. This is TCP's "memory".
    let mut connections: HashMap<tcp::Quad, tcp::Connection> = HashMap::new();
    // Day 22: per-connection HTTP request buffer — accumulate bytes until a full request head
    // (`\r\n\r\n`) arrives, so one connection can carry many keep-alive requests. Absent for a
    // non-HTTP (raw `nc` echo) connection; present once we've recognised an HTTP client.
    let mut http_bufs: HashMap<tcp::Quad, Vec<u8>> = HashMap::new();

    // Non-blocking I/O so one thread can both read packets AND fire retransmission timers.
    iface.set_non_blocking()?;
    let clock = std::time::Instant::now();

    let mut buf = [0u8; 1504];
    let mut count: u64 = 0;

    loop {
        let now_ms = clock.elapsed().as_millis() as u64;

        // Timers: resend any segment past its RTO, and reap connections whose TIME_WAIT expired.
        let mut closed = Vec::new();
        for (quad, conn) in connections.iter_mut() {
            for pkt in conn.on_tick(now_ms) {
                iface.send(&pkt)?;
                println!("         ↻ retransmit ({} bytes)", pkt.len());
            }
            if conn.state() == tcp::State::Closed {
                closed.push(*quad);
            }
        }
        for quad in closed {
            connections.remove(&quad);
            http_bufs.remove(&quad);
            println!("         · TIME_WAIT expired, connection removed");
        }

        // Read one packet if available; if none is ready, nap briefly so timers keep firing.
        let n = match iface.recv(&mut buf) {
            Ok(n) => n,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(5));
                continue;
            }
            Err(e) => return Err(e),
        };
        count += 1;
        let packet = &buf[..n];

        let hdr = match ip::parse(packet) {
            Ok(h) => h,
            Err(e) => {
                println!("[#{count:04}] skip ({n} bytes): {e:?}");
                continue;
            }
        };

        // Defensive: drop a packet whose IPv4 header checksum doesn't verify (corrupted in
        // transit). Real kernel-sent packets are valid; this rejects garbage before we act on it.
        if !ip::verify_checksum(&packet[..hdr.header_len]) {
            println!("[#{count:04}] bad IP header checksum — dropping");
            continue;
        }

        println!(
            "[#{count:04}] IPv4  {} → {}  proto={} ({})  total={}B ttl={}",
            hdr.src,
            hdr.dst,
            hdr.protocol,
            protocol_name(hdr.protocol),
            hdr.total_len,
            hdr.ttl,
        );

        let l4 = &packet[hdr.header_len..]; // payload starts after the IP header (§8)
        match hdr.protocol {
            // ── ICMP ──
            1 => {
                if let Some(i) = icmp::parse(l4) {
                    println!(
                        "         └── ICMP type={} code={} ({})  id={} seq={}",
                        i.typ,
                        i.code,
                        icmp::name(i.typ, i.code),
                        i.id,
                        i.seq
                    );
                    if i.typ == 8 {
                        if let Some(reply) = icmp::build_echo_reply(packet, hdr.header_len) {
                            iface.send(&reply)?;
                            println!("         → sent Echo Reply ({} bytes)", reply.len());
                        }
                    }
                }
            }

            // ── TCP ──
            6 => {
                if let Some(th) = tcp::parse(l4) {
                    let payload = &l4[th.data_offset.min(l4.len())..];
                    // Day 15: the TCP options sit between the 20-byte fixed header and the data.
                    let opts = tcp::parse_options(&l4[20..th.data_offset.min(l4.len())]);
                    println!(
                        "         └── TCP {} → {}  seq={} ack={} flags=[{}] win={}",
                        th.src_port,
                        th.dst_port,
                        th.seq,
                        th.ack,
                        tcp::flags_str(th.flags),
                        th.window
                    );

                    let quad = tcp::Quad {
                        remote: (hdr.src, th.src_port),
                        local: (hdr.dst, th.dst_port),
                    };

                    match connections.get_mut(&quad) {
                        // Existing connection: let it advance its state machine.
                        Some(conn) => {
                            // Advance the state machine; send any ACK/control response.
                            if let Some(out) = conn.on_segment(&th, payload, &opts, now_ms) {
                                iface.send(&out)?;
                            }
                            // Application layer (Day 22): read in-order bytes and respond. An HTTP
                            // client's bytes accumulate in a per-connection buffer until a full
                            // request head (`\r\n\r\n`) arrives; we then serve every complete request
                            // (pipelining + keep-alive) and close only when a response says so.
                            // Anything that doesn't look like HTTP is echoed (the raw `nc` path).
                            // `poll_transmit` puts responses on the wire as min(cwnd, rwnd) allows —
                            // the same API a TcpStream exposes.
                            let received = conn.take_received();
                            let mut closing_http = false;
                            if !received.is_empty() {
                                let is_http = http_bufs.contains_key(&quad)
                                    || http::looks_like_request(&received);
                                if is_http {
                                    let hbuf = http_bufs.entry(quad).or_default();
                                    hbuf.extend_from_slice(&received);
                                    // Serve each complete request currently buffered.
                                    while let Some(head_len) = http::request_head_len(hbuf) {
                                        let head: Vec<u8> = hbuf.drain(..head_len).collect();
                                        match http::parse_request(&head) {
                                            Some(req) => {
                                                conn.write(&http::response(&req));
                                                println!(
                                                    "         → HTTP {} {} ({}, {})",
                                                    req.method,
                                                    req.path,
                                                    if req.version == http::Version::Http11 {
                                                        "1.1"
                                                    } else {
                                                        "1.0"
                                                    },
                                                    if req.keep_alive { "keep-alive" } else { "close" }
                                                );
                                                if !req.keep_alive {
                                                    closing_http = true;
                                                    break;
                                                }
                                            }
                                            None => {
                                                closing_http = true; // malformed → close
                                                break;
                                            }
                                        }
                                    }
                                } else {
                                    conn.write(&received); // echo application (raw nc)
                                }
                            }
                            for seg in conn.poll_transmit(now_ms) {
                                iface.send(&seg)?;
                            }
                            if closing_http {
                                // The response asked to close (HTTP/1.0, or `Connection: close`):
                                // actively close once it's on the wire (the Day 7 FIN_WAIT path).
                                if let Some(fin) = conn.close(now_ms) {
                                    iface.send(&fin)?;
                                    println!("         → response sent, closing (FIN)");
                                }
                                http_bufs.remove(&quad);
                            }
                            // Day 19 — half-close: the peer closed its half (CLOSE_WAIT). An echo
                            // server has nothing more to send once its buffer is drained, so it
                            // closes its own half too — our FIN, advancing to LAST_ACK.
                            if conn.state() == tcp::State::CloseWait && conn.send_buffer_empty() {
                                if let Some(fin) = conn.close(now_ms) {
                                    iface.send(&fin)?;
                                    println!("         → peer closed; sent our FIN (LAST_ACK)");
                                }
                            }
                            let state = conn.state();
                            println!("         · state now {state:?}");
                            // Once fully closed, forget the connection.
                            if state == tcp::State::Closed {
                                connections.remove(&quad);
                                http_bufs.remove(&quad);
                                println!("         · connection closed, removed from table");
                            }
                        }
                        // New 4-tuple: a SYN opens a connection (passive open).
                        None => match tcp::Connection::accept(hdr.src, hdr.dst, &th, &opts, now_ms) {
                            Some((conn, synack)) => {
                                iface.send(&synack)?;
                                connections.insert(quad, conn);
                                println!("         → sent SYN-ACK (state SynRcvd)");
                            }
                            None => {
                                // Not a SYN to a closed/unknown connection → RST (RFC 9293).
                                let rst = tcp::build_rst(hdr.src, hdr.dst, &th, payload.len());
                                iface.send(&rst)?;
                                println!("         → sent RST (no connection)");
                            }
                        },
                    }
                }
            }

            // ── UDP ── (stateless: decode, then echo the datagram back)
            17 => {
                if let Some(u) = udp::parse(l4) {
                    println!(
                        "         └── UDP {} → {}  len={}",
                        u.src_port, u.dst_port, u.length
                    );
                    if let Some(reply) = udp::build_echo_reply(packet, hdr.header_len) {
                        iface.send(&reply)?;
                        println!("         → sent UDP echo ({} bytes)", reply.len());
                    }
                }
            }

            _ => {}
        }

        // Differential safety net for the IP parse (silence = agreement).
        if let Ok(ep) = Ipv4HeaderSlice::from_slice(packet) {
            if ep.source() != hdr.src.octets()
                || ep.destination() != hdr.dst.octets()
                || ep.protocol().0 != hdr.protocol
            {
                println!("         ⚠ MISMATCH vs etherparse");
            }
        }
    }
}
