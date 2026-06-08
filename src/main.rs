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
//! All of TCP's control loops now exist (reliability, flow, congestion) and are unit-tested.
//! The remaining piece is the interface: a socket-style API (TcpListener/TcpStream) + a real
//! send buffer so an app — not a hard-coded echo — drives the stack. See docs/day10-book.md §13.
//!
//! The flow is always: `iface.recv()` a buffer → interpret → optionally build a reply
//! buffer → `iface.send()`. This file is the wiring; protocol logic lives in the modules.
//!
//! Build/run/test: see the `tcp-stack-run` skill.  `cargo test` proves it offline.

mod congestion; // congestion control: slow start + AIMD + fast recovery (used by tcp)
mod icmp; // ICMP: parse + echo reply
mod ip; // IPv4: parse + header checksum + (used by tcp) checksum writer
mod reassembly; // out-of-order receive buffer (used by tcp)
mod rtt; // RTT estimation + adaptive RTO (RFC 6298)
mod seq; // 32-bit wrapping sequence-number arithmetic (used by tcp)
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

/// Minimal HTTP/1.0 responder: if the received bytes start with a request line, return a canned
/// `200 OK`; otherwise `None` (the caller then echoes). A real server buffers until the blank
/// line `\r\n\r\n`, but a simple `curl` GET arrives in a single segment over our local link, so
/// responding on the request line is enough to satisfy the Manual's Week-10 milestone.
fn http_response(received: &[u8]) -> Option<Vec<u8>> {
    let is_http = received.starts_with(b"GET ")
        || received.starts_with(b"HEAD ")
        || received.starts_with(b"POST ");
    if !is_http {
        return None;
    }
    let body = b"Hello from a TCP/IP stack built from scratch in Rust!\n";
    let mut resp = format!(
        "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    resp.extend_from_slice(body);
    Some(resp)
}

fn main() -> std::io::Result<()> {
    // without_packet_info: no 4-byte TUN PI header, so buf[0] is the IP version nibble. §3.
    let iface = Iface::without_packet_info("tun0", Mode::Tun)?;

    println!("✓ TUN interface up: {}", iface.name());
    println!("→ In another terminal:");
    println!("    sudo ip addr add 192.168.0.1/24 dev {}", iface.name());
    println!("    sudo ip link set {} up", iface.name());
    println!("    ping 192.168.0.2            # ICMP echo reply (0% loss)");
    println!("    nc 192.168.0.2 8080         # TCP echo: type a line, get it back");
    println!("    curl http://192.168.0.2:8080/   # HTTP/1.0 200 OK, then clean close");
    println!("──────────────────────────────────────────────");

    // The connection table: one TCB per active 4-tuple. This is TCP's "memory".
    let mut connections: HashMap<tcp::Quad, tcp::Connection> = HashMap::new();

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
                            if let Some(out) = conn.on_packet_at(&th, payload, now_ms) {
                                iface.send(&out)?;
                            }
                            // Application layer: read whatever was delivered in order and respond.
                            // An HTTP request gets a canned 200 OK (then we close); anything else is
                            // echoed. `poll_transmit` puts the response on the wire as the send
                            // window (min(cwnd, rwnd)) allows — the same API a TcpStream exposes.
                            let received = conn.take_received();
                            let mut serving_http = false;
                            if !received.is_empty() {
                                if let Some(resp) = http_response(&received) {
                                    conn.write(&resp);
                                    serving_http = true;
                                } else {
                                    conn.write(&received); // echo application
                                }
                            }
                            for seg in conn.poll_transmit(now_ms) {
                                iface.send(&seg)?;
                            }
                            if serving_http {
                                // HTTP/1.0 "Connection: close": actively close once the response is
                                // on the wire (the FIN_WAIT teardown path from Day 7).
                                if let Some(fin) = conn.close() {
                                    iface.send(&fin)?;
                                    println!("         → served HTTP/1.0 200 OK, closing (FIN)");
                                }
                            }
                            let state = conn.state();
                            println!("         · state now {state:?}");
                            // Once fully closed, forget the connection.
                            if state == tcp::State::Closed {
                                connections.remove(&quad);
                                println!("         · connection closed, removed from table");
                            }
                        }
                        // New 4-tuple: a SYN opens a connection (passive open).
                        None => match tcp::Connection::accept(hdr.src, hdr.dst, &th) {
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
