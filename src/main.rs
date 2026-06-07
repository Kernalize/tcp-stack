//! tcp-stack — a userspace TCP/IP stack built from scratch over a Linux TUN device.
//!
//! Progress:
//!   Day 1 — receive packets, DECODE IPv4 + ICMP + peek TCP            (docs/day1-book.md)
//!   Day 2 — Internet checksum + REPLY to pings (ping succeeds)        (docs/day2-book.md)
//!   Day 3 — TCP three-way handshake (SYN→SYN-ACK→ESTABLISHED)         (docs/day3-book.md)
//!   Day 4 — TCP data transfer: accept + ACK + echo data back          (docs/day4-book.md)
//!   Day 5 — TCP teardown: FIN handling → LAST_ACK → CLOSED            (docs/day5-book.md)
//! Lifecycle (open→transfer→close) works & is unit-tested. Remaining hardening
//! (retransmission/RTO, congestion control, flow control, RST) needs the move from
//! blocking I/O to an event loop — see docs/day5-book.md §10.
//!
//! The flow is always: `iface.recv()` a buffer → interpret → optionally build a reply
//! buffer → `iface.send()`. This file is the wiring; protocol logic lives in the modules.
//!
//! Build/run/test: see the `tcp-stack-run` skill.  `cargo test` proves it offline.

mod icmp; // ICMP: parse + echo reply
mod ip; // IPv4: parse + header checksum + (used by tcp) checksum writer
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

fn main() -> std::io::Result<()> {
    // without_packet_info: no 4-byte TUN PI header, so buf[0] is the IP version nibble. §3.
    let iface = Iface::without_packet_info("tun0", Mode::Tun)?;

    println!("✓ TUN interface up: {}", iface.name());
    println!("→ In another terminal:");
    println!("    sudo ip addr add 192.168.0.1/24 dev {}", iface.name());
    println!("    sudo ip link set {} up", iface.name());
    println!("    ping 192.168.0.2        # ICMP echo reply (0% loss)");
    println!("    nc 192.168.0.2 8080     # TCP handshake → ESTABLISHED");
    println!("──────────────────────────────────────────────");

    // The connection table: one TCB per active 4-tuple. This is TCP's "memory".
    let mut connections: HashMap<tcp::Quad, tcp::Connection> = HashMap::new();

    let mut buf = [0u8; 1504];
    let mut count: u64 = 0;

    loop {
        let n = iface.recv(&mut buf)?; // blocks until a packet arrives
        count += 1;
        let packet = &buf[..n];

        let hdr = match ip::parse(packet) {
            Ok(h) => h,
            Err(e) => {
                println!("[#{count:04}] skip ({n} bytes): {e:?}");
                continue;
            }
        };

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
                            if let Some(out) = conn.on_packet(&th, payload) {
                                iface.send(&out)?;
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
