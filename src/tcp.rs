//! TCP layer (RFC 9293) — the heart of the project.
//!
//! Step 3 implements the **passive-open three-way handshake**: a client's SYN creates a
//! connection in SYN_RCVD and gets a SYN-ACK; the client's final ACK moves it to
//! ESTABLISHED. Unlike ICMP, TCP has *memory* — a Transmission Control Block (TCB) per
//! connection — so we keep a table of connections keyed by the 4-tuple. Theory:
//! `docs/day3-book.md`.
//!
//! This step also adds the first real *header builder* (`build_packet`) and the TCP
//! checksum, which uniquely covers a "pseudo-header" of IP fields as well as the segment.

use std::net::Ipv4Addr;

use crate::{ip, seq, utils};

// TCP control-flag bit masks (RFC 9293 §3.1).
pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;
pub const URG: u8 = 0x20;

/// A connection is identified by both endpoints. `remote` is the packet's source (the
/// client); `local` is its destination (us). Used as the connection-table key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Quad {
    pub remote: (Ipv4Addr, u16),
    pub local: (Ipv4Addr, u16),
}

/// The subset of the TCP state machine we implement so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    SynRcvd,
    Established,
    /// We've sent our FIN and await the peer's final ACK (passive close).
    LastAck,
    /// Fully closed — `main` removes the connection from the table.
    Closed,
}

/// A parsed TCP header (the 20-byte fixed part; options are skipped via `data_offset`).
#[derive(Debug, PartialEq, Eq)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    /// Header length in BYTES (data offset × 4); the segment's data begins here.
    pub data_offset: usize,
    pub flags: u8,
    pub window: u16,
}

pub fn parse(seg: &[u8]) -> Option<TcpHeader> {
    if seg.len() < 20 {
        return None;
    }
    Some(TcpHeader {
        src_port: u16::from_be_bytes([seg[0], seg[1]]),
        dst_port: u16::from_be_bytes([seg[2], seg[3]]),
        seq: u32::from_be_bytes([seg[4], seg[5], seg[6], seg[7]]),
        ack: u32::from_be_bytes([seg[8], seg[9], seg[10], seg[11]]),
        // Byte 12 high nibble = data offset in 32-bit words.
        data_offset: ((seg[12] >> 4) as usize) * 4,
        flags: seg[13],
        window: u16::from_be_bytes([seg[14], seg[15]]),
    })
}

/// Human-readable flag list, e.g. "SYN ACK".
pub fn flags_str(flags: u8) -> String {
    let mut s = String::new();
    for (bit, name) in [(SYN, "SYN"), (ACK, "ACK"), (FIN, "FIN"), (RST, "RST"), (PSH, "PSH"), (URG, "URG")] {
        if flags & bit != 0 {
            s.push_str(name);
            s.push(' ');
        }
    }
    s.trim_end().to_string()
}

/// Send Sequence Space (RFC 9293 §3.3.1): everything about the bytes WE send.
#[derive(Debug)]
struct SendSequence {
    una: u32, // oldest unacknowledged sequence number
    nxt: u32, // next sequence number we'll send
    wnd: u16, // our send window (advertised by the peer)
    iss: u32, // our initial send sequence number
}

/// Receive Sequence Space: everything about the bytes WE receive.
// `wnd` and `irs` are part of the TCB now but first get read in Step 4 (data transfer):
// `wnd` bounds how much we accept, `irs` lets us report sequence numbers relative to the
// peer's ISN. Allowed-dead until then so the build stays warning-clean.
#[allow(dead_code)]
#[derive(Debug)]
struct RecvSequence {
    nxt: u32, // next sequence number we expect from the peer
    wnd: u16, // our receive window (how much we'll accept)
    irs: u32, // initial receive sequence number (the peer's ISN)
}

/// One TCP connection's state — the Transmission Control Block.
#[derive(Debug)]
pub struct Connection {
    state: State,
    send: SendSequence,
    recv: RecvSequence,
    local: (Ipv4Addr, u16),  // us
    remote: (Ipv4Addr, u16), // the peer
}

impl Connection {
    pub fn state(&self) -> State {
        self.state
    }

    /// Passive open: a SYN arrived for a connection we don't have yet. Create the TCB in
    /// SYN_RCVD and return it together with the SYN-ACK packet bytes to send.
    /// Returns `None` if the incoming segment isn't a SYN (we only open on a SYN).
    pub fn accept(ip_src: Ipv4Addr, ip_dst: Ipv4Addr, th: &TcpHeader) -> Option<(Connection, Vec<u8>)> {
        if th.flags & SYN == 0 {
            return None;
        }

        // ISS = our initial send sequence number. Real stacks randomize this (RFC 6528,
        // anti-spoofing); we use 0 so the arithmetic is easy to follow and test. See book.
        let iss = 0;
        let wnd = 1024;

        let conn = Connection {
            state: State::SynRcvd,
            // A SYN consumes one sequence number, so nxt = iss + 1.
            send: SendSequence { iss, una: iss, nxt: iss.wrapping_add(1), wnd },
            // We expect the peer's next byte to be its SYN's seq + 1.
            recv: RecvSequence { irs: th.seq, nxt: th.seq.wrapping_add(1), wnd },
            local: (ip_dst, th.dst_port),
            remote: (ip_src, th.src_port),
        };

        // SYN-ACK: our seq = ISS, ack = what we next expect from them (their seq + 1).
        let synack = conn.segment(conn.send.iss, conn.recv.nxt, SYN | ACK, &[]);
        Some((conn, synack))
    }

    /// Handle a packet on an existing connection. Returns bytes to send back, if any.
    pub fn on_packet(&mut self, th: &TcpHeader, payload: &[u8]) -> Option<Vec<u8>> {
        // Complete the handshake if we're still waiting for the client's ACK. (That ACK may
        // also piggyback data, so we fall through to data handling afterwards.)
        if self.state == State::SynRcvd {
            if th.flags & ACK != 0 && th.ack == self.send.nxt {
                self.send.una = th.ack;
                self.state = State::Established;
            } else {
                return None; // not the ACK we expect → ignore
            }
        }

        if self.state == State::Established {
            // Advance SND.UNA only if the ack is *acceptable*: SND.UNA < ACK <= SND.NXT, on the
            // wrapping 32-bit circle (RFC 9293 §3.4 via `seq::between`). A duplicate or
            // out-of-window ack is ignored rather than blindly trusted — the defensive version
            // of the earlier "store whatever they sent".
            if th.flags & ACK != 0 && seq::between(self.send.una, th.ack, self.send.nxt) {
                self.send.una = th.ack;
            }

            // Accept only IN-ORDER data (seq exactly == what we expect). Out-of-order or
            // duplicate data is dropped here; reliability/reassembly is a later step. When we
            // do accept data, we ECHO it back — and that segment's ACK field also acknowledges
            // the data, so one packet serves both purposes.
            if !payload.is_empty() && th.seq == self.recv.nxt {
                self.recv.nxt = self.recv.nxt.wrapping_add(payload.len() as u32);

                let seq = self.send.nxt; // our current send position
                let ack = self.recv.nxt; // acknowledge through the data we just took
                let out = self.segment(seq, ack, PSH | ACK, payload);

                // The data we just sent consumes that many sequence numbers.
                self.send.nxt = self.send.nxt.wrapping_add(payload.len() as u32);
                return Some(out);
            }

            // The peer wants to close: a FIN (in order) occupies one sequence number. We
            // acknowledge it AND, since an echo server has no more data to send, include our
            // own FIN in the same segment, then wait for the final ACK in LAST_ACK. (A full
            // stack would pass through CLOSE_WAIT while the local app finishes sending.)
            if th.flags & FIN != 0 && th.seq == self.recv.nxt {
                self.recv.nxt = self.recv.nxt.wrapping_add(1); // FIN consumes a seq number
                let out = self.segment(self.send.nxt, self.recv.nxt, FIN | ACK, &[]);
                self.send.nxt = self.send.nxt.wrapping_add(1); // our FIN consumes one too
                self.state = State::LastAck;
                return Some(out);
            }
        }

        if self.state == State::LastAck {
            // The connection is fully closed once the peer ACKs our FIN.
            if th.flags & ACK != 0 && th.ack == self.send.nxt {
                self.state = State::Closed;
            }
            return None;
        }

        None
    }

    #[cfg(test)]
    fn snd_nxt(&self) -> u32 {
        self.send.nxt
    }
    #[cfg(test)]
    fn rcv_nxt(&self) -> u32 {
        self.recv.nxt
    }

    /// Build a segment from THIS connection's perspective (src = us, dst = peer).
    fn segment(&self, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        build_packet(self.local, self.remote, seq, ack, flags, self.send.wnd, payload)
    }
}

/// Build a complete IPv4 + TCP packet (no options on either header). This is the first time
/// we synthesize headers from scratch rather than mutating a received packet.
fn build_packet(
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
) -> Vec<u8> {
    let (src_ip, src_port) = src;
    let (dst_ip, dst_port) = dst;

    let tcp_len = 20 + payload.len(); // TCP header (no options) + data
    let total_len = 20 + tcp_len; // IP header + TCP segment
    let mut pkt = vec![0u8; total_len];

    // ── IPv4 header (bytes 0..20) ──
    pkt[0] = 0x45; // version 4, IHL 5 (20 bytes)
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // flags = Don't Fragment
    pkt[8] = 64; // TTL
    pkt[9] = 6; // protocol = TCP
    pkt[12..16].copy_from_slice(&src_ip.octets());
    pkt[16..20].copy_from_slice(&dst_ip.octets());
    ip::write_header_checksum(&mut pkt[..20]); // sets bytes 10..12

    // ── TCP header (bytes 20..40) + payload (40..) ──
    let t = 20;
    pkt[t..t + 2].copy_from_slice(&src_port.to_be_bytes());
    pkt[t + 2..t + 4].copy_from_slice(&dst_port.to_be_bytes());
    pkt[t + 4..t + 8].copy_from_slice(&seq.to_be_bytes());
    pkt[t + 8..t + 12].copy_from_slice(&ack.to_be_bytes());
    pkt[t + 12] = 5 << 4; // data offset = 5 words (20 bytes); reserved bits 0
    pkt[t + 13] = flags;
    pkt[t + 14..t + 16].copy_from_slice(&window.to_be_bytes());
    // checksum (t+16..t+18) and urgent pointer (t+18..t+20) left zero for now
    pkt[t + 20..].copy_from_slice(payload);

    // TCP checksum covers a PSEUDO-HEADER (src/dst IP, proto, length) + the TCP segment.
    // The checksum field is currently zero, which is required while computing it.
    let csum = tcp_checksum(src_ip, dst_ip, &pkt[t..]);
    pkt[t + 16..t + 18].copy_from_slice(&csum.to_be_bytes());

    pkt
}

/// TCP/IPv4 checksum: the Internet checksum over a 12-byte pseudo-header followed by the
/// TCP segment. The pseudo-header ties the checksum to the IP addresses so a misdelivered
/// segment is detected. The segment's own checksum field must be zero when this is called.
fn tcp_checksum(src: Ipv4Addr, dst: Ipv4Addr, segment: &[u8]) -> u16 {
    let mut buf = Vec::with_capacity(12 + segment.len());
    buf.extend_from_slice(&src.octets()); // pseudo-header: source address
    buf.extend_from_slice(&dst.octets()); //               destination address
    buf.push(0); //                                        zero byte
    buf.push(6); //                                        protocol = TCP
    buf.extend_from_slice(&(segment.len() as u16).to_be_bytes()); // TCP length
    buf.extend_from_slice(segment); //                     the TCP header + data
    utils::checksum(&buf)
}

/// Build a TCP RST for a segment that arrived for a closed/unknown connection (RFC 9293
/// §3.10.7.1, the "CLOSED" rule). If the offending segment carries an ACK, reset with
/// `seq = SEG.ACK` and no ACK flag; otherwise reset with `seq = 0, ack = SEG.SEQ + SEG.LEN`
/// and the ACK flag set (SYN and FIN each occupy one sequence number). The RST is addressed
/// back to the offending source. This is correct, polite TCP behavior — it tells the peer to
/// stop retrying instead of silently dropping its segments.
pub fn build_rst(ip_src: Ipv4Addr, ip_dst: Ipv4Addr, th: &TcpHeader, payload_len: usize) -> Vec<u8> {
    let (seq, ack, flags) = if th.flags & ACK != 0 {
        (th.ack, 0, RST)
    } else {
        let seg_len = payload_len as u32
            + if th.flags & SYN != 0 { 1 } else { 0 }
            + if th.flags & FIN != 0 { 1 } else { 0 };
        (0, th.seq.wrapping_add(seg_len), RST | ACK)
    };
    // src = us (the offending packet's destination), dst = the offending source. Window 0.
    build_packet((ip_dst, th.dst_port), (ip_src, th.src_port), seq, ack, flags, 0, &[])
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: Ipv4Addr = Ipv4Addr::new(192, 168, 0, 2);
    const PEER: Ipv4Addr = Ipv4Addr::new(192, 168, 0, 1);

    /// A client SYN: sport 0x1234, dport 80, seq 100, no ack, flags SYN, window 0xffff.
    fn syn_segment() -> [u8; 20] {
        [
            0x12, 0x34, 0x00, 0x50, // ports 4660 → 80
            0x00, 0x00, 0x00, 0x64, // seq = 100
            0x00, 0x00, 0x00, 0x00, // ack = 0
            0x50, SYN, 0xff, 0xff, // data offset 5, flags SYN, window 0xffff
            0x00, 0x00, 0x00, 0x00, // checksum, urgent
        ]
    }

    #[test]
    fn parses_syn() {
        let th = parse(&syn_segment()).unwrap();
        assert_eq!(th.src_port, 0x1234);
        assert_eq!(th.dst_port, 80);
        assert_eq!(th.seq, 100);
        assert_eq!(th.data_offset, 20);
        assert_eq!(th.flags, SYN);
    }

    #[test]
    fn accept_produces_valid_synack() {
        let th = parse(&syn_segment()).unwrap();
        let (conn, synack) = Connection::accept(PEER, ME, &th).expect("a SYN-ACK");

        assert_eq!(conn.state(), State::SynRcvd);
        assert_eq!(synack.len(), 40); // 20 IP + 20 TCP, no payload

        // IP layer: addresses swapped, valid header checksum.
        let iph = ip::parse(&synack).unwrap();
        assert_eq!(iph.src, ME);
        assert_eq!(iph.dst, PEER);
        assert_eq!(iph.protocol, 6);
        assert_eq!(utils::checksum(&synack[..20]), 0, "IP checksum invalid");

        // TCP layer: SYN|ACK, our seq = ISS (0), ack = client_seq + 1 = 101.
        let th2 = parse(&synack[20..]).unwrap();
        assert_eq!(th2.flags, SYN | ACK);
        assert_eq!(th2.seq, 0); // ISS
        assert_eq!(th2.ack, 101); // 100 + 1
        assert_eq!(th2.src_port, 80);
        assert_eq!(th2.dst_port, 0x1234);

        // TCP checksum must verify to 0 (includes the pseudo-header).
        assert_eq!(tcp_checksum(ME, PEER, &synack[20..]), 0, "TCP checksum invalid");
    }

    #[test]
    fn final_ack_reaches_established() {
        let th = parse(&syn_segment()).unwrap();
        let (mut conn, _synack) = Connection::accept(PEER, ME, &th).unwrap();

        // Client's final ACK: seq 101, ack 1 (acks our ISS+1), flags ACK.
        let ack = TcpHeader {
            src_port: 0x1234,
            dst_port: 80,
            seq: 101,
            ack: 1, // our send.nxt (iss 0 + 1)
            data_offset: 20,
            flags: ACK,
            window: 0xffff,
        };
        assert!(conn.on_packet(&ack, &[]).is_none());
        assert_eq!(conn.state(), State::Established);
    }

    #[test]
    fn established_echoes_data() {
        // Establish the connection first.
        let th = parse(&syn_segment()).unwrap();
        let (mut conn, _synack) = Connection::accept(PEER, ME, &th).unwrap();
        let handshake_ack = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 1,
            data_offset: 20, flags: ACK, window: 0xffff,
        };
        conn.on_packet(&handshake_ack, &[]);
        assert_eq!(conn.state(), State::Established);

        // Client sends 2 bytes "hi" in-order at seq 101.
        let data = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 1,
            data_offset: 20, flags: PSH | ACK, window: 0xffff,
        };
        let echo = conn.on_packet(&data, b"hi").expect("an echo segment");

        // Sequence bookkeeping advanced by the 2 bytes on both sides.
        assert_eq!(conn.rcv_nxt(), 103); // 101 + 2 received
        assert_eq!(conn.snd_nxt(), 3); // 1 + 2 sent

        // The echo packet is a valid IP+TCP packet carrying "hi" back to the peer.
        let iph = ip::parse(&echo).unwrap();
        assert_eq!(iph.src, ME);
        assert_eq!(iph.dst, PEER);
        assert_eq!(utils::checksum(&echo[..20]), 0, "IP checksum invalid");

        let eth = parse(&echo[20..]).unwrap();
        assert_eq!(eth.flags, PSH | ACK);
        assert_eq!(eth.seq, 1); // our send position before the echo
        assert_eq!(eth.ack, 103); // acknowledges the 2 bytes we received
        assert_eq!(&echo[20 + eth.data_offset..], b"hi"); // echoed payload
        assert_eq!(tcp_checksum(ME, PEER, &echo[20..]), 0, "TCP checksum invalid");
    }

    #[test]
    fn passive_close_via_fin() {
        let th = parse(&syn_segment()).unwrap();
        let (mut conn, _s) = Connection::accept(PEER, ME, &th).unwrap();
        let hs_ack = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 1,
            data_offset: 20, flags: ACK, window: 0xffff,
        };
        conn.on_packet(&hs_ack, &[]);
        assert_eq!(conn.state(), State::Established);

        // Client closes: FIN at seq 101.
        let fin = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 1,
            data_offset: 20, flags: FIN | ACK, window: 0xffff,
        };
        let finack = conn.on_packet(&fin, &[]).expect("our FIN-ACK");
        assert_eq!(conn.state(), State::LastAck);

        let t = parse(&finack[20..]).unwrap();
        assert_eq!(t.flags, FIN | ACK);
        assert_eq!(t.seq, 1); // our send position
        assert_eq!(t.ack, 102); // acknowledges their FIN (101 + 1)
        assert_eq!(tcp_checksum(ME, PEER, &finack[20..]), 0, "TCP checksum invalid");

        // Client ACKs our FIN → fully closed.
        let last = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 102, ack: 2,
            data_offset: 20, flags: ACK, window: 0xffff,
        };
        assert!(conn.on_packet(&last, &[]).is_none());
        assert_eq!(conn.state(), State::Closed);
    }

    #[test]
    fn ignores_non_syn_open() {
        let mut seg = syn_segment();
        seg[13] = ACK; // an ACK to a closed connection is not a valid open
        let th = parse(&seg).unwrap();
        assert!(Connection::accept(PEER, ME, &th).is_none());
    }

    #[test]
    fn rst_for_stray_ack() {
        // A stray ACK to a closed port: reset with seq = SEG.ACK, no ACK flag.
        let ack = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 100, ack: 500,
            data_offset: 20, flags: ACK, window: 0xffff,
        };
        let rst = build_rst(PEER, ME, &ack, 0);

        let iph = ip::parse(&rst).unwrap();
        assert_eq!(iph.src, ME); // RST comes from us
        assert_eq!(iph.dst, PEER);
        assert_eq!(utils::checksum(&rst[..20]), 0, "IP checksum invalid");

        let t = parse(&rst[20..]).unwrap();
        assert_eq!(t.flags, RST);
        assert_eq!(t.seq, 500); // SEG.ACK
        assert_eq!(t.src_port, 80);
        assert_eq!(t.dst_port, 0x1234);
        assert_eq!(tcp_checksum(ME, PEER, &rst[20..]), 0, "TCP checksum invalid");
    }
}
