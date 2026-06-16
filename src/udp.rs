//! UDP layer (RFC 768) — parse + pseudo-header checksum.
//!
//! UDP is the simplest transport: an 8-byte header and no connection state, so this module
//! has no table and no state machine — just parse and a checksum that (unlike ICMP) covers a
//! 12-byte pseudo-header of IP fields. It's the stateless warm-up for the TCP checksum. Theory:
//! `docs/doc2-book.md` §BI–§BK.

use std::net::Ipv4Addr;

use crate::{ip, utils};

/// A parsed UDP header (RFC 768). `length` counts the header + data.
#[derive(Debug, PartialEq, Eq)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
}

/// `Option` because the only failure is "too short" (an 8-byte header is the minimum).
pub fn parse(seg: &[u8]) -> Option<UdpHeader> {
    if seg.len() < 8 {
        return None;
    }
    Some(UdpHeader {
        src_port: u16::from_be_bytes([seg[0], seg[1]]),
        dst_port: u16::from_be_bytes([seg[2], seg[3]]),
        length: u16::from_be_bytes([seg[4], seg[5]]),
    })
}

/// UDP/IPv4 checksum: the Internet checksum over a 12-byte pseudo-header (src/dst IP, zero,
/// protocol 17, UDP length) followed by the UDP segment. The segment's own checksum field
/// (bytes 6–7) must be zero when this is called. The pseudo-header binds the checksum to the
/// addresses so a misdelivered datagram is detected; it is never transmitted.
pub fn checksum(src: Ipv4Addr, dst: Ipv4Addr, segment: &[u8]) -> u16 {
    let mut buf = Vec::with_capacity(12 + segment.len());
    buf.extend_from_slice(&src.octets()); // pseudo-header: source address
    buf.extend_from_slice(&dst.octets()); //               destination address
    buf.push(0); //                                         zero byte
    buf.push(17); //                                        protocol = UDP
    buf.extend_from_slice(&(segment.len() as u16).to_be_bytes()); // UDP length
    buf.extend_from_slice(segment); //                      the UDP header + data
    utils::checksum(&buf)
}

/// Build a UDP echo reply from a request (full IP packet). Like the ICMP reply: copy, swap IP
/// src/dst, reset TTL, swap UDP ports, then recompute BOTH checksums (IP header, then the UDP
/// pseudo-header checksum). The data echoes for free. `header_len` is the IP header length.
/// Returns `None` if the packet is too short for an IP header + an 8-byte UDP header.
pub fn build_echo_reply(request: &[u8], header_len: usize) -> Option<Vec<u8>> {
    if request.len() < header_len + 8 {
        return None;
    }
    let mut reply = request.to_vec();

    // ── IP layer ── swap source/destination, reset TTL, recompute the header checksum.
    let (mut s, mut d) = ([0u8; 4], [0u8; 4]);
    s.copy_from_slice(&reply[12..16]);
    d.copy_from_slice(&reply[16..20]);
    reply[12..16].copy_from_slice(&d);
    reply[16..20].copy_from_slice(&s);
    reply[8] = 64;
    ip::write_header_checksum(&mut reply[..header_len]);

    // ── UDP layer ── swap the ports, then recompute the pseudo-header checksum.
    let u = header_len;
    let (mut sp, mut dp) = ([0u8; 2], [0u8; 2]);
    sp.copy_from_slice(&reply[u..u + 2]);
    dp.copy_from_slice(&reply[u + 2..u + 4]);
    reply[u..u + 2].copy_from_slice(&dp);
    reply[u + 2..u + 4].copy_from_slice(&sp);

    // The checksum uses the NEW (swapped) addresses — the reply's src = us, dst = peer.
    let src = Ipv4Addr::new(reply[12], reply[13], reply[14], reply[15]);
    let dst = Ipv4Addr::new(reply[16], reply[17], reply[18], reply[19]);
    reply[u + 6] = 0; // zero the checksum field before computing
    reply[u + 7] = 0;
    let c = checksum(src, dst, &reply[u..]);
    reply[u + 6..u + 8].copy_from_slice(&c.to_be_bytes());

    Some(reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: Ipv4Addr = Ipv4Addr::new(192, 168, 0, 2);
    const PEER: Ipv4Addr = Ipv4Addr::new(192, 168, 0, 1);

    /// An 8-byte UDP header: sport 7, dport 0x1234, length 8, checksum field zeroed.
    fn udp_seg() -> [u8; 8] {
        [0x00, 0x07, 0x12, 0x34, 0x00, 0x08, 0x00, 0x00]
    }

    #[test]
    fn parses_header() {
        let h = parse(&udp_seg()).unwrap();
        assert_eq!(h.src_port, 7);
        assert_eq!(h.dst_port, 0x1234);
        assert_eq!(h.length, 8);
    }

    #[test]
    fn rejects_too_short() {
        assert!(parse(&[0, 0, 0]).is_none());
    }

    /// Compute the checksum, store it, then re-checksum (incl. the field) → must be 0.
    /// This exercises the pseudo-header path and the verify-to-zero property together.
    #[test]
    fn checksum_verifies_to_zero() {
        let mut seg = udp_seg();
        let c = checksum(ME, PEER, &seg);
        seg[6..8].copy_from_slice(&c.to_be_bytes());
        assert_eq!(checksum(ME, PEER, &seg), 0);
    }

    /// A full IPv4 + UDP packet (192.168.0.1:0x1234 → 192.168.0.2:7) carrying "hi".
    fn udp_packet() -> Vec<u8> {
        vec![
            // IPv4 header (20 bytes): proto 17, total length 30 (20 + 8 + 2)
            0x45, 0x00, 0x00, 0x1e, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0x02,
            // UDP header (8 bytes): sport 0x1234, dport 7, len 10, checksum 0
            0x12, 0x34, 0x00, 0x07, 0x00, 0x0a, 0x00, 0x00, // + data:
            0x68, 0x69, // "hi"
        ]
    }

    #[test]
    fn echo_reply_is_well_formed() {
        let req = udp_packet();
        let reply = build_echo_reply(&req, 20).expect("a reply");

        // IP addresses swapped, valid header checksum.
        assert_eq!(&reply[12..16], &[192, 168, 0, 2]); // src = us
        assert_eq!(&reply[16..20], &[192, 168, 0, 1]); // dst = peer
        assert_eq!(utils::checksum(&reply[..20]), 0, "IP checksum invalid");

        // UDP ports swapped: reply sport = request dport (7), dport = request sport (0x1234).
        assert_eq!(&reply[20..22], &[0x00, 0x07]);
        assert_eq!(&reply[22..24], &[0x12, 0x34]);

        // UDP checksum (with the new addresses' pseudo-header) verifies to 0.
        assert_eq!(checksum(ME, PEER, &reply[20..]), 0, "UDP checksum invalid");

        // The data payload is echoed unchanged.
        assert_eq!(&reply[28..], &[0x68, 0x69]);
    }

    #[test]
    fn echo_rejects_too_short() {
        // IP header but no full UDP header.
        assert!(build_echo_reply(&[0u8; 24], 20).is_none());
    }
}
