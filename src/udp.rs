//! UDP layer (RFC 768) — parse + pseudo-header checksum.
//!
//! UDP is the simplest transport: an 8-byte header and no connection state, so this module
//! has no table and no state machine — just parse and a checksum that (unlike ICMP) covers a
//! 12-byte pseudo-header of IP fields. It's the stateless warm-up for the TCP checksum. Theory:
//! `docs/day2-book.md` §BI–§BK.

use std::net::Ipv4Addr;

use crate::utils;

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
}
