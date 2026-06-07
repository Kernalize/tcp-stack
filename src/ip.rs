//! IPv4 layer (RFC 791).
//!
//! As of Day 2 the IPv4 logic lives here (moved out of `main.rs` now that ICMP also needs
//! it — the "refactor when there are 2+ callers" rule, day1-book.md §13). Theory for the
//! parse is in `docs/day1-book.md` §5–§8; for checksum writing, `docs/day2-book.md`.

use std::net::Ipv4Addr;

use crate::utils;

/// The fields of an IPv4 header we use (a subset of RFC 791).
#[derive(Debug, PartialEq, Eq)]
pub struct Ipv4Header {
    pub version: u8,
    /// Header length in BYTES (IHL × 4). The L4 payload starts here — not always at 20.
    pub header_len: usize,
    /// Total datagram length (header + payload) in bytes, from the wire.
    pub total_len: usize,
    pub ttl: u8,
    /// 1 = ICMP, 6 = TCP, 17 = UDP.
    pub protocol: u8,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
}

/// Why typed errors: packet bytes are hostile input; we must reject, never panic. §9.
#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    TooShort { have: usize, need: usize },
    NotIpv4 { version: u8 },
    HeaderLongerThanPacket { header_len: usize, have: usize },
    /// Declared total length is smaller than the header itself — malformed.
    BadTotalLength { total_len: usize, header_len: usize },
}

/// Parse an IPv4 header from the front of `packet`. Borrows; copies only the few fields
/// returned. The two length guards make all later indexing panic-free.
pub fn parse(packet: &[u8]) -> Result<Ipv4Header, ParseError> {
    if packet.len() < 20 {
        return Err(ParseError::TooShort { have: packet.len(), need: 20 });
    }

    let version = packet[0] >> 4; // high nibble of byte 0
    if version != 4 {
        return Err(ParseError::NotIpv4 { version });
    }

    let ihl = (packet[0] & 0x0f) as usize; // low nibble = header length in 32-bit words
    let header_len = ihl * 4;
    if packet.len() < header_len {
        return Err(ParseError::HeaderLongerThanPacket { header_len, have: packet.len() });
    }

    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize; // big-endian!
    // The declared datagram length can't be smaller than the header it includes. We only log
    // total_len today, but rejecting a nonsensical value is correct defensive parsing.
    if total_len < header_len {
        return Err(ParseError::BadTotalLength { total_len, header_len });
    }
    let ttl = packet[8];
    let protocol = packet[9];
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

    Ok(Ipv4Header { version, header_len, total_len, ttl, protocol, src, dst })
}

/// Recompute the IPv4 **header** checksum (bytes 10..12) over `header`, which must be
/// exactly the IP header (`ihl × 4` bytes). Zeroes the field first, as the algorithm
/// requires, then writes the result big-endian. Used when we build a packet to send.
pub fn write_header_checksum(header: &mut [u8]) {
    header[10] = 0;
    header[11] = 0;
    let c = utils::checksum(header);
    let [hi, lo] = c.to_be_bytes();
    header[10] = hi;
    header[11] = lo;
}

/// True if the IP header's stored checksum is valid (a correct header verifies to 0). Use to
/// reject corrupt incoming headers before trusting them — defensive parsing at the boundary.
pub fn verify_checksum(header: &[u8]) -> bool {
    utils::checksum(header) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::Ipv4HeaderSlice;

    /// 20-byte IPv4 header of a real ping (from the manual), here without payload.
    const PING_HDR: [u8; 20] = [
        0x45, 0x00, 0x00, 0x54, 0xab, 0xcd, 0x40, 0x00, 0x40, 0x01, 0xe2, 0x3f, 0xc0, 0xa8,
        0x00, 0x01, 0xc0, 0xa8, 0x00, 0x02,
    ];

    #[test]
    fn parses_fields() {
        let h = parse(&PING_HDR).expect("valid IPv4");
        assert_eq!(h.version, 4);
        assert_eq!(h.header_len, 20);
        assert_eq!(h.total_len, 84);
        assert_eq!(h.ttl, 64);
        assert_eq!(h.protocol, 1);
        assert_eq!(h.src, Ipv4Addr::new(192, 168, 0, 1));
        assert_eq!(h.dst, Ipv4Addr::new(192, 168, 0, 2));
    }

    #[test]
    fn rejects_too_short() {
        assert_eq!(parse(&[0x45, 0x00]), Err(ParseError::TooShort { have: 2, need: 20 }));
    }

    #[test]
    fn rejects_non_ipv4() {
        let mut p = PING_HDR;
        p[0] = 0x60;
        assert!(matches!(parse(&p), Err(ParseError::NotIpv4 { version: 6 })));
    }

    #[test]
    fn rejects_total_length_below_header() {
        let mut p = PING_HDR;
        p[2] = 0;
        p[3] = 10; // total_len = 10 < 20-byte header → malformed
        assert!(matches!(parse(&p), Err(ParseError::BadTotalLength { .. })));
    }

    #[test]
    fn agrees_with_etherparse() {
        let ours = parse(&PING_HDR).unwrap();
        let ep = Ipv4HeaderSlice::from_slice(&PING_HDR).unwrap();
        assert_eq!(ep.source(), ours.src.octets());
        assert_eq!(ep.destination(), ours.dst.octets());
        assert_eq!(ep.protocol().0, ours.protocol);
    }

    #[test]
    fn checksum_round_trips() {
        // Writing the checksum then verifying the header must sum to 0.
        let mut h = PING_HDR;
        write_header_checksum(&mut h);
        assert_eq!(utils::checksum(&h), 0);
    }

    #[test]
    fn verify_checksum_detects_corruption() {
        let mut h = PING_HDR;
        write_header_checksum(&mut h);
        assert!(verify_checksum(&h)); // a freshly-checksummed header is valid
        h[12] ^= 0xff; // corrupt the source address
        assert!(!verify_checksum(&h)); // now it must fail
    }
}
