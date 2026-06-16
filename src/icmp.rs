//! ICMP layer (RFC 792) — the protocol behind `ping`.
//!
//! Doc 1 added parsing; **Doc 2 adds the Echo Reply** so `ping` finally succeeds. Theory:
//! `docs/doc1-book.md` §10 (parse) and `docs/doc2-book.md` (reply + checksums).

use crate::{ip, utils};

/// The fixed 8-byte head of an ICMP echo message. Variable data follows it.
#[derive(Debug, PartialEq, Eq)]
pub struct IcmpHeader {
    pub typ: u8,
    pub code: u8,
    pub checksum: u16,
    pub id: u16,
    pub seq: u16,
}

/// `Option` because the only failure mode is "too short" (§9).
pub fn parse(payload: &[u8]) -> Option<IcmpHeader> {
    if payload.len() < 8 {
        return None;
    }
    Some(IcmpHeader {
        typ: payload[0],
        code: payload[1],
        checksum: u16::from_be_bytes([payload[2], payload[3]]),
        id: u16::from_be_bytes([payload[4], payload[5]]),
        seq: u16::from_be_bytes([payload[6], payload[7]]),
    })
}

pub fn name(typ: u8, code: u8) -> &'static str {
    match (typ, code) {
        (8, 0) => "Echo Request (ping)",
        (0, 0) => "Echo Reply (pong)",
        (3, 0) => "Net Unreachable",
        (3, 1) => "Host Unreachable",
        (3, 3) => "Port Unreachable",
        (11, 0) => "Time Exceeded (TTL=0)",
        _ => "other",
    }
}

/// Build an ICMP **Echo Reply** from an Echo **Request** (the full IP packet bytes).
///
/// The trick: an echo reply is the request with four edits — so we copy the request and
/// (1) swap IP source/dest, (2) reset TTL, (3) flip ICMP type 8→0, (4) recompute BOTH
/// checksums. The data payload is echoed automatically because we copied it verbatim.
///
/// `header_len` is the IP header length (from `ip::parse`). Returns `None` if the packet
/// is too short or is not an echo request.
pub fn build_echo_reply(request: &[u8], header_len: usize) -> Option<Vec<u8>> {
    // Need a full IP header + the 8-byte ICMP header.
    if request.len() < header_len + 8 {
        return None;
    }
    // Only answer Echo Requests (type 8). The type byte is the first ICMP byte.
    if request[header_len] != 8 {
        return None;
    }

    let mut reply = request.to_vec();

    // ── IP layer edits ──
    // Swap source (bytes 12..16) and destination (16..20): the reply goes back to the sender.
    let (mut src, mut dst) = ([0u8; 4], [0u8; 4]);
    src.copy_from_slice(&reply[12..16]);
    dst.copy_from_slice(&reply[16..20]);
    reply[12..16].copy_from_slice(&dst);
    reply[16..20].copy_from_slice(&src);
    reply[8] = 64; // give the reply a fresh TTL
    ip::write_header_checksum(&mut reply[..header_len]); // header changed → recompute

    // ── ICMP layer edits ──
    reply[header_len] = 0; // type 0 = Echo Reply
    // Zero the ICMP checksum field, then recompute over the whole ICMP message (header+data).
    reply[header_len + 2] = 0;
    reply[header_len + 3] = 0;
    let c = utils::checksum(&reply[header_len..]);
    let [hi, lo] = c.to_be_bytes();
    reply[header_len + 2] = hi;
    reply[header_len + 3] = lo;

    Some(reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real IPv4 + ICMP echo request, padded to 84 bytes like a Linux ping.
    fn ping_packet() -> Vec<u8> {
        let mut p = vec![
            0x45, 0x00, 0x00, 0x54, 0xab, 0xcd, 0x40, 0x00, 0x40, 0x01, 0xe2, 0x3f, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0x02, // IP header
            0x08, 0x00, 0x3f, 0x2a, 0x12, 0x34, 0x00, 0x01, // ICMP echo request
        ];
        p.resize(84, 0);
        p
    }

    #[test]
    fn parses_echo_request() {
        let pkt = ping_packet();
        let icmp = parse(&pkt[20..]).expect("valid ICMP");
        assert_eq!(icmp.typ, 8);
        assert_eq!(icmp.id, 0x1234);
        assert_eq!(icmp.seq, 1);
    }

    #[test]
    fn reply_is_well_formed() {
        let req = ping_packet();
        let reply = build_echo_reply(&req, 20).expect("a reply");

        // Same length (data echoed), type flipped to 0.
        assert_eq!(reply.len(), req.len());
        assert_eq!(reply[20], 0); // ICMP type 0 = echo reply

        // Source/dest swapped: reply src = request dst (192.168.0.2) and vice versa.
        assert_eq!(&reply[12..16], &[192, 168, 0, 2]);
        assert_eq!(&reply[16..20], &[192, 168, 0, 1]);

        // Both checksums must now be VALID — i.e. each region sums to 0.
        assert_eq!(utils::checksum(&reply[..20]), 0, "IP header checksum invalid");
        assert_eq!(utils::checksum(&reply[20..]), 0, "ICMP checksum invalid");

        // The echoed data payload is unchanged.
        assert_eq!(&reply[28..], &req[28..]);
    }

    #[test]
    fn ignores_non_echo_request() {
        let mut req = ping_packet();
        req[20] = 0; // make it an echo *reply*, not a request
        assert!(build_echo_reply(&req, 20).is_none());
    }
}
