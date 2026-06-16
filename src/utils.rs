//! Shared helpers used across layers.
//!
//! Doc 2: the **Internet Checksum** (RFC 1071) — one function reused by the IPv4
//! header, ICMP, TCP and UDP (the "reuse physically" rule). Theory: `docs/doc2-book.md`.

/// Internet checksum (RFC 1071): the 16-bit one's-complement of the one's-complement
/// sum of the data, taken as a sequence of 16-bit big-endian words.
///
/// - To **compute**: zero the checksum field in your header, call this over the bytes,
///   store the result back into the field.
/// - To **verify**: call this over the bytes *including* the stored checksum — a valid
///   message sums to 0.
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0; // wider than 16 bits so carries can accumulate

    // Add up every 16-bit big-endian word.
    let mut chunks = data.chunks_exact(2);
    for w in chunks.by_ref() {
        sum += u16::from_be_bytes([w[0], w[1]]) as u32;
    }
    // Odd total length: the final lone byte is the HIGH byte of a word padded with 0x00.
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }

    // "End-around carry": fold everything above bit 15 back into the low 16 bits, until
    // nothing remains in the high half. This is what makes it a *one's-complement* sum.
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // Final one's complement (bitwise NOT).
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A well-known correct IPv4 header (the Wikipedia "Header checksum" worked example).
    // Its stored checksum, 0xb861, is the right value for these bytes.
    const HDR: [u8; 20] = [
        0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8,
        0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
    ];

    #[test]
    fn computes_known_checksum() {
        let mut h = HDR;
        h[10] = 0;
        h[11] = 0; // zero the checksum field, then we must reproduce 0xb861
        assert_eq!(checksum(&h), 0xb861);
    }

    #[test]
    fn valid_header_verifies_to_zero() {
        // Summing a correct header *including* its checksum field yields 0.
        assert_eq!(checksum(&HDR), 0);
    }

    #[test]
    fn odd_length_pads_last_byte() {
        // The 3-byte input must equal the 4-byte input padded with a trailing 0x00.
        assert_eq!(checksum(&[0x12, 0x34, 0x56]), checksum(&[0x12, 0x34, 0x56, 0x00]));
    }
}
