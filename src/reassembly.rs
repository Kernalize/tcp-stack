//! Out-of-order receive reassembly (RFC 9293 §3.4, the receive side of reliability).
//!
//! Data segments can arrive out of order — the network reorders them, or a retransmission fills
//! a gap left by an earlier loss. TCP must still hand the application a single **contiguous,
//! in-order** byte stream. So the receiver buffers anything that arrives ahead of `RCV.NXT` and
//! only "delivers" bytes once the run from `RCV.NXT` is unbroken.
//!
//! We key buffered fragments by their **offset from a fixed base** (the peer's first data
//! sequence number) rather than by the raw 32-bit sequence number. That keeps ordering as plain
//! integer order and sidesteps the sequence-space wrap, *assuming a connection moves fewer than
//! 2³¹ bytes* — true for any realistic transfer; a production stack tracks the wrap explicitly.
//!
//! Simplification: we assume buffered future fragments don't *overlap* each other (our sender
//! emits each byte range once, so a reorder is just distinct ranges arriving in a jumbled order).
//! We do correctly trim a fragment that overlaps already-delivered data, and drop pure
//! duplicates. Theory: `docs/doc9-book.md`.

use std::collections::BTreeMap;

/// We never buffer data more than this far past what we expect — anything beyond the window we'd
/// advertise is out-of-window and discarded (RFC 9293 §3.10.7.4). Matches our 1 KB receive window
/// with generous headroom; it just bounds pathological buffering.
const MAX_AHEAD: u32 = 1 << 16;

/// Per-connection receive reassembly buffer.
#[derive(Debug)]
pub struct Reassembler {
    /// Offset 0 — the sequence number of the peer's first data byte (IRS + 1). All offsets are
    /// `seq − base`, monotonically increasing from 0 over the connection.
    base: u32,
    /// Out-of-order fragments, keyed by offset, each disjoint from the others and from the
    /// already-delivered prefix. Emptied as gaps fill.
    frags: BTreeMap<u32, Vec<u8>>,
}

impl Reassembler {
    /// `first_data_seq` is the sequence number we expect the first *data* byte at — i.e. `RCV.NXT`
    /// the moment the connection reaches ESTABLISHED (IRS + 1, since the SYN consumed IRS).
    pub fn new(first_data_seq: u32) -> Self {
        Self { base: first_data_seq, frags: BTreeMap::new() }
    }

    /// Feed the data of a segment that arrived at absolute sequence `seq`, given the caller's
    /// current `rcv_nxt`. Returns the bytes that are now contiguous from `rcv_nxt`, in order
    /// (possibly empty). The caller advances `RCV.NXT` by exactly the returned length.
    pub fn recv(&mut self, seq: u32, data: &[u8], rcv_nxt: u32) -> Vec<u8> {
        if data.is_empty() {
            return Vec::new();
        }
        let nxt_off = rcv_nxt.wrapping_sub(self.base);
        let mut off = seq.wrapping_sub(self.base);
        let mut data = data;

        // Trim bytes we've already delivered (segment starts at or before RCV.NXT).
        if off < nxt_off {
            let skip = (nxt_off - off) as usize;
            if skip >= data.len() {
                return Vec::new(); // wholly old / a pure duplicate
            }
            data = &data[skip..];
            off = nxt_off;
        }

        // Discard data that sits absurdly far ahead — outside any window we'd ever advertise.
        if off - nxt_off > MAX_AHEAD {
            return Vec::new();
        }

        // Buffer it. (A duplicate of an already-buffered future range simply overwrites with the
        // same bytes; we assume future fragments don't partially overlap one another.)
        self.frags.insert(off, data.to_vec());

        // Deliver the now-unbroken run starting at RCV.NXT.
        let mut out = Vec::new();
        let mut cur = nxt_off;
        while let Some((&o, _)) = self.frags.range(cur..).next() {
            if o != cur {
                break; // a gap remains — stop, keep the rest buffered
            }
            let bytes = self.frags.remove(&o).unwrap();
            cur = cur.wrapping_add(bytes.len() as u32);
            out.extend_from_slice(&bytes);
        }
        out
    }

    /// How many out-of-order fragments are currently buffered (for tests / introspection).
    #[allow(dead_code)]
    pub fn buffered(&self) -> usize {
        self.frags.len()
    }

    /// The currently-buffered out-of-order ranges, as absolute `(left edge, right edge)` sequence
    /// pairs — exactly what we report in SACK blocks (RFC 2018 §3); right edges are exclusive.
    /// Adjacent fragments are coalesced into one range, and ranges come back in ascending sequence
    /// order. (RFC 2018 §4 says the first block SHOULD be the most recently received; we keep
    /// ascending order — a SHOULD, not a MUST — because our reassembler doesn't track arrival order.)
    pub fn sack_blocks(&self) -> Vec<(u32, u32)> {
        let mut blocks: Vec<(u32, u32)> = Vec::new();
        for (&off, frag) in &self.frags {
            let left = self.base.wrapping_add(off);
            let right = left.wrapping_add(frag.len() as u32);
            match blocks.last_mut() {
                // The BTreeMap yields fragments in ascending offset order, so a fragment whose left
                // edge meets the previous block's right edge extends it (the gap closed exactly).
                Some(last) if last.1 == left => last.1 = right,
                _ => blocks.push((left, right)),
            }
        }
        blocks
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u32 = 1000;

    #[test]
    fn in_order_delivers_immediately() {
        let mut r = Reassembler::new(BASE);
        assert_eq!(r.recv(1000, b"abc", 1000), b"abc");
        assert_eq!(r.recv(1003, b"de", 1003), b"de");
        assert_eq!(r.buffered(), 0);
    }

    #[test]
    fn buffers_out_of_order_then_fills_gap() {
        let mut r = Reassembler::new(BASE);
        // "de" arrives first (a gap precedes it) → buffered, nothing deliverable yet.
        assert_eq!(r.recv(1003, b"de", 1000), b"");
        assert_eq!(r.buffered(), 1);
        // The gap-filler arrives → both flush in order.
        assert_eq!(r.recv(1000, b"abc", 1000), b"abcde");
        assert_eq!(r.buffered(), 0);
    }

    #[test]
    fn drops_duplicate_already_delivered() {
        let mut r = Reassembler::new(BASE);
        assert_eq!(r.recv(1000, b"abc", 1000), b"abc");
        // RCV.NXT is now 1003; re-receiving "abc" yields nothing.
        assert_eq!(r.recv(1000, b"abc", 1003), b"");
    }

    #[test]
    fn trims_partial_overlap_with_delivered() {
        let mut r = Reassembler::new(BASE);
        assert_eq!(r.recv(1000, b"abc", 1000), b"abc"); // RCV.NXT → 1003
        // A segment 1001.."bcXY" overlaps delivered "bc"; only the new "XY" tail is delivered.
        assert_eq!(r.recv(1001, b"bcXY", 1003), b"XY");
    }

    #[test]
    fn multiple_gaps_fill_in_any_order() {
        let mut r = Reassembler::new(BASE);
        assert_eq!(r.recv(1006, b"gh", 1000), b""); // offset 6, buffered
        assert_eq!(r.recv(1003, b"def", 1000), b""); // offset 3, buffered (gap at 0 remains)
        assert_eq!(r.buffered(), 2);
        assert_eq!(r.recv(1000, b"abc", 1000), b"abcdefgh"); // fills the head → all flush
        assert_eq!(r.buffered(), 0);
    }

    #[test]
    fn discards_data_far_outside_window() {
        let mut r = Reassembler::new(BASE);
        // Offset ~100k, well past MAX_AHEAD → dropped, not buffered.
        assert_eq!(r.recv(1000 + (1 << 17), b"zz", 1000), b"");
        assert_eq!(r.buffered(), 0);
    }

    #[test]
    fn sack_blocks_empty_when_in_order() {
        let mut r = Reassembler::new(BASE);
        assert_eq!(r.recv(1000, b"abc", 1000), b"abc"); // delivered in order, nothing buffered
        assert!(r.sack_blocks().is_empty());
    }

    #[test]
    fn sack_blocks_reports_disjoint_buffered_ranges() {
        let mut r = Reassembler::new(BASE);
        assert_eq!(r.recv(1003, b"de", 1000), b""); // gap at [1000,1003): buffer [1003,1005)
        assert_eq!(r.recv(1006, b"gh", 1000), b""); // another hole: buffer [1006,1008)
        // Two disjoint ranges → two SACK blocks, ascending, right edge exclusive (RFC 2018 §3).
        assert_eq!(r.sack_blocks(), vec![(1003, 1005), (1006, 1008)]);
    }

    #[test]
    fn sack_blocks_coalesces_adjacent_fragments() {
        let mut r = Reassembler::new(BASE);
        assert_eq!(r.recv(1003, b"de", 1000), b""); //   [1003,1005)
        assert_eq!(r.recv(1005, b"fg", 1000), b""); //   [1005,1007) abuts the previous fragment
        // Adjacent fragments collapse into a single block — the SACK option stays compact.
        assert_eq!(r.sack_blocks(), vec![(1003, 1007)]);
    }
}
