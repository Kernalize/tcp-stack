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

use std::collections::VecDeque;
use std::net::Ipv4Addr;

use crate::{congestion::CongestionControl, ip, reassembly::Reassembler, rtt::RttEstimator, seq, utils};

// TCP control-flag bit masks (RFC 9293 §3.1).
pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;
pub const URG: u8 = 0x20;

// TCP option kinds (RFC 9293 §3.1, IANA "TCP Option Kind Numbers").
const OPT_END: u8 = 0; // End of Option List (single byte)
const OPT_NOP: u8 = 1; // No-Operation, used for alignment padding (single byte)
const OPT_MSS: u8 = 2; // Maximum Segment Size (len 4), valid only on SYN segments
const OPT_WS: u8 = 3; //  Window Scale (len 3): a 1-byte shift count (RFC 7323 §2)
const OPT_SACK_PERM: u8 = 4; // SACK-Permitted (len 2): negotiated on the SYN (RFC 2018 §2)
const OPT_SACK: u8 = 5; //    SACK blocks (len 2 + 8·n): carried on ACKs (RFC 2018 §3)
const OPT_TS: u8 = 8; //  Timestamps (len 10): TSval + TSecr (RFC 7323 §3)

/// The window-scale shift WE advertise. Our receive buffer is small (1 KB), so we don't need to
/// scale our *own* window — but we still send the option (shift 0) so scaling is negotiated and we
/// may honor the peer's much larger window. RFC 7323 §2.2 caps the shift at 14.
const OUR_RCV_WSCALE: u8 = 0;
const MAX_WSCALE: u8 = 14;

/// The most SACK blocks we emit in one ACK. The TCP option area is 40 bytes; a Timestamps option
/// eats 12, leaving 28, and a SACK option after a 2-byte NOP pad is `4 + 8·n` bytes — so
/// `4 + 8·n ≤ 28` gives `n ≤ 3`. Three separate holes is ample for our small window (RFC 2018 §3,
/// RFC 7323 appendix A). We *parse* up to four (a peer without timestamps may send four).
const MAX_SACK_BLOCKS: usize = 3;

/// The Maximum Segment Size we advertise — how big a segment WE are willing to *receive*. 1460 =
/// 1500-byte interface MTU − 20 IP − 20 TCP (RFC 9293 §3.7.1). The peer's advertised MSS bounds how
/// big a segment we may *send*; the effective send MSS is the smaller of the two. It coincides with
/// the congestion module's MSS (same link), so we derive it rather than repeat the literal.
pub const OUR_MSS: u16 = crate::congestion::MSS as u16;

/// Default send MSS when the peer's SYN carried no MSS option. RFC 9293 §3.7.1 specifies 536 for
/// IPv4, but every real peer advertises one; we default to OUR_MSS so our synthetic, option-less
/// test SYNs still segment at full size. (Documented deviation; see docs/day15-book.md.)
const DEFAULT_SEND_MSS: u16 = OUR_MSS;

/// Parsed TCP options: the peer's advertised MSS (SYN only); the Timestamps option `(TSval, TSecr)`
/// when present (RFC 7323 §3); the window-scale shift (RFC 7323 §2); and the SACK fields (RFC 2018).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TcpOptions {
    pub mss: Option<u16>,
    pub timestamps: Option<(u32, u32)>,
    /// Window-scale shift the peer advertised (SYN only), clamped to 14 (RFC 7323 §2.3).
    pub window_scale: Option<u8>,
    /// The peer's SYN carried a SACK-Permitted option (RFC 2018 §2) — it understands SACK blocks.
    pub sack_permitted: bool,
    /// SACK blocks parsed from an ACK (RFC 2018 §3): `(left edge, right edge)` pairs of out-of-order
    /// data the peer has buffered (right edge exclusive). `sack_block_count` says how many are valid.
    pub sack_blocks: [(u32, u32); 4],
    pub sack_block_count: usize,
}

/// Parse the TCP options area — the bytes between the 20-byte fixed header and the data
/// (`segment[20..data_offset]`). Walks kind/length-prefixed options, tolerating padding (NOP),
/// the end marker, and malformed/truncated lengths (stop, don't panic). Unknown kinds are skipped
/// by their length. RFC 9293 §3.1.
pub fn parse_options(opts: &[u8]) -> TcpOptions {
    let mut out = TcpOptions::default();
    let mut i = 0;
    while i < opts.len() {
        match opts[i] {
            OPT_END => break,        // no more options
            OPT_NOP => i += 1,       // single-byte padding
            kind => {
                // Length-prefixed option: [kind, len, data…]; `len` counts the kind + len bytes too.
                if i + 1 >= opts.len() {
                    break; // truncated: a kind with no length byte
                }
                let len = opts[i + 1] as usize;
                if len < 2 || i + len > opts.len() {
                    break; // malformed/overlong length → stop parsing defensively
                }
                let data = &opts[i + 2..i + len];
                if kind == OPT_MSS && data.len() == 2 {
                    out.mss = Some(u16::from_be_bytes([data[0], data[1]]));
                } else if kind == OPT_TS && data.len() == 8 {
                    // Timestamps: TSval (the sender's clock) then TSecr (the value it is echoing).
                    let tsval = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                    let tsecr = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                    out.timestamps = Some((tsval, tsecr));
                } else if kind == OPT_WS && data.len() == 1 {
                    // Window Scale: a single shift byte, capped at 14 (RFC 7323 §2.3).
                    out.window_scale = Some(data[0].min(MAX_WSCALE));
                } else if kind == OPT_SACK_PERM && data.is_empty() {
                    // SACK-Permitted (RFC 2018 §2): a bare flag (len 2, no payload) on the SYN,
                    // meaning "I understand SACK blocks." Only consulted during the handshake.
                    out.sack_permitted = true;
                } else if kind == OPT_SACK && !data.is_empty() && data.len().is_multiple_of(8) {
                    // SACK blocks (RFC 2018 §3): N×8 bytes, each a (left edge, right edge) pair of
                    // 32-bit sequence numbers (right edge exclusive). Read up to four; a length that
                    // isn't a positive multiple of 8 is malformed and ignored.
                    let n = (data.len() / 8).min(out.sack_blocks.len());
                    for k in 0..n {
                        let b = &data[k * 8..k * 8 + 8];
                        let left = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
                        let right = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
                        out.sack_blocks[k] = (left, right);
                    }
                    out.sack_block_count = n;
                }
                i += len;
            }
        }
    }
    out
}

/// The 4-byte MSS option blob `[kind=2, len=4, value_hi, value_lo]` — already 4-byte aligned, so it
/// can be handed straight to `build_packet`.
fn mss_option(mss: u16) -> [u8; 4] {
    let v = mss.to_be_bytes();
    [OPT_MSS, 4, v[0], v[1]]
}

/// The Window Scale option blob (RFC 7323 §2), padded to 4 bytes with one leading NOP —
/// `[NOP, kind=3, len=3, shift]`. The shift applies to the *advertiser's* window field.
fn ws_option(shift: u8) -> [u8; 4] {
    [OPT_NOP, OPT_WS, 3, shift]
}

/// The Timestamps option blob (RFC 7323 §3), padded to 12 bytes (a 4-byte boundary) with two
/// leading NOPs — the canonical layout `[NOP, NOP, kind=8, len=10, TSval(4), TSecr(4)]`. TSval is
/// our current clock; TSecr echoes the most recent TSval we received from the peer.
fn ts_option(tsval: u32, tsecr: u32) -> [u8; 12] {
    let val = tsval.to_be_bytes();
    let ecr = tsecr.to_be_bytes();
    [
        OPT_NOP, OPT_NOP, OPT_TS, 10,
        val[0], val[1], val[2], val[3],
        ecr[0], ecr[1], ecr[2], ecr[3],
    ]
}

/// The SACK-Permitted option (RFC 2018 §2), padded to 4 bytes with two leading NOPs —
/// `[NOP, NOP, kind=4, len=2]`. Sent only in the SYN / SYN-ACK to negotiate SACK; it carries no
/// payload — its mere presence is the message.
fn sack_perm_option() -> [u8; 4] {
    [OPT_NOP, OPT_NOP, OPT_SACK_PERM, 2]
}

/// Encode SACK blocks as a wire option (RFC 2018 §3), padded to a 4-byte boundary with two leading
/// NOPs — `[NOP, NOP, kind=5, len, (left, right)…]`, each edge a big-endian u32 (right exclusive).
/// Emits at most `MAX_SACK_BLOCKS`; returns an empty vec for no blocks (so the caller adds no option).
fn sack_option(blocks: &[(u32, u32)]) -> Vec<u8> {
    let n = blocks.len().min(MAX_SACK_BLOCKS);
    if n == 0 {
        return Vec::new();
    }
    let len = 2 + 8 * n; // the value written into the option's length byte: kind + len + n×8
    let mut out = Vec::with_capacity(2 + len); // + the two NOP pad bytes
    out.extend_from_slice(&[OPT_NOP, OPT_NOP, OPT_SACK, len as u8]);
    for &(left, right) in &blocks[..n] {
        out.extend_from_slice(&left.to_be_bytes());
        out.extend_from_slice(&right.to_be_bytes());
    }
    debug_assert!(out.len().is_multiple_of(4), "SACK option must be 4-byte aligned");
    out
}

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
    /// Active open: we sent a SYN and await the peer's SYN-ACK.
    SynSent,
    /// Passive open: we received a SYN and sent a SYN-ACK; await the peer's ACK.
    SynRcvd,
    Established,
    /// Passive close: we received the peer's FIN and sent our FIN; await the final ACK.
    LastAck,
    /// Active close: we sent our FIN; await its ACK and/or the peer's FIN.
    FinWait1,
    /// Active close: our FIN was ACKed; await the peer's FIN.
    FinWait2,
    /// Simultaneous close: both sent FIN; await the ACK of ours.
    Closing,
    /// Active close complete; linger for 2·MSL to absorb retransmitted FINs, then CLOSED.
    TimeWait,
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
    // Byte 12 high nibble = data offset in 32-bit words = TCP header length. It must be at least
    // 5 words (20 bytes) and must not claim more bytes than the segment actually holds — reject a
    // malformed/hostile header rather than trusting an out-of-range length downstream.
    let data_offset = ((seg[12] >> 4) as usize) * 4;
    if data_offset < 20 || data_offset > seg.len() {
        return None;
    }
    Some(TcpHeader {
        src_port: u16::from_be_bytes([seg[0], seg[1]]),
        dst_port: u16::from_be_bytes([seg[2], seg[3]]),
        seq: u32::from_be_bytes([seg[4], seg[5], seg[6], seg[7]]),
        ack: u32::from_be_bytes([seg[8], seg[9], seg[10], seg[11]]),
        data_offset,
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
    // The peer's advertised window, already left-shifted by its window scale (Day 17). It is `u32`,
    // not `u16`, because window scaling can stretch it past 64 KB up to ~1 GB (RFC 7323 §2).
    wnd: u32,
    iss: u32, // our initial send sequence number
}

/// Receive Sequence Space: everything about the bytes WE receive.
// `wnd` is the receive window we advertise in every segment we send (read by `segment()`).
// `irs` (the peer's ISN) is stored for future relative-sequence reporting but not yet read,
// so the struct stays `allow(dead_code)` to keep the build warning-clean.
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
    /// Sent-but-unacknowledged data segments, for retransmission (RFC 9293 §3.8.1).
    retx: RetxQueue,
    /// Time (ms) we entered TIME_WAIT, so `on_tick` can expire it after 2·MSL.
    time_wait_ms: u64,
    /// Smoothed-RTT estimator driving the adaptive RTO (RFC 6298). Fed by acks of new,
    /// never-retransmitted data (Karn's algorithm); read by `on_tick` to time retransmits.
    rtt: RttEstimator,
    /// Out-of-order receive buffer: holds data that arrives ahead of RCV.NXT until the gap fills,
    /// then delivers it contiguously (RFC 9293 §3.4).
    reasm: Reassembler,
    /// Congestion control (RFC 5681): a network-imposed send limit (`cwnd`) alongside the
    /// receiver's `SND.WND`. Grows on good ACKs, collapses on loss; gates `usable_window()`.
    cong: CongestionControl,
    /// Application bytes queued for transmission but not yet put on the wire. `poll_transmit`
    /// drains it into segments as the window allows; once sent, bytes live in `retx` until acked.
    send_buf: VecDeque<u8>,
    /// Reassembled, in-order bytes delivered to the application, awaiting `take_received()`.
    recv_buf: Vec<u8>,
    /// Nagle's algorithm (RFC 896 / RFC 9293 §3.7.4): when `true`, a small (sub-MSS) segment is
    /// held while earlier data is still unacknowledged, to coalesce tiny writes. `TCP_NODELAY`
    /// clears it for latency-sensitive traffic. Default on.
    nagle: bool,
    /// Persist timer (RFC 9293 §3.8.6.1): the absolute time (ms) the next zero-window probe is due,
    /// or 0 when disarmed. Armed when the peer's window is shut with data pending and nothing in
    /// flight; firing pokes one byte into the closed window so a lost window-update can't deadlock us.
    persist_ms: u64,
    /// Effective send MSS (Day 15): the largest payload we put in one segment, = min(OUR_MSS, the
    /// peer's advertised MSS). Learned from the peer's SYN (RFC 9293 §3.7.1); bounds `poll_transmit`.
    send_mss: u16,
    /// Timestamps negotiated (RFC 7323 §3): true only when BOTH SYNs offered the option. When set,
    /// every segment we send carries a Timestamps option, and we use it for RTT + PAWS.
    ts_enabled: bool,
    /// `TS.Recent` — the most recent TSval received from the peer; echoed as TSecr in what we send,
    /// and the PAWS reference for rejecting old wrapped duplicates (RFC 7323 §4).
    ts_recent: u32,
    /// Our timestamp clock (ms), refreshed from `now_ms` at every time-aware entry point and written
    /// as TSval. The peer echoes it back as TSecr, letting us measure RTT on every ACK.
    ts_val: u32,
    /// The peer's window-scale shift (Day 17, RFC 7323 §2): we left-shift its advertised window field
    /// by this to recover the true `SND.WND`. 0 when window scaling wasn't negotiated, so the shift
    /// is a no-op and the field is taken literally.
    snd_wscale: u8,
    /// SACK negotiated (Day 18, RFC 2018 §2): true only when BOTH SYNs carried SACK-Permitted. When
    /// set, our ACKs describe buffered out-of-order data in SACK blocks, and incoming SACK blocks let
    /// loss recovery retransmit only the genuine holes instead of go-back-N.
    sack_ok: bool,
}

impl Connection {
    pub fn state(&self) -> State {
        self.state
    }

    /// Passive open: a SYN arrived for a connection we don't have yet. Create the TCB in
    /// SYN_RCVD and return it together with the SYN-ACK packet bytes to send. Returns `None` if
    /// the incoming segment isn't a SYN (we only open on a SYN). `now_ms` timestamps the SYN-ACK
    /// in the retransmission queue (Day 12) so a lost SYN-ACK is resent on RTO.
    ///
    /// The ISN is **randomized** (RFC 6528): a predictable initial sequence number lets an
    /// off-path attacker forge segments / spoof connections. `accept_with_iss` takes a fixed ISN
    /// for deterministic tests.
    pub fn accept(
        ip_src: Ipv4Addr,
        ip_dst: Ipv4Addr,
        th: &TcpHeader,
        opts: &TcpOptions,
        now_ms: u64,
    ) -> Option<(Connection, Vec<u8>)> {
        Self::accept_with_iss_at(ip_src, ip_dst, th, opts, rand::random::<u32>(), now_ms)
    }

    /// Deterministic-ISS passive open for tests (records the SYN-ACK as if sent at t=0, which is
    /// exactly when the tests drive the clock from). Production goes through `accept`.
    #[cfg(test)]
    pub fn accept_with_iss(
        ip_src: Ipv4Addr,
        ip_dst: Ipv4Addr,
        th: &TcpHeader,
        iss: u32,
    ) -> Option<(Connection, Vec<u8>)> {
        Self::accept_with_iss_at(ip_src, ip_dst, th, &TcpOptions::default(), iss, 0)
    }

    /// Passive open with a caller-chosen initial send sequence number (ISS) and send time. `accept`
    /// wraps this with a random ISS; tests pass a fixed ISS so the handshake's seq/ack numbers are
    /// predictable. `opts` carries the peer's SYN options (its advertised MSS).
    pub fn accept_with_iss_at(
        ip_src: Ipv4Addr,
        ip_dst: Ipv4Addr,
        th: &TcpHeader,
        opts: &TcpOptions,
        iss: u32,
        now_ms: u64,
    ) -> Option<(Connection, Vec<u8>)> {
        if th.flags & SYN == 0 {
            return None;
        }

        let wnd: u16 = 1024;

        let mut conn = Connection {
            state: State::SynRcvd,
            // A SYN consumes one sequence number, so nxt = iss + 1. SND.WND is u32 (window scaling).
            send: SendSequence { iss, una: iss, nxt: iss.wrapping_add(1), wnd: wnd as u32 },
            // We expect the peer's next byte to be its SYN's seq + 1.
            recv: RecvSequence { irs: th.seq, nxt: th.seq.wrapping_add(1), wnd },
            local: (ip_dst, th.dst_port),
            remote: (ip_src, th.src_port),
            retx: RetxQueue::default(),
            time_wait_ms: 0,
            rtt: RttEstimator::default(),
            // First data byte will be at IRS + 1 (the SYN consumed IRS).
            reasm: Reassembler::new(th.seq.wrapping_add(1)),
            cong: CongestionControl::default(),
            send_buf: VecDeque::new(),
            recv_buf: Vec::new(),
            nagle: true, // Nagle on by default (RFC 9293 §3.7.4); TCP_NODELAY clears it
            persist_ms: 0, // persist timer disarmed until a zero window blocks pending data
            // Day 15: the most we may send the peer per segment = min(our MSS, the MSS it advertised
            // in its SYN). If it advertised none, fall back to our own (see DEFAULT_SEND_MSS).
            send_mss: opts.mss.map_or(DEFAULT_SEND_MSS, |m| m.min(OUR_MSS)),
            // Day 16: enable timestamps only if the peer's SYN offered them (RFC 7323 §3); seed
            // TS.Recent with its TSval so our SYN-ACK can echo it.
            ts_enabled: opts.timestamps.is_some(),
            ts_recent: opts.timestamps.map_or(0, |(tsval, _)| tsval),
            ts_val: now_ms as u32,
            // Day 17: window scaling negotiates per-direction. We left-shift the peer's window field
            // by the shift it advertised; 0 (no scaling) if its SYN carried no window-scale option.
            snd_wscale: opts.window_scale.unwrap_or(0),
            // Day 18: enable SACK only if the peer's SYN offered it; we echo SACK-Permitted in the
            // SYN-ACK below only in that case (RFC 2018 §2).
            sack_ok: opts.sack_permitted,
        };

        // SYN-ACK: our seq = ISS, ack = what we next expect from them (their seq + 1). It carries
        // OUR MSS option (Day 15), and — only if the peer offered each — a Window Scale option
        // (Day 17) and the Timestamps option echoing the peer's SYN TSval (Day 16, RFC 7323).
        let mut synack_opts = mss_option(OUR_MSS).to_vec();
        if opts.window_scale.is_some() {
            synack_opts.extend_from_slice(&ws_option(OUR_RCV_WSCALE));
        }
        if conn.ts_enabled {
            synack_opts.extend_from_slice(&ts_option(conn.ts_val, conn.ts_recent));
        }
        // Day 18: echo SACK-Permitted only if the peer's SYN offered it (RFC 2018 §2).
        if conn.sack_ok {
            synack_opts.extend_from_slice(&sack_perm_option());
        }
        let synack = conn.segment_opts(conn.send.iss, conn.recv.nxt, SYN | ACK, &synack_opts, &[]);
        // Day 12: the SYN-ACK consumes sequence number ISS (end = ISS + 1 = SND.NXT). Queue it for
        // retransmission so a lost SYN-ACK is resent on RTO instead of hanging the handshake — the
        // peer's final ACK clears it (RFC 9293 §3.8.1).
        conn.retx.record(conn.send.iss, conn.send.nxt, synack.clone(), now_ms);
        Some((conn, synack))
    }

    /// Active open: initiate a connection from `local` to `remote`. Returns the TCB (in
    /// SYN_SENT) and the SYN packet to send. Randomized ISN (RFC 6528). `now_ms` timestamps the
    /// SYN for retransmission.
    ///
    /// The binary runs as a passive server (it only `accept`s), so this client-side capability is
    /// exercised by tests rather than `main` — hence `allow(dead_code)`.
    #[allow(dead_code)]
    pub fn connect(local: (Ipv4Addr, u16), remote: (Ipv4Addr, u16), now_ms: u64) -> (Connection, Vec<u8>) {
        Self::connect_with_iss(local, remote, rand::random::<u32>(), now_ms)
    }

    /// Active open with a caller-chosen ISS and send time (deterministic, for tests).
    #[allow(dead_code)]
    pub fn connect_with_iss(
        local: (Ipv4Addr, u16),
        remote: (Ipv4Addr, u16),
        iss: u32,
        now_ms: u64,
    ) -> (Connection, Vec<u8>) {
        let wnd: u16 = 1024;
        let mut conn = Connection {
            state: State::SynSent,
            send: SendSequence { iss, una: iss, nxt: iss.wrapping_add(1), wnd: wnd as u32 },
            // The peer's sequence space is unknown until its SYN-ACK arrives.
            recv: RecvSequence { irs: 0, nxt: 0, wnd },
            local,
            remote,
            retx: RetxQueue::default(),
            time_wait_ms: 0,
            rtt: RttEstimator::default(),
            // Placeholder base; rebased once the peer's ISN arrives in the SYN-ACK.
            reasm: Reassembler::new(0),
            cong: CongestionControl::default(),
            send_buf: VecDeque::new(),
            recv_buf: Vec::new(),
            nagle: true, // Nagle on by default (RFC 9293 §3.7.4); TCP_NODELAY clears it
            persist_ms: 0, // persist timer disarmed until a zero window blocks pending data
            // Day 15: until the SYN-ACK reveals the peer's MSS, segment at our own (updated below).
            send_mss: DEFAULT_SEND_MSS,
            // Day 16: we OFFER timestamps in our SYN; they're enabled only if the SYN-ACK also
            // carries them (decided in on_segment's SYN_SENT branch).
            ts_enabled: false,
            ts_recent: 0,
            ts_val: now_ms as u32,
            // Day 17: learned from the SYN-ACK's window-scale option (0 until then = no scaling).
            snd_wscale: 0,
            // Day 18: we OFFER SACK-Permitted in our SYN (below); it's enabled only if the SYN-ACK
            // echoes it (decided in on_segment's SYN_SENT branch). RFC 2018 §2.
            sack_ok: false,
        };
        // SYN: seq = ISS, no ACK (we don't know the peer's seq yet). Carries OUR MSS option, a
        // Window Scale option (Day 17), and a Timestamps option offering RTTM/PAWS (TSecr = 0 — we
        // have nothing to echo yet).
        let mut syn_opts = mss_option(OUR_MSS).to_vec();
        syn_opts.extend_from_slice(&ws_option(OUR_RCV_WSCALE));
        syn_opts.extend_from_slice(&ts_option(conn.ts_val, 0));
        syn_opts.extend_from_slice(&sack_perm_option()); // Day 18: offer SACK (RFC 2018 §2)
        let syn = conn.segment_opts(conn.send.iss, 0, SYN, &syn_opts, &[]);
        // Day 12: the SYN consumes sequence number ISS (end = ISS + 1 = SND.NXT). Queue it so a
        // lost SYN is resent on RTO; the peer's SYN-ACK clears it (RFC 9293 §3.8.1).
        conn.retx.record(conn.send.iss, conn.send.nxt, syn.clone(), now_ms);
        (conn, syn)
    }

    /// Active close: send our FIN (valid only from ESTABLISHED) and enter FIN_WAIT_1. `now_ms`
    /// timestamps the FIN for retransmission (Day 12). The HTTP path in `main` calls this; the
    /// echo path closes passively.
    pub fn close(&mut self, now_ms: u64) -> Option<Vec<u8>> {
        if self.state != State::Established {
            return None;
        }
        self.ts_val = now_ms as u32; // Day 16: stamp the FIN with the current clock
        let out = self.segment(self.send.nxt, self.recv.nxt, FIN | ACK, &[]);
        self.send.nxt = self.send.nxt.wrapping_add(1); // our FIN consumes a sequence number
        // Day 12: queue the FIN (end = SND.NXT) so a lost FIN is resent until the peer ACKs it,
        // instead of leaving the teardown half-finished (RFC 9293 §3.8.1).
        self.retx.record(self.send.nxt.wrapping_sub(1), self.send.nxt, out.clone(), now_ms);
        self.state = State::FinWait1;
        Some(out)
    }

    /// Handle a packet on an existing connection. Convenience wrapper (timestamps with 0) for
    /// callers/tests that don't track retransmission time. (`main` uses `on_packet_at`.)
    #[allow(dead_code)]
    pub fn on_packet(&mut self, th: &TcpHeader, payload: &[u8]) -> Option<Vec<u8>> {
        self.on_packet_at(th, payload, 0)
    }

    /// Time-aware packet handler with no segment options — a thin wrapper over `on_segment` for
    /// callers/tests that don't carry options. `now_ms` lets sent data be queued for retransmission
    /// and incoming ACKs clear the queue. Returns bytes to send back, if any.
    pub fn on_packet_at(&mut self, th: &TcpHeader, payload: &[u8], now_ms: u64) -> Option<Vec<u8>> {
        self.on_segment(th, payload, &TcpOptions::default(), now_ms)
    }

    /// Full segment handler: like `on_packet_at` but also given the parsed TCP `options`, so the
    /// state machine can learn the peer's MSS (Day 15) and, later, timestamps / SACK blocks. `main`
    /// calls this with the options parsed off the wire.
    pub fn on_segment(
        &mut self,
        th: &TcpHeader,
        payload: &[u8],
        opts: &TcpOptions,
        now_ms: u64,
    ) -> Option<Vec<u8>> {
        self.ts_val = now_ms as u32; // Day 16: refresh our timestamp clock for anything we send

        // Active open: we sent a SYN and are waiting for the peer's SYN-ACK.
        if self.state == State::SynSent {
            // Accept the SYN-ACK only if it acknowledges our SYN (ack == SND.NXT).
            if th.flags & (SYN | ACK) == (SYN | ACK) && th.ack == self.send.nxt {
                self.recv.irs = th.seq;
                self.recv.nxt = th.seq.wrapping_add(1);
                self.reasm = Reassembler::new(self.recv.nxt); // now we know the peer's ISN
                self.send.una = th.ack;
                // Day 15: learn the peer's MSS from its SYN-ACK; bound our send segments by it.
                if let Some(mss) = opts.mss {
                    self.send_mss = mss.min(OUR_MSS);
                }
                // Day 16: timestamps are enabled iff the SYN-ACK also carries them (we offered in
                // our SYN). Seed TS.Recent so our segments echo the peer's clock.
                if let Some((tsval, _)) = opts.timestamps {
                    self.ts_enabled = true;
                    self.ts_recent = tsval;
                }
                // Day 17: adopt the peer's window scale from its SYN-ACK (we offered ours in the SYN).
                if let Some(shift) = opts.window_scale {
                    self.snd_wscale = shift;
                }
                // Day 18: SACK is enabled iff the SYN-ACK also carried SACK-Permitted (RFC 2018 §2).
                if opts.sack_permitted {
                    self.sack_ok = true;
                }
                // Day 12: the SYN-ACK acknowledges our SYN — drop it from the retx queue (no RTT
                // sample: a handshake segment can be ambiguous and isn't fed to the estimator here).
                let _ = self.retx.ack(self.send.una, now_ms);
                self.state = State::Established;
                // Complete the handshake with the final ACK.
                return Some(self.segment(self.send.nxt, self.recv.nxt, ACK, &[]));
            }
            return None; // not the SYN-ACK we expect → ignore
        }

        // Complete the handshake if we're still waiting for the client's ACK. (That ACK may
        // also piggyback data, so we fall through to data handling afterwards.)
        if self.state == State::SynRcvd {
            if th.flags & ACK != 0 && th.ack == self.send.nxt {
                self.send.una = th.ack;
                // Day 12: the final ACK acknowledges our SYN-ACK — drop it from the retx queue.
                let _ = self.retx.ack(self.send.una, now_ms);
                self.state = State::Established;
            } else {
                return None; // not the ACK we expect → ignore
            }
        }

        if self.state == State::Established {
            // Day 16 — PAWS (Protect Against Wrapped Sequences, RFC 7323 §5): on a fast, long-lived
            // connection the 32-bit sequence space can wrap, so an ancient duplicate could land in
            // the current window. Its *timestamp*, however, is older than anything we've recently
            // seen — so reject a segment whose TSval predates TS.Recent, acknowledging current state
            // rather than acting on stale data. When the timestamp is fresh, advance TS.Recent from
            // any segment at/under the left window edge (RFC 7323 §4.3) so we echo the peer's clock.
            if self.ts_enabled {
                if let Some((tsval, _)) = opts.timestamps {
                    if seq::before(tsval, self.ts_recent) {
                        return Some(self.segment(self.send.nxt, self.recv.nxt, ACK, &[]));
                    }
                    if !seq::after(th.seq, self.recv.nxt) {
                        self.ts_recent = tsval;
                    }
                }
            }

            // Flow control: track the peer's advertised receive window so we never send more
            // unacknowledged data than it can hold (RFC 9293 §3.4). The 16-bit window field is
            // left-shifted by the peer's negotiated window scale (Day 17) to recover the true
            // SND.WND. Keep the prior value so the duplicate-ACK test below can tell a real dup from
            // a pure window update (Day 14).
            let prev_wnd = self.send.wnd;
            let new_wnd = (th.window as u32) << self.snd_wscale;
            self.send.wnd = new_wnd;

            // Advance SND.UNA only if the ack is *acceptable*: SND.UNA < ACK <= SND.NXT, on the
            // wrapping 32-bit circle (RFC 9293 §3.4 via `seq::between`). A duplicate or
            // out-of-window ack is ignored rather than blindly trusted — the defensive version
            // of the earlier "store whatever they sent".
            if th.flags & ACK != 0 {
                // Day 18: apply any SACK blocks first (RFC 2018 §4) — mark those out-of-order ranges
                // as selectively acked, so the fast-retransmit below resends the genuine hole rather
                // than data the peer already holds. SACK blocks ride on (often duplicate) ACKs.
                if self.sack_ok && opts.sack_block_count > 0 {
                    self.retx.mark_sacked(&opts.sack_blocks[..opts.sack_block_count]);
                }
                if seq::between(self.send.una, th.ack, self.send.nxt) {
                    // New data acknowledged: advance SND.UNA, drop what was acked, sample the RTT
                    // (Karn's algorithm skips retransmitted segments), and grow the congestion
                    // window (slow start / congestion avoidance, RFC 5681).
                    let acked = th.ack.wrapping_sub(self.send.una);
                    self.send.una = th.ack;
                    // RTT: with timestamps (Day 16) the echoed TSecr dates the acked data exactly, so
                    // every ACK yields a clean sample — even for retransmitted data, since the echo
                    // disambiguates which copy (no Karn restriction). Without timestamps, fall back to
                    // timing the retx queue (Karn-limited to never-retransmitted segments).
                    if self.ts_enabled {
                        if let Some((_, tsecr)) = opts.timestamps {
                            self.rtt.sample(self.ts_val.wrapping_sub(tsecr) as u64);
                        }
                        let _ = self.retx.ack(self.send.una, now_ms);
                    } else if let Some(rtt_ms) = self.retx.ack(self.send.una, now_ms) {
                        self.rtt.sample(rtt_ms);
                    }
                    self.cong.on_ack(acked);
                } else if th.ack == self.send.una
                    && self.send.una != self.send.nxt
                    && payload.is_empty()
                    && new_wnd == prev_wnd
                    && new_wnd != 0
                {
                    // Duplicate ACK (RFC 5681 §2, all four conditions): acks no new data, carries no
                    // data, data is still in flight, AND the window is unchanged — so this is a
                    // congestion signal, not a window update or a zero-window probe response. The
                    // third in a row triggers fast retransmit of the oldest unacked segment, without
                    // waiting for the RTO (RFC 5681 §3.2). Window changes and zero-window re-acks are
                    // excluded here so they can't masquerade as loss (Day 14).
                    if self.cong.on_dup_ack(self.flight_size()) {
                        if let Some(pkt) = self.retx.fast_retransmit(now_ms) {
                            return Some(pkt);
                        }
                    }
                }
            }

            // Data handling via the reassembler: it buffers out-of-order segments, drops
            // duplicates, and returns only the bytes now contiguous from RCV.NXT (RFC 9293 §3.4).
            // Delivered bytes go into the receive buffer for the application; we do NOT echo here —
            // the app reads (`take_received`) and responds (`write` + `poll_transmit`).
            if !payload.is_empty() {
                let delivered = self.reasm.recv(th.seq, payload, self.recv.nxt);
                if !delivered.is_empty() {
                    self.recv.nxt = self.recv.nxt.wrapping_add(delivered.len() as u32);
                    self.recv_buf.extend_from_slice(&delivered);
                }
                // Acknowledge: a fresh RCV.NXT for in-order data, or a *duplicate ACK* for
                // out-of-order/duplicate data (three of which trigger the sender's fast retransmit).
                // Day 18: when SACK is on and we have out-of-order data buffered, this ACK also names
                // those ranges in SACK blocks, so the peer retransmits only the hole (RFC 2018 §3).
                let ack_opts = self.ack_options();
                return Some(self.segment_opts(self.send.nxt, self.recv.nxt, ACK, &ack_opts, &[]));
            }

            // The peer wants to close: a FIN (in order) occupies one sequence number. We
            // acknowledge it AND, since an echo server has no more data to send, include our
            // own FIN in the same segment, then wait for the final ACK in LAST_ACK. (A full
            // stack would pass through CLOSE_WAIT while the local app finishes sending.)
            if th.flags & FIN != 0 && th.seq == self.recv.nxt {
                self.recv.nxt = self.recv.nxt.wrapping_add(1); // FIN consumes a seq number
                let out = self.segment(self.send.nxt, self.recv.nxt, FIN | ACK, &[]);
                self.send.nxt = self.send.nxt.wrapping_add(1); // our FIN consumes one too
                // Day 12: queue our FIN (end = SND.NXT) so it is resent until the peer's final ACK.
                self.retx.record(self.send.nxt.wrapping_sub(1), self.send.nxt, out.clone(), now_ms);
                self.state = State::LastAck;
                return Some(out);
            }
        }

        if self.state == State::LastAck {
            // The connection is fully closed once the peer ACKs our FIN.
            if th.flags & ACK != 0 && th.ack == self.send.nxt {
                let _ = self.retx.ack(th.ack, now_ms); // Day 12: drop the now-acked FIN
                self.state = State::Closed;
            }
            return None;
        }

        // ── Active-close states (we initiated the close via `close()`) ──
        if self.state == State::FinWait1 {
            let acked_our_fin = th.flags & ACK != 0 && th.ack == self.send.nxt;
            // Day 12: once our FIN is acknowledged, drop it from the retx queue (whichever close
            // variant we end up in below).
            if acked_our_fin {
                let _ = self.retx.ack(th.ack, now_ms);
            }
            // The peer also sent its FIN (in order) — acknowledge it.
            if th.flags & FIN != 0 && th.seq == self.recv.nxt {
                self.recv.nxt = self.recv.nxt.wrapping_add(1);
                let out = self.segment(self.send.nxt, self.recv.nxt, ACK, &[]);
                if acked_our_fin {
                    self.state = State::TimeWait; // our FIN acked AND theirs received
                    self.time_wait_ms = now_ms;
                } else {
                    self.state = State::Closing; // simultaneous close: still need our FIN's ACK
                }
                return Some(out);
            }
            if acked_our_fin {
                self.state = State::FinWait2;
            }
            return None;
        }

        if self.state == State::FinWait2 {
            // Await the peer's FIN; acknowledge it and enter TIME_WAIT.
            if th.flags & FIN != 0 && th.seq == self.recv.nxt {
                self.recv.nxt = self.recv.nxt.wrapping_add(1);
                let out = self.segment(self.send.nxt, self.recv.nxt, ACK, &[]);
                self.state = State::TimeWait;
                self.time_wait_ms = now_ms;
                return Some(out);
            }
            return None;
        }

        if self.state == State::Closing {
            // Simultaneous close: we've ACKed their FIN; now wait for the ACK of ours.
            if th.flags & ACK != 0 && th.ack == self.send.nxt {
                let _ = self.retx.ack(th.ack, now_ms); // Day 12: drop the now-acked FIN
                self.state = State::TimeWait;
                self.time_wait_ms = now_ms;
            }
            return None;
        }

        None
    }

    /// Time-driven step: return any sent-but-unacknowledged segments whose RTO has elapsed, for
    /// the caller (the event loop) to re-send. Resets each segment's timer. The timeout is the
    /// connection's own *adaptive* estimate (RFC 6298) — short on a LAN, long on a slow path —
    /// not a fixed constant, so the caller no longer supplies one.
    pub fn on_tick(&mut self, now_ms: u64) -> Vec<Vec<u8>> {
        self.ts_val = now_ms as u32; // Day 16: refresh the timestamp clock for any probe we send
        // Expire TIME_WAIT after 2·MSL so the connection can finally be reaped (RFC 9293).
        const TIME_WAIT_MS: u64 = 2 * 120_000; // 2·MSL, with MSL = 2 minutes
        if self.state == State::TimeWait
            && now_ms.saturating_sub(self.time_wait_ms) >= TIME_WAIT_MS
        {
            self.state = State::Closed;
        }
        let mut out = self.retx.due(now_ms, self.rtt.rto());
        if !out.is_empty() {
            // The retransmission timer fired — the strongest congestion signal. Collapse cwnd to
            // one segment and re-enter slow start (RFC 5681 §3.1).
            let flight = self.flight_size();
            self.cong.on_timeout(flight);
            self.rtt.back_off(); // double the RTO per timeout (RFC 6298 §5.5 / Karn's backoff)
        }

        // Persist timer / zero-window probe (RFC 9293 §3.8.6.1). If the peer's window is shut but we
        // have data to send and nothing is in flight, there is no retransmission to lean on — and a
        // lost "window re-opened" ACK would deadlock both sides forever. So poke a single byte into
        // the closed window after one RTO. Once that probe is outstanding (FlightSize > 0) the
        // ordinary RTO retransmission keeps re-probing it; the peer's ACK (carrying its now-current
        // window) breaks the stall.
        if self.state == State::Established
            && self.send.wnd == 0
            && !self.send_buf.is_empty()
            && self.flight_size() == 0
        {
            if self.persist_ms == 0 {
                self.persist_ms = now_ms.saturating_add(self.rtt.rto()); // arm one RTO out
            } else if now_ms >= self.persist_ms {
                if let Some(byte) = self.send_buf.pop_front() {
                    let probe = self.segment(self.send.nxt, self.recv.nxt, ACK, &[byte]);
                    self.send.nxt = self.send.nxt.wrapping_add(1);
                    self.retx.record(self.send.nxt.wrapping_sub(1), self.send.nxt, probe.clone(), now_ms);
                    out.push(probe);
                }
                self.persist_ms = 0; // disarm; the retx queue now repeats the probe on its own RTO
            }
        } else {
            self.persist_ms = 0; // window open, nothing to send, or a probe already in flight
        }
        out
    }

    /// Bytes sent but not yet acknowledged — the "FlightSize" of RFC 5681 (`SND.NXT − SND.UNA`).
    fn flight_size(&self) -> u32 {
        self.send.nxt.wrapping_sub(self.send.una)
    }

    /// Bytes we may still send right now. Bounded by BOTH the receiver and the network: the
    /// classic `min(SND.WND, cwnd) − FlightSize` (RFC 5681). Saturates at 0 when the window is full.
    pub fn usable_window(&self) -> u32 {
        let limit = self.send.wnd.min(self.cong.window());
        limit.saturating_sub(self.flight_size())
    }

    /// Application send: queue `data` for transmission. The bytes go out on the next
    /// `poll_transmit`, as fast as the send window allows.
    pub fn write(&mut self, data: &[u8]) {
        self.send_buf.extend(data.iter().copied());
    }

    /// Set `TCP_NODELAY` (RFC 9293 §3.7.4): `true` disables Nagle's algorithm so even a tiny write
    /// is sent at once — the right choice for interactive/latency-sensitive traffic (ssh, games).
    /// The server binary leaves Nagle on; this is exercised by tests.
    #[allow(dead_code)]
    pub fn set_nodelay(&mut self, nodelay: bool) {
        self.nagle = !nodelay;
    }

    /// Drain the send buffer into wire segments, bounded by the **usable window**
    /// (`min(SND.WND, cwnd) − FlightSize`) and chopped to the MSS. Each segment advances SND.NXT
    /// and is recorded for retransmission. Returns the segments to send (possibly empty when the
    /// window is full — exactly how slow start throttles a bulk sender, RFC 5681). Valid only once
    /// ESTABLISHED.
    ///
    /// **Nagle's algorithm** (RFC 896 / RFC 9293 §3.7.4): while earlier data is still
    /// unacknowledged (`FlightSize > 0`), a *small* (sub-MSS) tail is held rather than dribbled out
    /// as a runt packet — it waits until that data is acked or a full segment accumulates. This
    /// trades a little latency for far fewer 41-byte packets on chatty connections; `TCP_NODELAY`
    /// (`!self.nagle`) opts out. A full-sized segment, and the first segment when nothing is in
    /// flight, are never held.
    pub fn poll_transmit(&mut self, now_ms: u64) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        if self.state != State::Established {
            return out;
        }
        self.ts_val = now_ms as u32; // Day 16: stamp outgoing data with the current clock
        let mss = self.send_mss as usize; // Day 15: the negotiated send MSS, not a fixed constant
        while !self.send_buf.is_empty() {
            let n = (self.usable_window() as usize).min(mss).min(self.send_buf.len());
            if n == 0 {
                break; // window full — wait for an ACK to slide it open
            }
            // Nagle: hold a sub-MSS segment while unacked data is outstanding, unless TCP_NODELAY.
            // (A full segment, or any segment when nothing is in flight, passes through.)
            if self.nagle && n < mss && self.flight_size() > 0 {
                break;
            }
            let payload: Vec<u8> = self.send_buf.drain(..n).collect();
            let seg = self.segment(self.send.nxt, self.recv.nxt, PSH | ACK, &payload);
            self.send.nxt = self.send.nxt.wrapping_add(n as u32);
            self.retx.record(self.send.nxt.wrapping_sub(n as u32), self.send.nxt, seg.clone(), now_ms);
            out.push(seg);
        }
        out
    }

    /// Application receive: take all reassembled, in-order bytes delivered so far, draining the
    /// receive buffer. Empty if nothing new has arrived.
    pub fn take_received(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.recv_buf)
    }

    #[cfg(test)]
    fn snd_nxt(&self) -> u32 {
        self.send.nxt
    }
    #[cfg(test)]
    fn rcv_nxt(&self) -> u32 {
        self.recv.nxt
    }
    #[cfg(test)]
    fn rto(&self) -> u64 {
        self.rtt.rto()
    }

    /// Build a segment from THIS connection's perspective (src = us, dst = peer). The advertised
    /// window is *our* receive window (`RCV.WND`) — how much WE can accept — never `send.wnd`,
    /// which is the peer's window and bounds only how much we may send. When timestamps are
    /// negotiated (Day 16) every such segment carries a Timestamps option (TSval = our clock,
    /// TSecr = TS.Recent); SYN/SYN-ACK build their options explicitly via `segment_opts`.
    fn segment(&self, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        if self.ts_enabled {
            self.segment_opts(seq, ack, flags, &ts_option(self.ts_val, self.ts_recent), payload)
        } else {
            self.segment_opts(seq, ack, flags, &[], payload)
        }
    }

    /// `segment` with explicit TCP options (must be 4-byte aligned). Used by the SYN/SYN-ACK path to
    /// carry the MSS option (Day 15) and, later, timestamps / window scale / SACK-permitted.
    fn segment_opts(&self, seq: u32, ack: u32, flags: u8, options: &[u8], payload: &[u8]) -> Vec<u8> {
        build_packet(self.local, self.remote, seq, ack, flags, self.recv.wnd, options, payload)
    }

    /// Options for an ordinary outgoing ACK: the Timestamps option (if negotiated), then SACK blocks
    /// describing our buffered out-of-order data (if SACK is negotiated and any exist). Each sub-blob
    /// is individually 4-byte aligned, so their concatenation is too (RFC 7323 §3, RFC 2018 §3).
    fn ack_options(&self) -> Vec<u8> {
        let mut o = Vec::new();
        if self.ts_enabled {
            o.extend_from_slice(&ts_option(self.ts_val, self.ts_recent));
        }
        if self.sack_ok {
            let blocks = self.reasm.sack_blocks();
            if !blocks.is_empty() {
                let take = blocks.len().min(MAX_SACK_BLOCKS);
                o.extend_from_slice(&sack_option(&blocks[..take]));
            }
        }
        o
    }
}

/// Build a complete IPv4 + TCP packet. `options` is the raw TCP-options blob, which **must already
/// be padded to a 4-byte boundary** (the data offset counts 32-bit words); pass `&[]` for the
/// common no-options case. This is the first time we synthesize headers from scratch rather than
/// mutating a received packet.
// A header builder genuinely needs each wire field as an argument; bundling them into a struct would
// just move the noise. The two callers (`segment_opts`, `build_rst`) keep it readable.
#[allow(clippy::too_many_arguments)]
fn build_packet(
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    options: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let (src_ip, src_port) = src;
    let (dst_ip, dst_port) = dst;

    debug_assert!(options.len().is_multiple_of(4), "TCP options must be 4-byte aligned");
    let tcp_hdr_len = 20 + options.len(); // fixed header + options
    let tcp_len = tcp_hdr_len + payload.len(); // header + options + data
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

    // ── TCP header (bytes 20..20+tcp_hdr_len) + payload ──
    let t = 20;
    pkt[t..t + 2].copy_from_slice(&src_port.to_be_bytes());
    pkt[t + 2..t + 4].copy_from_slice(&dst_port.to_be_bytes());
    pkt[t + 4..t + 8].copy_from_slice(&seq.to_be_bytes());
    pkt[t + 8..t + 12].copy_from_slice(&ack.to_be_bytes());
    // Data offset = (20 + options) / 4 words, in the high nibble of byte 12; reserved bits 0.
    pkt[t + 12] = ((tcp_hdr_len / 4) as u8) << 4;
    pkt[t + 13] = flags;
    pkt[t + 14..t + 16].copy_from_slice(&window.to_be_bytes());
    // checksum (t+16..t+18) and urgent pointer (t+18..t+20) left zero for now
    pkt[t + 20..t + 20 + options.len()].copy_from_slice(options);
    pkt[t + tcp_hdr_len..].copy_from_slice(payload);

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
    build_packet((ip_dst, th.dst_port), (ip_src, th.src_port), seq, ack, flags, 0, &[], &[])
}

/// One sent-but-unacknowledged segment, kept so we can resend it if its ACK never comes.
#[derive(Debug, Clone)]
struct Unacked {
    /// First sequence number this segment covers (Day 18) — its left edge, for matching SACK blocks.
    start_seq: u32,
    /// One past the last sequence number this segment covers; fully acked when SND.UNA reaches it.
    end_seq: u32,
    /// The complete IP+TCP bytes, ready to resend verbatim.
    packet: Vec<u8>,
    /// When it was (last) sent, in milliseconds — supplied by the caller's clock.
    sent_at_ms: u64,
    /// How many times it's been retransmitted (for backoff / giving up).
    retries: u32,
    /// Selectively acknowledged by a peer SACK block (Day 18, RFC 2018): the peer holds this range
    /// out of order, so loss recovery skips it and resends only the holes that precede it.
    sacked: bool,
}

/// The per-connection retransmission queue (RFC 9293 §3.8.1) — the heart of TCP reliability.
/// Time is passed in (`now_ms`) rather than read from a clock, so the logic is unit-testable
/// without sleeping; the event loop supplies the real time and resends whatever is `due`.
#[derive(Debug, Default)]
pub struct RetxQueue {
    segments: Vec<Unacked>,
}

#[allow(dead_code)] // is_empty()/len() are exercised only by tests
impl RetxQueue {
    /// Record a segment we just sent, covering `[start_seq, end_seq)` (a SYN/FIN counts as one byte,
    /// so `end_seq = start_seq + 1`). `start_seq` is kept so a peer SACK block can mark it.
    pub fn record(&mut self, start_seq: u32, end_seq: u32, packet: Vec<u8>, now_ms: u64) {
        self.segments.push(Unacked {
            start_seq,
            end_seq,
            packet,
            sent_at_ms: now_ms,
            retries: 0,
            sacked: false,
        });
    }

    /// Drop every segment the peer has now fully acknowledged (`end_seq <= SND.UNA`, mod 2³²).
    /// Returns an RTT sample (ms) — `now_ms − send time` — for the oldest freshly-acked segment
    /// that was **never retransmitted**, else `None`. A retransmitted segment yields no sample:
    /// we can't tell which copy the ack answers, so timing it would corrupt SRTT (Karn's
    /// algorithm, RFC 6298 §3). The caller feeds any returned sample to the RTT estimator.
    pub fn ack(&mut self, una: u32, now_ms: u64) -> Option<u64> {
        let mut sample = None;
        self.segments.retain(|s| {
            // `una` still "before" end_seq ⇒ segment not yet fully acked ⇒ keep it.
            let still_unacked = seq::before(una, s.end_seq);
            if !still_unacked && s.retries == 0 && sample.is_none() {
                sample = Some(now_ms.saturating_sub(s.sent_at_ms));
            }
            still_unacked
        });
        sample
    }

    /// Packets whose retransmission timeout (`rto_ms`) has elapsed. Resets each one's timer and
    /// bumps its retry count, then returns clones for the caller to re-send.
    pub fn due(&mut self, now_ms: u64, rto_ms: u64) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for s in &mut self.segments {
            // Day 18: never resend a SACKed range — the peer already has it (RFC 2018 §4); only the
            // holes need retransmitting. (We keep SACK state across RTOs; a production stack clears
            // it if it detects the peer reneging on previously-SACKed data, RFC 6675 §5.1.)
            if !s.sacked && now_ms.saturating_sub(s.sent_at_ms) >= rto_ms {
                s.sent_at_ms = now_ms;
                s.retries += 1;
                out.push(s.packet.clone());
            }
        }
        out
    }

    /// Resend the oldest unacknowledged segment immediately (fast retransmit, RFC 5681 §3.2).
    /// Resets its timer and counts it as a retransmission so Karn's algorithm suppresses its
    /// RTT sample. Returns the packet bytes to send, or `None` if nothing is outstanding.
    pub fn fast_retransmit(&mut self, now_ms: u64) -> Option<Vec<u8>> {
        // Day 18: resend the oldest segment the peer has NOT selectively acked — the first genuine
        // hole — instead of blindly the oldest (which SACK may reveal the peer already holds).
        self.segments.iter_mut().find(|s| !s.sacked).map(|s| {
            s.retries += 1;
            s.sent_at_ms = now_ms;
            s.packet.clone()
        })
    }

    /// Mark every queued segment fully covered by one of the peer's SACK blocks (RFC 2018 §4) as
    /// selectively acknowledged. A segment `[start, end)` is covered by a block `[left, right)` iff
    /// `left ≤ start` and `end ≤ right`, all compared modulo 2³². SACKed segments are skipped by
    /// `due` and `fast_retransmit`, so loss recovery resends only the holes between them.
    pub fn mark_sacked(&mut self, blocks: &[(u32, u32)]) {
        for s in &mut self.segments {
            if s.sacked {
                continue;
            }
            for &(left, right) in blocks {
                let covered = !seq::before(s.start_seq, left) && !seq::after(s.end_seq, right);
                if covered {
                    s.sacked = true;
                    break;
                }
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    pub fn len(&self) -> usize {
        self.segments.len()
    }
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
    fn rejects_bad_data_offset() {
        let mut small = syn_segment();
        small[12] = 0x40; // 4 words = 16 bytes < 20-byte minimum → reject
        assert!(parse(&small).is_none());
        let mut big = syn_segment();
        big[12] = 0xf0; // 15 words = 60 bytes, more than the 20-byte segment → reject
        assert!(parse(&big).is_none());
    }

    #[test]
    fn accept_produces_valid_synack() {
        let th = parse(&syn_segment()).unwrap();
        let (conn, synack) = Connection::accept_with_iss(PEER, ME, &th, 0).expect("a SYN-ACK");

        assert_eq!(conn.state(), State::SynRcvd);
        assert_eq!(synack.len(), 44); // 20 IP + 24 TCP (20 fixed + 4-byte MSS option), no payload

        // IP layer: addresses swapped, valid header checksum.
        let iph = ip::parse(&synack).unwrap();
        assert_eq!(iph.src, ME);
        assert_eq!(iph.dst, PEER);
        assert_eq!(iph.protocol, 6);
        assert_eq!(utils::checksum(&synack[..20]), 0, "IP checksum invalid");

        // TCP layer: SYN|ACK, our seq = ISS (0), ack = client_seq + 1 = 101, data offset 24 (options).
        let th2 = parse(&synack[20..]).unwrap();
        assert_eq!(th2.flags, SYN | ACK);
        assert_eq!(th2.seq, 0); // ISS
        assert_eq!(th2.ack, 101); // 100 + 1
        assert_eq!(th2.src_port, 80);
        assert_eq!(th2.dst_port, 0x1234);
        assert_eq!(th2.data_offset, 24); // 20-byte fixed header + 4-byte MSS option

        // The SYN-ACK advertises OUR receive MSS (Day 15).
        let emitted = parse_options(&synack[20 + 20..20 + th2.data_offset]);
        assert_eq!(emitted.mss, Some(OUR_MSS));

        // TCP checksum must verify to 0 (includes the pseudo-header AND the option bytes).
        assert_eq!(tcp_checksum(ME, PEER, &synack[20..]), 0, "TCP checksum invalid");
    }

    #[test]
    fn final_ack_reaches_established() {
        let th = parse(&syn_segment()).unwrap();
        let (mut conn, _synack) = Connection::accept_with_iss(PEER, ME, &th, 0).unwrap();

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
    fn established_delivers_data_then_app_echoes() {
        // Establish the connection first.
        let th = parse(&syn_segment()).unwrap();
        let (mut conn, _synack) = Connection::accept_with_iss(PEER, ME, &th, 0).unwrap();
        let handshake_ack = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 1,
            data_offset: 20, flags: ACK, window: 0xffff,
        };
        conn.on_packet(&handshake_ack, &[]);
        assert_eq!(conn.state(), State::Established);

        // Client sends 2 bytes "hi" in-order at seq 101. We reply with a bare ACK and deliver the
        // bytes to the application's receive buffer (no inline echo).
        let data = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 1,
            data_offset: 20, flags: PSH | ACK, window: 0xffff,
        };
        let ackseg = conn.on_packet(&data, b"hi").expect("an ACK");
        assert_eq!(conn.rcv_nxt(), 103); // 101 + 2 received
        let ah = parse(&ackseg[20..]).unwrap();
        assert_eq!(ah.flags, ACK);
        assert_eq!(ah.ack, 103);
        assert_eq!(ackseg.len(), 40); // header only — no payload
        assert_eq!(conn.take_received(), b"hi"); // delivered to the application

        // The echo application writes the bytes back; poll_transmit puts them on the wire.
        conn.write(b"hi");
        let segs = conn.poll_transmit(0);
        assert_eq!(segs.len(), 1);
        let echo = &segs[0];
        assert_eq!(conn.snd_nxt(), 3); // 1 + 2 sent
        let iph = ip::parse(echo).unwrap();
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
    fn active_close_to_timewait_then_closed() {
        let th = parse(&syn_segment()).unwrap();
        let (mut conn, _s) = Connection::accept_with_iss(PEER, ME, &th, 0).unwrap();
        let hs_ack = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 1,
            data_offset: 20, flags: ACK, window: 0xffff,
        };
        conn.on_packet_at(&hs_ack, &[], 0);
        assert_eq!(conn.state(), State::Established);

        // We actively close → our FIN, FIN_WAIT_1.
        let fin = conn.close(0).expect("our FIN");
        assert_eq!(conn.state(), State::FinWait1);
        let finh = parse(&fin[20..]).unwrap();
        assert_eq!(finh.flags, FIN | ACK);
        assert_eq!(finh.seq, 1); // SND.NXT before its +1
        assert_eq!(tcp_checksum(ME, PEER, &fin[20..]), 0);

        // Peer ACKs our FIN (SND.NXT is now 2) → FIN_WAIT_2.
        let ack = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 2,
            data_offset: 20, flags: ACK, window: 0xffff,
        };
        assert!(conn.on_packet_at(&ack, &[], 0).is_none());
        assert_eq!(conn.state(), State::FinWait2);

        // Peer sends its FIN → we ACK it and enter TIME_WAIT.
        let peer_fin = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 2,
            data_offset: 20, flags: FIN | ACK, window: 0xffff,
        };
        let our_ack = conn.on_packet_at(&peer_fin, &[], 1000).expect("ACK of their FIN");
        assert_eq!(conn.state(), State::TimeWait);
        let ah = parse(&our_ack[20..]).unwrap();
        assert_eq!(ah.flags, ACK);
        assert_eq!(ah.ack, 102); // their FIN at seq 101, +1

        // TIME_WAIT expires after 2·MSL → CLOSED.
        conn.on_tick(1000); // before timeout: still TIME_WAIT
        assert_eq!(conn.state(), State::TimeWait);
        conn.on_tick(1000 + 240_000); // after 2·MSL
        assert_eq!(conn.state(), State::Closed);
    }

    #[test]
    fn passive_close_via_fin() {
        let th = parse(&syn_segment()).unwrap();
        let (mut conn, _s) = Connection::accept_with_iss(PEER, ME, &th, 0).unwrap();
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
        assert!(Connection::accept(PEER, ME, &th, &TcpOptions::default(), 0).is_none());
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

    #[test]
    fn tracks_peer_window() {
        let th = parse(&syn_segment()).unwrap();
        let (mut conn, _s) = Connection::accept_with_iss(PEER, ME, &th, 0).unwrap();
        let hs_ack = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 1,
            data_offset: 20, flags: ACK, window: 0xffff,
        };
        conn.on_packet_at(&hs_ack, &[], 0);
        // Peer advertises a 500-byte window; nothing is in flight yet → usable = 500.
        let probe = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 1,
            data_offset: 20, flags: ACK, window: 500,
        };
        conn.on_packet_at(&probe, &[], 0);
        assert_eq!(conn.usable_window(), 500);
    }

    #[test]
    fn advertises_our_receive_window_not_the_peers() {
        let th = parse(&syn_segment()).unwrap();
        let (mut conn, _s) = Connection::accept_with_iss(PEER, ME, &th, 0).unwrap();
        let hs_ack = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 1,
            data_offset: 20, flags: ACK, window: 0xffff,
        };
        conn.on_packet_at(&hs_ack, &[], 0);

        // The peer advertises a huge window; our ACK must still advertise OUR 1024-byte receive
        // window, never parrot the peer's (which would over-claim buffer we lack).
        let data = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 1,
            data_offset: 20, flags: PSH | ACK, window: 0xffff,
        };
        let ackseg = conn.on_packet_at(&data, b"hi", 0).expect("an ACK");
        let ah = parse(&ackseg[20..]).unwrap();
        assert_eq!(ah.window, 1024);
    }

    #[test]
    fn reassembles_out_of_order_data() {
        let th = parse(&syn_segment()).unwrap();
        let (mut conn, _s) = Connection::accept_with_iss(PEER, ME, &th, 0).unwrap();
        let hs_ack = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 1,
            data_offset: 20, flags: ACK, window: 0xffff,
        };
        conn.on_packet_at(&hs_ack, &[], 0);
        assert_eq!(conn.state(), State::Established);

        // The peer's SECOND chunk arrives first: "lo" at seq 103 (we still expect 101). We can't
        // deliver it → reply with a bare duplicate ACK still acknowledging seq 101.
        let second = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 103, ack: 1,
            data_offset: 20, flags: PSH | ACK, window: 0xffff,
        };
        let dup = conn.on_packet_at(&second, b"lo", 0).expect("a duplicate ACK");
        let dh = parse(&dup[20..]).unwrap();
        assert_eq!(dh.flags, ACK);
        assert_eq!(dh.ack, 101); // still waiting for byte 101
        assert_eq!(dup.len(), 40); // header only, no payload
        assert_eq!(conn.rcv_nxt(), 101); // RCV.NXT unmoved

        // Now the FIRST chunk "he" at seq 101 arrives → the gap fills, both flush, and we echo
        // the contiguous "helo", acknowledging through seq 105 (101 + 4 bytes).
        let first = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 1,
            data_offset: 20, flags: PSH | ACK, window: 0xffff,
        };
        let ackseg = conn.on_packet_at(&first, b"he", 0).expect("an ACK");
        let ah = parse(&ackseg[20..]).unwrap();
        assert_eq!(ah.flags, ACK);
        assert_eq!(ah.ack, 105); // 101 + 4 bytes (he + lo)
        assert_eq!(ackseg.len(), 40); // header only
        assert_eq!(conn.rcv_nxt(), 105);
        assert_eq!(conn.take_received(), b"helo"); // both chunks delivered, in order
    }

    #[test]
    fn three_dup_acks_fast_retransmit_the_oldest_segment() {
        let th = parse(&syn_segment()).unwrap();
        let (mut conn, _s) = Connection::accept_with_iss(PEER, ME, &th, 0).unwrap();
        let hs_ack = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 1,
            data_offset: 20, flags: ACK, window: 0xffff,
        };
        conn.on_packet_at(&hs_ack, &[], 0);

        // The app sends "hi" → it's now unacknowledged in flight (seq 1).
        conn.write(b"hi");
        let segs = conn.poll_transmit(0);
        assert_eq!(segs.len(), 1);
        let echo = segs[0].clone();

        // Three duplicate ACKs (each acks seq 1, no new data, no payload). The first two do
        // nothing; the third fast-retransmits the oldest unacked segment — our echo — at once.
        let dup = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 103, ack: 1,
            data_offset: 20, flags: ACK, window: 0xffff,
        };
        assert!(conn.on_packet_at(&dup, &[], 1).is_none()); // 1st dup
        assert!(conn.on_packet_at(&dup, &[], 2).is_none()); // 2nd dup
        let resent = conn.on_packet_at(&dup, &[], 3).expect("fast retransmit"); // 3rd dup
        assert_eq!(resent, echo);
    }

    #[test]
    fn bulk_send_is_gated_by_the_congestion_window() {
        use crate::congestion::MSS;
        let th = parse(&syn_segment()).unwrap();
        let (mut conn, _s) = Connection::accept_with_iss(PEER, ME, &th, 0).unwrap();
        let hs_ack = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 1,
            data_offset: 20, flags: ACK, window: 0xffff,
        };
        conn.on_packet_at(&hs_ack, &[], 0);

        // Queue 5000 bytes. cwnd starts at 1 MSS, so only ONE full-MSS segment leaves now.
        conn.write(&vec![b'x'; 5000]);
        let first = conn.poll_transmit(0);
        assert_eq!(first.len(), 1);
        let fh = parse(&first[0][20..]).unwrap();
        assert_eq!(first[0].len() - 20 - fh.data_offset, MSS as usize); // 1460-byte payload
        assert_eq!(fh.seq, 1);

        // Until it's acked the window is full — nothing more goes out.
        assert!(conn.poll_transmit(0).is_empty());

        // Peer ACKs the 1460 bytes → slow start grows cwnd to 2 MSS, so two segments now fit.
        let ack = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 1 + MSS,
            data_offset: 20, flags: ACK, window: 0xffff,
        };
        conn.on_packet_at(&ack, &[], 0);
        assert_eq!(conn.poll_transmit(0).len(), 2);
    }

    #[test]
    fn connection_retransmits_then_clears_on_ack() {
        let th = parse(&syn_segment()).unwrap();
        let (mut conn, _s) = Connection::accept_with_iss(PEER, ME, &th, 0).unwrap();
        let hs_ack = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 1,
            data_offset: 20, flags: ACK, window: 0xffff,
        };
        conn.on_packet_at(&hs_ack, &[], 0);
        assert_eq!(conn.state(), State::Established);

        // App writes "hi"; poll_transmit emits it at t=0 (queued for retransmission).
        conn.write(b"hi");
        let segs = conn.poll_transmit(0);
        assert_eq!(segs.len(), 1);
        let echo = segs[0].clone();

        // No RTT sample yet, so the RTO is the conservative 200 ms default.
        assert_eq!(conn.rto(), 200);
        assert!(conn.on_tick(150).is_empty()); // before RTO: nothing resent
        let resent = conn.on_tick(250); // after the 200 ms RTO: the echo is resent
        assert_eq!(resent, vec![echo]);

        // Peer ACKs our echoed data (SND.NXT advanced to 3) → the retx queue clears. The segment
        // was retransmitted, so Karn suppresses the RTT sample and the backed-off RTO holds — the
        // one timeout doubled it 200 → 400.
        let ack = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 103, ack: 3,
            data_offset: 20, flags: ACK, window: 0xffff,
        };
        conn.on_packet_at(&ack, &[], 300);
        assert_eq!(conn.rto(), 400);
        assert!(conn.on_tick(600).is_empty());
    }

    #[test]
    fn ack_of_new_data_samples_rtt_and_adapts_rto() {
        let th = parse(&syn_segment()).unwrap();
        let (mut conn, _s) = Connection::accept_with_iss(PEER, ME, &th, 0).unwrap();
        let hs_ack = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 1,
            data_offset: 20, flags: ACK, window: 0xffff,
        };
        conn.on_packet_at(&hs_ack, &[], 0);

        // App writes "hi"; poll_transmit sends it at t=0 (queued for retransmission).
        conn.write(b"hi");
        conn.poll_transmit(0);
        assert_eq!(conn.rto(), 200); // still the default — no sample yet

        // Peer ACKs the sent bytes 120 ms later, never having forced a retransmission.
        let ack = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 103, ack: 3,
            data_offset: 20, flags: ACK, window: 0xffff,
        };
        conn.on_packet_at(&ack, &[], 120);

        // First sample R=120 → SRTT=120, RTTVAR=60 → RTO = 120 + 4·60 = 360.
        assert_eq!(conn.rto(), 360);
    }

    #[test]
    fn retx_records_acks_and_clears() {
        let mut q = RetxQueue::default();
        q.record(8, 11, vec![1, 2, 3], 0); // segment [8,11)
        q.record(18, 21, vec![4, 5, 6], 0); // segment [18,21)
        assert_eq!(q.len(), 2);
        assert_eq!(q.ack(11, 30), Some(30)); // UNA=11 → first acked at t=30 → RTT sample 30
        assert_eq!(q.len(), 1);
        assert_eq!(q.ack(21, 40), Some(40)); // second fully acked → sample 40
        assert!(q.is_empty());
    }

    #[test]
    fn retx_partial_ack_keeps_unacked() {
        let mut q = RetxQueue::default();
        q.record(10, 11, vec![1], 0);
        q.record(20, 21, vec![2], 0);
        q.ack(15, 0); // covers the first (end 11 <= 15), not the second (end 21 > 15)
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn retx_fires_after_rto() {
        let mut q = RetxQueue::default();
        q.record(10, 11, vec![0xAB], 0);
        assert!(q.due(50, 100).is_empty()); // 50ms < 100ms RTO → nothing due
        let resent = q.due(150, 100); // 150ms >= RTO → due
        assert_eq!(resent, vec![vec![0xABu8]]);
        assert!(q.due(160, 100).is_empty()); // timer reset → not due again yet
        assert_eq!(q.due(300, 100).len(), 1); // due again after another RTO
    }

    #[test]
    fn retx_ack_wraparound() {
        let mut q = RetxQueue::default();
        // Segment ends just past the wrap; an ack past it (mod 2^32) clears it.
        q.record(2, 3, vec![9], 0); // [2,3), end_seq 3, conceptually after wrapping from ~0xFFFFFFFF
        q.ack(3, 0);
        assert!(q.is_empty());
    }

    #[test]
    fn active_open_completes() {
        // We initiate: connect from ME:50000 to PEER:80, ISS 0.
        let (mut conn, syn) = Connection::connect_with_iss((ME, 50000), (PEER, 80), 0, 0);
        assert_eq!(conn.state(), State::SynSent);

        // The SYN we emit: flags SYN, seq 0, from us to the peer, valid checksums.
        let synh = parse(&syn[20..]).unwrap();
        assert_eq!(synh.flags, SYN);
        assert_eq!(synh.seq, 0);
        assert_eq!(synh.src_port, 50000);
        assert_eq!(synh.dst_port, 80);
        assert_eq!(utils::checksum(&syn[..20]), 0);
        assert_eq!(tcp_checksum(ME, PEER, &syn[20..]), 0);

        // The peer answers SYN-ACK: its seq 900, ack 1 (acks our ISS+1).
        let synack = TcpHeader {
            src_port: 80, dst_port: 50000, seq: 900, ack: 1,
            data_offset: 20, flags: SYN | ACK, window: 0xffff,
        };
        let out = conn.on_packet(&synack, &[]).expect("the final ACK");
        assert_eq!(conn.state(), State::Established);

        // The ACK we send: seq = our SND.NXT (1), ack = peer seq + 1 (901), flags ACK.
        let ackh = parse(&out[20..]).unwrap();
        assert_eq!(ackh.flags, ACK);
        assert_eq!(ackh.seq, 1);
        assert_eq!(ackh.ack, 901);
        assert_eq!(tcp_checksum(ME, PEER, &out[20..]), 0, "TCP checksum invalid");
    }

    // ── Day 12: control-segment (SYN / SYN-ACK / FIN) retransmission ──

    #[test]
    fn synack_retransmits_until_final_ack() {
        let th = parse(&syn_segment()).unwrap();
        // The SYN-ACK is queued for retransmission at send time (t=0), end_seq = ISS+1 = 1.
        let (mut conn, synack) = Connection::accept_with_iss(PEER, ME, &th, 0).unwrap();

        // No RTT sample yet → 200 ms default RTO. Before it, nothing is resent…
        assert!(conn.on_tick(150).is_empty());
        // …after it, the SYN-ACK goes out again, byte-for-byte.
        assert_eq!(conn.on_tick(250), vec![synack.clone()]);

        // The client's final ACK acknowledges our SYN-ACK → it leaves the queue and stays gone.
        let hs_ack = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 1,
            data_offset: 20, flags: ACK, window: 0xffff,
        };
        conn.on_packet_at(&hs_ack, &[], 300);
        assert_eq!(conn.state(), State::Established);
        assert!(conn.on_tick(1000).is_empty(), "SYN-ACK must not be resent after it is acked");
    }

    #[test]
    fn syn_retransmits_until_synack() {
        // Active open: the SYN is queued at t=0, end_seq = ISS+1 = 1.
        let (mut conn, syn) = Connection::connect_with_iss((ME, 50000), (PEER, 80), 0, 0);
        assert_eq!(conn.state(), State::SynSent);

        assert!(conn.on_tick(150).is_empty());
        assert_eq!(conn.on_tick(250), vec![syn.clone()]); // resent after the RTO

        // The peer's SYN-ACK acknowledges our SYN → it clears.
        let synack = TcpHeader {
            src_port: 80, dst_port: 50000, seq: 900, ack: 1,
            data_offset: 20, flags: SYN | ACK, window: 0xffff,
        };
        conn.on_packet_at(&synack, &[], 300);
        assert_eq!(conn.state(), State::Established);
        assert!(conn.on_tick(1000).is_empty(), "SYN must not be resent after it is acked");
    }

    #[test]
    fn passive_fin_retransmits_until_acked() {
        let th = parse(&syn_segment()).unwrap();
        let (mut conn, _s) = Connection::accept_with_iss(PEER, ME, &th, 0).unwrap();
        let hs_ack = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 1,
            data_offset: 20, flags: ACK, window: 0xffff,
        };
        conn.on_packet_at(&hs_ack, &[], 0);

        // Peer closes; our FIN-ACK (LastAck) is queued at t=0, end_seq = SND.NXT = 2.
        let fin = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 1,
            data_offset: 20, flags: FIN | ACK, window: 0xffff,
        };
        let finack = conn.on_packet_at(&fin, &[], 0).expect("our FIN-ACK");
        assert_eq!(conn.state(), State::LastAck);
        assert_eq!(conn.on_tick(250), vec![finack.clone()]); // resent after the RTO

        // The peer's ACK of our FIN closes the connection and clears the queue.
        let last = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 102, ack: 2,
            data_offset: 20, flags: ACK, window: 0xffff,
        };
        conn.on_packet_at(&last, &[], 300);
        assert_eq!(conn.state(), State::Closed);
        assert!(conn.on_tick(1000).is_empty(), "FIN must not be resent after it is acked");
    }

    #[test]
    fn active_fin_retransmits_until_acked() {
        let th = parse(&syn_segment()).unwrap();
        let (mut conn, _s) = Connection::accept_with_iss(PEER, ME, &th, 0).unwrap();
        let hs_ack = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 1,
            data_offset: 20, flags: ACK, window: 0xffff,
        };
        conn.on_packet_at(&hs_ack, &[], 0);

        // We actively close; our FIN is queued at t=0, end_seq = SND.NXT = 2.
        let fin = conn.close(0).expect("our FIN");
        assert_eq!(conn.state(), State::FinWait1);
        assert_eq!(conn.on_tick(250), vec![fin.clone()]); // resent after the RTO

        // The peer ACKs our FIN → it clears and we advance to FIN_WAIT_2.
        let ack = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 2,
            data_offset: 20, flags: ACK, window: 0xffff,
        };
        conn.on_packet_at(&ack, &[], 300);
        assert_eq!(conn.state(), State::FinWait2);
        assert!(conn.on_tick(1000).is_empty(), "FIN must not be resent after it is acked");
    }

    // ── Day 13: Nagle's algorithm + TCP_NODELAY ──

    /// Helper: establish a connection (ISS 0, peer window 0xffff) ready for sending.
    fn established_conn() -> Connection {
        let th = parse(&syn_segment()).unwrap();
        let (mut conn, _s) = Connection::accept_with_iss(PEER, ME, &th, 0).unwrap();
        let hs_ack = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 1,
            data_offset: 20, flags: ACK, window: 0xffff,
        };
        conn.on_packet_at(&hs_ack, &[], 0);
        assert_eq!(conn.state(), State::Established);
        conn
    }

    fn payload_of(pkt: &[u8]) -> Vec<u8> {
        let h = parse(&pkt[20..]).unwrap();
        pkt[20 + h.data_offset..].to_vec()
    }

    #[test]
    fn nagle_holds_small_write_until_prior_data_acked() {
        let mut conn = established_conn();

        // First small write: nothing in flight → sent immediately.
        conn.write(b"hello");
        let first = conn.poll_transmit(0);
        assert_eq!(first.len(), 1);
        assert_eq!(payload_of(&first[0]), b"hello");

        // Second small write while "hello" is still unacknowledged → Nagle holds it.
        conn.write(b"abc");
        assert!(conn.poll_transmit(0).is_empty(), "Nagle must hold the sub-MSS write");

        // Peer ACKs "hello" (seq 1..6 → ack 6): nothing in flight → the held bytes flush.
        let ack = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 6,
            data_offset: 20, flags: ACK, window: 0xffff,
        };
        conn.on_packet_at(&ack, &[], 0);
        let flushed = conn.poll_transmit(0);
        assert_eq!(flushed.len(), 1);
        assert_eq!(payload_of(&flushed[0]), b"abc");
    }

    #[test]
    fn nodelay_sends_small_write_immediately() {
        let mut conn = established_conn();
        conn.set_nodelay(true); // disable Nagle

        conn.write(b"hello");
        assert_eq!(conn.poll_transmit(0).len(), 1);

        // With TCP_NODELAY, the second small write goes out at once despite data in flight.
        conn.write(b"abc");
        let segs = conn.poll_transmit(0);
        assert_eq!(segs.len(), 1);
        assert_eq!(payload_of(&segs[0]), b"abc");
    }

    #[test]
    fn nagle_never_holds_a_full_segment() {
        use crate::congestion::MSS;
        let mut conn = established_conn();

        // Grow cwnd to 2·MSS: send one full segment and have it acknowledged.
        conn.write(&vec![b'x'; MSS as usize]);
        assert_eq!(conn.poll_transmit(0).len(), 1);
        let ack = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 1 + MSS,
            data_offset: 20, flags: ACK, window: 0xffff,
        };
        conn.on_packet_at(&ack, &[], 0);

        // Now send 2·MSS: BOTH full segments go out, even though the second leaves while the first
        // is in flight — Nagle only ever holds a *sub-MSS* tail.
        conn.write(&vec![b'y'; 2 * MSS as usize]);
        let segs = conn.poll_transmit(0);
        assert_eq!(segs.len(), 2);
        for s in &segs {
            assert_eq!(payload_of(s).len(), MSS as usize);
        }
    }

    // ── Day 14: zero-window probes (persist timer) ──

    #[test]
    fn zero_window_arms_then_fires_persist_probe() {
        let mut conn = established_conn();

        // The peer slams its receive window shut.
        let zero = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 1,
            data_offset: 20, flags: ACK, window: 0,
        };
        conn.on_packet_at(&zero, &[], 0);

        // The app has data, but a zero window blocks it — poll sends nothing.
        conn.write(b"hello");
        assert!(conn.poll_transmit(0).is_empty());

        // The first tick only arms the persist timer (one RTO = 200 ms default); no probe yet.
        assert!(conn.on_tick(100).is_empty());

        // After the persist timeout, a single byte is poked into the closed window at SND.NXT.
        let probes = conn.on_tick(350);
        assert_eq!(probes.len(), 1);
        assert_eq!(payload_of(&probes[0]), b"h");
        assert_eq!(parse(&probes[0][20..]).unwrap().seq, 1);
    }

    #[test]
    fn persist_probe_recovers_when_window_reopens() {
        let mut conn = established_conn();
        let zero = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 1,
            data_offset: 20, flags: ACK, window: 0,
        };
        conn.on_packet_at(&zero, &[], 0);
        conn.write(b"hello");

        // Arm and fire the probe (byte 'h' at seq 1).
        conn.on_tick(100);
        assert_eq!(conn.on_tick(350).len(), 1);

        // The peer's window reopens and its ACK acknowledges the probe byte (ack = 2).
        let reopen = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 2,
            data_offset: 20, flags: ACK, window: 1000,
        };
        conn.on_packet_at(&reopen, &[], 400);

        // The deadlock is broken: the rest of "hello" now flows.
        let segs = conn.poll_transmit(400);
        assert_eq!(segs.len(), 1);
        assert_eq!(payload_of(&segs[0]), b"ello");
    }

    #[test]
    fn window_updates_and_zero_windows_are_not_duplicate_acks() {
        let mut conn = established_conn();
        // Put 5 bytes in flight so the duplicate-ACK conditions could otherwise be met.
        conn.write(b"hello");
        assert_eq!(conn.poll_transmit(0).len(), 1);

        // Three ACKs for the same seq, each carrying a *changed* window — pure window updates, not
        // duplicate ACKs. Without the RFC 5681 §2 window condition the third would fast-retransmit;
        // with it, all three are inert (return None).
        for win in [500u16, 400, 300] {
            let upd = TcpHeader {
                src_port: 0x1234, dst_port: 80, seq: 101, ack: 1,
                data_offset: 20, flags: ACK, window: win,
            };
            assert!(conn.on_packet_at(&upd, &[], 0).is_none(), "window update must not be a dup ACK");
        }

        // Three zero-window ACKs (the receiver is full) are likewise not duplicate ACKs.
        let zero = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 1,
            data_offset: 20, flags: ACK, window: 0,
        };
        for _ in 0..3 {
            assert!(conn.on_packet_at(&zero, &[], 0).is_none(), "zero-window re-ack must not be a dup ACK");
        }
    }

    // ── Day 15: MSS option + outgoing segmentation ──

    #[test]
    fn parse_options_handles_mss_nop_eol_and_malformed() {
        // NOP, NOP, MSS=1460 (0x05b4), End-of-Options, then trailing garbage (ignored after EOL).
        let bytes = [OPT_NOP, OPT_NOP, OPT_MSS, 4, 0x05, 0xb4, OPT_END, 0xff];
        assert_eq!(parse_options(&bytes).mss, Some(1460));
        // No options at all.
        assert_eq!(parse_options(&[]).mss, None);
        // Truncated MSS (length says 4 but only 1 value byte present) → ignored, no panic.
        assert_eq!(parse_options(&[OPT_MSS, 4, 0x05]).mss, None);
        // A zero length is malformed → parsing stops without looping forever.
        assert_eq!(parse_options(&[OPT_MSS, 0, 1, 2]).mss, None);
    }

    #[test]
    fn synack_advertises_our_mss_and_negotiates_send_mss() {
        let th = parse(&syn_segment()).unwrap();
        // The peer's SYN advertised a 600-byte MSS.
        let opts = TcpOptions { mss: Some(600), ..Default::default() };
        let (conn, synack) = Connection::accept_with_iss_at(PEER, ME, &th, &opts, 0, 0).unwrap();

        // We advertise OUR receive MSS in the SYN-ACK…
        let h = parse(&synack[20..]).unwrap();
        let emitted = parse_options(&synack[20 + 20..20 + h.data_offset]);
        assert_eq!(emitted.mss, Some(OUR_MSS));
        // …and our *send* MSS becomes min(OUR_MSS, peer's 600) = 600.
        assert_eq!(conn.send_mss, 600);
    }

    #[test]
    fn missing_peer_mss_falls_back_to_default() {
        // syn_segment() carries no options → no peer MSS → we segment at the default (OUR_MSS).
        let th = parse(&syn_segment()).unwrap();
        let (conn, _s) = Connection::accept_with_iss(PEER, ME, &th, 0).unwrap();
        assert_eq!(conn.send_mss, DEFAULT_SEND_MSS);
    }

    #[test]
    fn outgoing_data_is_segmented_to_negotiated_mss() {
        // The peer advertised a small 500-byte MSS, so our segments are capped at 500 — not the
        // 1460 congestion MSS — even though cwnd (1·1460) would allow a bigger one.
        let th = parse(&syn_segment()).unwrap();
        let opts = TcpOptions { mss: Some(500), ..Default::default() };
        let (mut conn, _s) = Connection::accept_with_iss_at(PEER, ME, &th, &opts, 0, 0).unwrap();
        let hs_ack = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 1,
            data_offset: 20, flags: ACK, window: 0xffff,
        };
        conn.on_packet_at(&hs_ack, &[], 0);
        assert_eq!(conn.state(), State::Established);

        conn.write(&vec![b'x'; 1200]);
        let segs = conn.poll_transmit(0);
        // cwnd=1460 admits 1000 bytes of in-flight here → two 500-byte segments; the 200-byte tail
        // is held by Nagle (sub-MSS with data in flight), confirming the MSS bound.
        assert_eq!(segs.len(), 2);
        assert_eq!(payload_of(&segs[0]).len(), 500);
        assert_eq!(payload_of(&segs[1]).len(), 500);
    }

    #[test]
    fn active_open_learns_peer_mss_from_synack() {
        let (mut conn, _syn) = Connection::connect_with_iss((ME, 50000), (PEER, 80), 0, 0);
        assert_eq!(conn.send_mss, DEFAULT_SEND_MSS); // unknown until the SYN-ACK

        // The peer's SYN-ACK advertises a 700-byte MSS; on_segment learns it.
        let synack = TcpHeader {
            src_port: 80, dst_port: 50000, seq: 900, ack: 1,
            data_offset: 24, flags: SYN | ACK, window: 0xffff,
        };
        let opts = TcpOptions { mss: Some(700), ..Default::default() };
        conn.on_segment(&synack, &[], &opts, 0);
        assert_eq!(conn.state(), State::Established);
        assert_eq!(conn.send_mss, 700);
    }

    // ── Day 16: TCP timestamps + RTTM + PAWS ──

    #[test]
    fn parse_options_reads_timestamps() {
        // NOP, NOP, TS(kind 8, len 10), TSval=0x01020304, TSecr=0x0a0b0c0d.
        let bytes = [OPT_NOP, OPT_NOP, OPT_TS, 10, 1, 2, 3, 4, 0x0a, 0x0b, 0x0c, 0x0d];
        assert_eq!(parse_options(&bytes).timestamps, Some((0x0102_0304, 0x0a0b_0c0d)));
        // Wrong length (6, not 10) → not a valid timestamps option.
        assert_eq!(parse_options(&[OPT_TS, 6, 1, 2, 3, 4]).timestamps, None);
    }

    #[test]
    fn timestamps_negotiated_and_synack_echoes_peer() {
        let th = parse(&syn_segment()).unwrap();
        let opts = TcpOptions { mss: Some(1460), timestamps: Some((5000, 0)), ..Default::default() };
        let (conn, synack) = Connection::accept_with_iss_at(PEER, ME, &th, &opts, 0, 100).unwrap();
        assert!(conn.ts_enabled);

        // The SYN-ACK carries both MSS and a Timestamps option: TSval = our clock (100), TSecr =
        // the peer's SYN TSval (5000).
        let h = parse(&synack[20..]).unwrap();
        let emitted = parse_options(&synack[20 + 20..20 + h.data_offset]);
        assert_eq!(emitted.mss, Some(OUR_MSS));
        assert_eq!(emitted.timestamps, Some((100, 5000)));
    }

    #[test]
    fn timestamps_disabled_when_peer_does_not_offer() {
        let th = parse(&syn_segment()).unwrap();
        let opts = TcpOptions { mss: Some(1460), timestamps: None, ..Default::default() };
        let (conn, synack) = Connection::accept_with_iss_at(PEER, ME, &th, &opts, 0, 0).unwrap();
        assert!(!conn.ts_enabled);
        let h = parse(&synack[20..]).unwrap();
        assert_eq!(parse_options(&synack[20 + 20..20 + h.data_offset]).timestamps, None);
    }

    /// Establish a timestamps-enabled connection (peer SYN TSval = `peer_ts`), handshake at t=0.
    fn established_ts_conn(peer_ts: u32) -> Connection {
        let th = parse(&syn_segment()).unwrap();
        let opts = TcpOptions { mss: Some(1460), timestamps: Some((peer_ts, 0)), ..Default::default() };
        let (mut conn, _s) = Connection::accept_with_iss_at(PEER, ME, &th, &opts, 0, 0).unwrap();
        let hs_ack = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 1,
            data_offset: 20, flags: ACK, window: 0xffff,
        };
        let ack_opts = TcpOptions { mss: None, timestamps: Some((peer_ts, 0)), ..Default::default() };
        conn.on_segment(&hs_ack, &[], &ack_opts, 0);
        assert_eq!(conn.state(), State::Established);
        conn
    }

    #[test]
    fn rttm_samples_rtt_from_echoed_timestamp() {
        let mut conn = established_ts_conn(5000);

        // We send "hi" at t=0 → its TSval is 0.
        conn.write(b"hi");
        conn.poll_transmit(0);

        // The peer ACKs at t=120, echoing TSecr = 0 (our send time).
        let ack = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 3,
            data_offset: 20, flags: ACK, window: 0xffff,
        };
        let ack_opts = TcpOptions { mss: None, timestamps: Some((5002, 0)), ..Default::default() };
        conn.on_segment(&ack, &[], &ack_opts, 120);

        // Sample R = 120 − 0 = 120 → first sample → SRTT 120, RTTVAR 60 → RTO = 120 + 4·60 = 360.
        assert_eq!(conn.rto(), 360);
    }

    #[test]
    fn paws_rejects_an_old_timestamp_segment() {
        let mut conn = established_ts_conn(5000);
        // TS.Recent is 5000 after the handshake.

        // An old duplicate: in-window seq, but a stale TSval (4000 < 5000). PAWS drops it — the data
        // is NOT delivered and we re-ACK current state.
        let old = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 1,
            data_offset: 20, flags: PSH | ACK, window: 0xffff,
        };
        let old_opts = TcpOptions { mss: None, timestamps: Some((4000, 0)), ..Default::default() };
        let resp = conn.on_segment(&old, b"XX", &old_opts, 10).expect("a current ACK");
        assert_eq!(parse(&resp[20..]).unwrap().ack, 101); // RCV.NXT unmoved
        assert_eq!(conn.take_received(), b""); // nothing delivered

        // The same data with a fresh timestamp IS accepted.
        let fresh = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 1,
            data_offset: 20, flags: PSH | ACK, window: 0xffff,
        };
        let fresh_opts = TcpOptions { mss: None, timestamps: Some((5002, 0)), ..Default::default() };
        conn.on_segment(&fresh, b"hi", &fresh_opts, 20);
        assert_eq!(conn.take_received(), b"hi");
    }

    #[test]
    fn timestamped_connection_emits_timestamps_on_data() {
        let mut conn = established_ts_conn(5000);
        conn.write(b"hi");
        let segs = conn.poll_transmit(7);
        assert_eq!(segs.len(), 1);
        // The data segment carries a Timestamps option: TSval = clock (7), TSecr = TS.Recent (5000).
        let h = parse(&segs[0][20..]).unwrap();
        let emitted = parse_options(&segs[0][20 + 20..20 + h.data_offset]);
        assert_eq!(emitted.timestamps, Some((7, 5000)));
    }

    // ── Day 17: window scaling ──

    #[test]
    fn parse_options_reads_and_clamps_window_scale() {
        assert_eq!(parse_options(&[OPT_WS, 3, 7]).window_scale, Some(7));
        // A shift above 14 is clamped to 14 (RFC 7323 §2.3).
        assert_eq!(parse_options(&[OPT_WS, 3, 20]).window_scale, Some(MAX_WSCALE));
        // Wrong length → not a valid window-scale option.
        assert_eq!(parse_options(&[OPT_WS, 4, 7, 0]).window_scale, None);
    }

    #[test]
    fn synack_offers_window_scale_when_peer_does() {
        let th = parse(&syn_segment()).unwrap();
        let opts = TcpOptions { window_scale: Some(8), ..Default::default() };
        let (conn, synack) = Connection::accept_with_iss_at(PEER, ME, &th, &opts, 0, 0).unwrap();
        assert_eq!(conn.snd_wscale, 8);
        let h = parse(&synack[20..]).unwrap();
        let emitted = parse_options(&synack[20 + 20..20 + h.data_offset]);
        assert_eq!(emitted.window_scale, Some(OUR_RCV_WSCALE));
        assert_eq!(emitted.mss, Some(OUR_MSS));
    }

    #[test]
    fn synack_omits_window_scale_when_peer_silent() {
        let th = parse(&syn_segment()).unwrap();
        let opts = TcpOptions { window_scale: None, ..Default::default() };
        let (conn, synack) = Connection::accept_with_iss_at(PEER, ME, &th, &opts, 0, 0).unwrap();
        assert_eq!(conn.snd_wscale, 0);
        let h = parse(&synack[20..]).unwrap();
        assert_eq!(parse_options(&synack[20 + 20..20 + h.data_offset]).window_scale, None);
    }

    #[test]
    fn peer_window_is_left_shifted_by_negotiated_scale() {
        let th = parse(&syn_segment()).unwrap();
        // The peer offers window scale 7 (×128).
        let opts = TcpOptions { window_scale: Some(7), ..Default::default() };
        let (mut conn, _s) = Connection::accept_with_iss_at(PEER, ME, &th, &opts, 0, 0).unwrap();
        assert_eq!(conn.snd_wscale, 7);

        // A later ACK whose window FIELD is 1000 really advertises 1000 << 7 = 128000 bytes.
        let ack = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 1,
            data_offset: 20, flags: ACK, window: 1000,
        };
        conn.on_packet_at(&ack, &[], 0);
        assert_eq!(conn.send.wnd, 1000 << 7);
    }

    #[test]
    fn active_open_adopts_peer_window_scale() {
        let (mut conn, _syn) = Connection::connect_with_iss((ME, 50000), (PEER, 80), 0, 0);
        assert_eq!(conn.snd_wscale, 0); // unknown until the SYN-ACK

        let synack = TcpHeader {
            src_port: 80, dst_port: 50000, seq: 900, ack: 1,
            data_offset: 24, flags: SYN | ACK, window: 0xffff,
        };
        let opts = TcpOptions { window_scale: Some(5), ..Default::default() };
        conn.on_segment(&synack, &[], &opts, 0);
        assert_eq!(conn.state(), State::Established);
        assert_eq!(conn.snd_wscale, 5);
    }

    // ── Day 18: Selective Acknowledgment (SACK, RFC 2018) ──

    /// Establish a SACK-negotiated connection (peer SYN offered SACK-Permitted), handshake at t=0.
    /// RCV.NXT = 101 (peer ISN 100, SYN consumed it); SND.UNA = SND.NXT = 1.
    fn established_sack_conn() -> Connection {
        let th = parse(&syn_segment()).unwrap();
        let syn_opts = TcpOptions { sack_permitted: true, ..Default::default() };
        let (mut conn, _s) = Connection::accept_with_iss_at(PEER, ME, &th, &syn_opts, 0, 0).unwrap();
        let hs_ack = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 1,
            data_offset: 20, flags: ACK, window: 0xffff,
        };
        conn.on_packet_at(&hs_ack, &[], 0);
        assert_eq!(conn.state(), State::Established);
        assert!(conn.sack_ok);
        conn
    }

    #[test]
    fn parse_options_reads_sack_permitted() {
        // SACK-Permitted is kind=4, len=2, no payload.
        assert!(parse_options(&[OPT_SACK_PERM, 2]).sack_permitted);
        assert!(!parse_options(&[]).sack_permitted);
        // Bundled after an MSS option with NOP padding — both parse.
        let o = parse_options(&[OPT_MSS, 4, 0x05, 0xb4, OPT_NOP, OPT_NOP, OPT_SACK_PERM, 2]);
        assert_eq!(o.mss, Some(1460));
        assert!(o.sack_permitted);
    }

    #[test]
    fn parse_options_reads_sack_blocks() {
        // Two blocks [1000,2000) and [3000,4000): kind=5, len = 2 + 2×8 = 18.
        let mut bytes = vec![OPT_SACK, 18];
        for edge in [1000u32, 2000, 3000, 4000] {
            bytes.extend_from_slice(&edge.to_be_bytes());
        }
        let o = parse_options(&bytes);
        assert_eq!(o.sack_block_count, 2);
        assert_eq!(o.sack_blocks[0], (1000, 2000));
        assert_eq!(o.sack_blocks[1], (3000, 4000));
        // A length that isn't a positive multiple of 8 is malformed → ignored.
        assert_eq!(parse_options(&[OPT_SACK, 6, 0, 0, 0, 1]).sack_block_count, 0);
    }

    #[test]
    fn syn_offers_sack_permitted() {
        let (_conn, syn) = Connection::connect_with_iss((ME, 50000), (PEER, 80), 0, 0);
        let h = parse(&syn[20..]).unwrap();
        let o = parse_options(&syn[20 + 20..20 + h.data_offset]);
        assert!(o.sack_permitted, "our SYN must offer SACK");
        assert_eq!(o.mss, Some(OUR_MSS)); // alongside MSS / window scale / timestamps
    }

    #[test]
    fn synack_offers_sack_when_peer_permits() {
        let th = parse(&syn_segment()).unwrap();
        let opts = TcpOptions { sack_permitted: true, ..Default::default() };
        let (conn, synack) = Connection::accept_with_iss_at(PEER, ME, &th, &opts, 0, 0).unwrap();
        assert!(conn.sack_ok);
        let h = parse(&synack[20..]).unwrap();
        assert!(parse_options(&synack[20 + 20..20 + h.data_offset]).sack_permitted);
    }

    #[test]
    fn synack_omits_sack_when_peer_silent() {
        let th = parse(&syn_segment()).unwrap();
        let opts = TcpOptions { sack_permitted: false, ..Default::default() };
        let (conn, synack) = Connection::accept_with_iss_at(PEER, ME, &th, &opts, 0, 0).unwrap();
        assert!(!conn.sack_ok);
        let h = parse(&synack[20..]).unwrap();
        assert!(!parse_options(&synack[20 + 20..20 + h.data_offset]).sack_permitted);
    }

    #[test]
    fn active_open_enables_sack_from_synack() {
        let (mut conn, _syn) = Connection::connect_with_iss((ME, 50000), (PEER, 80), 0, 0);
        assert!(!conn.sack_ok); // not until the SYN-ACK confirms it
        let synack = TcpHeader {
            src_port: 80, dst_port: 50000, seq: 900, ack: 1,
            data_offset: 20, flags: SYN | ACK, window: 0xffff,
        };
        let opts = TcpOptions { sack_permitted: true, ..Default::default() };
        conn.on_segment(&synack, &[], &opts, 0);
        assert_eq!(conn.state(), State::Established);
        assert!(conn.sack_ok);
    }

    #[test]
    fn out_of_order_data_acks_with_a_sack_block() {
        let mut conn = established_sack_conn(); // RCV.NXT = 101
        // Data at seq 104 arrives before the [101,104) gap is filled: a hole remains, so the dup ACK
        // must SACK the buffered range [104,106) (RFC 2018 §3) while its cumulative ack stays at 101.
        let ooo = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 104, ack: 1,
            data_offset: 20, flags: PSH | ACK, window: 0xffff,
        };
        let ack = conn.on_packet_at(&ooo, b"DE", 0).expect("a dup ACK carrying SACK");
        let h = parse(&ack[20..]).unwrap();
        assert_eq!(h.ack, 101, "cumulative ack unmoved — the gap remains");
        let o = parse_options(&ack[20 + 20..20 + h.data_offset]);
        assert_eq!(o.sack_block_count, 1);
        assert_eq!(o.sack_blocks[0], (104, 106));
    }

    #[test]
    fn no_sack_block_when_data_is_in_order() {
        let mut conn = established_sack_conn();
        let inorder = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 1,
            data_offset: 20, flags: PSH | ACK, window: 0xffff,
        };
        let ack = conn.on_packet_at(&inorder, b"hi", 0).expect("an ACK");
        let h = parse(&ack[20..]).unwrap();
        assert_eq!(h.ack, 103); // delivered in order → RCV.NXT advanced, no hole
        assert_eq!(parse_options(&ack[20 + 20..20 + h.data_offset]).sack_block_count, 0);
    }

    #[test]
    fn sack_marks_segment_so_retransmit_skips_it() {
        // The selective-retransmit core (RFC 2018 §4), exercised directly on the queue.
        let mut q = RetxQueue::default();
        q.record(0, 100, vec![0xAA], 0); //   segment A [0,100)
        q.record(100, 200, vec![0xBB], 0); // segment B [100,200)
        q.record(200, 300, vec![0xCC], 0); // segment C [200,300)
        // The peer SACKs the middle range — B is now selectively acknowledged.
        q.mark_sacked(&[(100, 200)]);
        // Fast retransmit resends the first NON-sacked segment (A), not the SACKed B.
        assert_eq!(q.fast_retransmit(10), Some(vec![0xAA]));
        // An RTO sweep resends only the holes A and C, never B.
        assert_eq!(q.due(10_000, 200), vec![vec![0xAAu8], vec![0xCCu8]]);
    }

    #[test]
    fn partial_sack_block_does_not_mark_a_segment() {
        // A block must FULLY cover a segment to mark it: half-coverage leaves it retransmittable.
        let mut q = RetxQueue::default();
        q.record(0, 100, vec![0xAA], 0);
        q.mark_sacked(&[(0, 50)]); // covers only the first half of [0,100)
        assert_eq!(q.fast_retransmit(10), Some(vec![0xAA]));
    }
}
