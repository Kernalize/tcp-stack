//! TCP layer (RFC 9293) — the heart of the project.
//!
//! Step 3 implements the **passive-open three-way handshake**: a client's SYN creates a
//! connection in SYN_RCVD and gets a SYN-ACK; the client's final ACK moves it to
//! ESTABLISHED. Unlike ICMP, TCP has *memory* — a Transmission Control Block (TCB) per
//! connection — so we keep a table of connections keyed by the 4-tuple. Theory:
//! `docs/doc3-book.md`.
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
/// test SYNs still segment at full size. (Documented deviation; see docs/doc15-book.md.)
const DEFAULT_SEND_MSS: u16 = OUR_MSS;

/// Doc 21 — RFC 6675 duplicate/SACK threshold: the receiver must SACK three segments above a hole
/// before we presume it lost (the SACK analogue of three duplicate ACKs). Matches the congestion
/// module's dup-ACK threshold; named here because the `RetxQueue` `pipe`/loss logic consult it.
const DUP_THRESH: u32 = 3;

/// Doc 23 — the per-window challenge-ACK budget ceiling (RFC 5961 ACK throttling). The actual budget
/// is randomized in `1..=CHALLENGE_ACK_MAX` each window so the count can't be inferred off-path
/// (the lesson of CVE-2016-5696, where a shared, predictable counter became an oracle).
const CHALLENGE_ACK_MAX: u32 = 5;

/// Doc 26 — TCP keepalive (RFC 9293 §3.8.4). After a connection sits idle `KEEPALIVE_IDLE_MS` we
/// probe it; a real stack defaults to 2 hours, but we shorten it for a teaching demo. Probes are
/// spaced `KEEPALIVE_INTVL_MS` apart; after `KEEPALIVE_PROBES` go unanswered the peer is declared dead.
const KEEPALIVE_IDLE_MS: u64 = 60_000;
const KEEPALIVE_INTVL_MS: u64 = 5_000;
const KEEPALIVE_PROBES: u32 = 3;

/// Doc 27 — SYN-cookie scheme (Bernstein-style, teaching-grade). Under a SYN flood the server encodes
/// the handshake into the SYN-ACK's ISN — a slow counter (for expiry), a 2-bit MSS index, and a keyed
/// 24-bit hash of the 4-tuple + the client's ISN — and allocates NO TCB until a valid cookie returns
/// in the final ACK. Layout of the 32-bit cookie: `[counter:6][mss_idx:2][mac:24]`.
const COOKIE_TICK_MS: u64 = 64_000; // the cookie counter advances ~once a minute (bounds cookie life)
const COOKIE_MSS_TABLE: [u16; 4] = [536, 1220, 1460, 8960]; // 2-bit MSS encoding (common path MTUs)

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
    /// Passive close (Doc 19): the peer sent its FIN; we ACKed it and entered CLOSE_WAIT. Our send
    /// side stays open — the local app may keep sending until it calls `close`, which sends our FIN
    /// and moves to LAST_ACK. The passive closer never enters TIME_WAIT (RFC 9293 §3.3.2).
    CloseWait,
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
    // The peer's advertised window, already left-shifted by its window scale (Doc 17). It is `u32`,
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
    /// Effective send MSS (Doc 15): the largest payload we put in one segment, = min(OUR_MSS, the
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
    /// The peer's window-scale shift (Doc 17, RFC 7323 §2): we left-shift its advertised window field
    /// by this to recover the true `SND.WND`. 0 when window scaling wasn't negotiated, so the shift
    /// is a no-op and the field is taken literally.
    snd_wscale: u8,
    /// SACK negotiated (Doc 18, RFC 2018 §2): true only when BOTH SYNs carried SACK-Permitted. When
    /// set, our ACKs describe buffered out-of-order data in SACK blocks, and incoming SACK blocks let
    /// loss recovery retransmit only the genuine holes instead of go-back-N.
    sack_ok: bool,
    /// Doc 19 — the peer has sent its FIN (we are at/after CLOSE_WAIT): the application is at EOF.
    /// Set when we honor an in-order FIN; read by `peer_closed()` so a socket veneer can return
    /// `Ok(0)`. Distinct from our *own* close, which `close()` drives.
    peer_fin: bool,
    /// Doc 19 — the sequence number the peer's FIN sits at, recorded when the FIN arrives out of
    /// order (its data gap isn't filled yet). Honored — consumed, EOF, → CLOSE_WAIT — once RCV.NXT
    /// reaches it. `None` when no FIN is outstanding. (A real stack tracks this inside the
    /// reassembler; one pending FIN is all a single peer can have in flight.)
    pending_fin: Option<u32>,
    /// Doc 20 — NewReno (RFC 6582) recovery point: the SND.NXT captured when a fast-recovery
    /// episode begins. An ACK that reaches `recover` is a *full* ACK (recovery complete); one that
    /// falls short is a *partial* ACK (another hole to retransmit). Meaningless outside recovery.
    recover: u32,
    /// Doc 23 — RFC 5961 §5: the largest send window we've seen, defining the blind-data
    /// ACK-acceptability range `SND.UNA − MAX.SND.WND ≤ SEG.ACK ≤ SND.NXT`. An ACK outside it (e.g.
    /// one acking data we never sent) earns a challenge ACK instead of being trusted.
    max_snd_wnd: u32,
    /// Doc 23 — challenge-ACK throttle (RFC 5961, hardened against CVE-2016-5696): a per-connection,
    /// randomized budget refilled each ~second, so challenge ACKs can't be farmed as an off-path
    /// oracle. `challenge_window_ms` is the start of the current budget window.
    challenge_budget: u32,
    challenge_window_ms: u64,
    /// Doc 23 — the time the last segment arrived; drives the CLOSE_WAIT / FIN_WAIT_2 reaper, so a
    /// peer that vanishes can't pin a half-closed connection (and its memory) open forever.
    last_active_ms: u64,
    /// Doc 24 — Tail Loss Probe (RFC 8985 §7): absolute time (ms) the probe is due, or 0 disarmed.
    /// Armed when the tail of a transfer is outstanding with nothing new to send; fires one probe.
    tlp_deadline_ms: u64,
    /// Doc 24 — whether a TLP probe is currently outstanding (one per tail; a fresh ACK re-arms it).
    tlp_sent: bool,
    /// Doc 26 — TCP keepalive opt-in (off by default, like `SO_KEEPALIVE`); when set, an idle
    /// ESTABLISHED connection is probed and a dead peer eventually reaped.
    keepalive_enabled: bool,
    /// Doc 26 — keepalive probes sent since the last activity; reset by any arriving segment.
    keepalive_probes_sent: u32,
    /// Doc 28 — BBR **pacing** clock: the earliest time (ms) the next new-data segment may leave, so
    /// data is spread at the modelled `pacing_rate` instead of bursting. `0` = unconstrained. Only the
    /// model-based controller paces (CUBIC reports a `0` pacing rate, leaving this a no-op).
    next_send_ms: u64,
}

impl Connection {
    pub fn state(&self) -> State {
        self.state
    }

    /// Doc 19: has the peer closed its half (sent FIN)? Once true the application is at EOF — a
    /// `read()` veneer returns `Ok(0)`. We may still *send* until we `close()` our own half.
    /// Part of the socket-style API for a future `TcpStream` (doc11-book §11); `main` decides via
    /// `state()`, so this is exercised by tests — hence `allow(dead_code)`.
    #[allow(dead_code)]
    pub fn peer_closed(&self) -> bool {
        self.peer_fin
    }

    /// Doc 19: true when the application's send buffer is fully drained onto the wire. `main` uses
    /// it to decide a CLOSE_WAIT connection has nothing left to send and may close its own half.
    pub fn send_buffer_empty(&self) -> bool {
        self.send_buf.is_empty()
    }

    /// Passive open: a SYN arrived for a connection we don't have yet. Create the TCB in
    /// SYN_RCVD and return it together with the SYN-ACK packet bytes to send. Returns `None` if
    /// the incoming segment isn't a SYN (we only open on a SYN). `now_ms` timestamps the SYN-ACK
    /// in the retransmission queue (Doc 12) so a lost SYN-ACK is resent on RTO.
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
            // Doc 15: the most we may send the peer per segment = min(our MSS, the MSS it advertised
            // in its SYN). If it advertised none, fall back to our own (see DEFAULT_SEND_MSS).
            send_mss: opts.mss.map_or(DEFAULT_SEND_MSS, |m| m.min(OUR_MSS)),
            // Doc 16: enable timestamps only if the peer's SYN offered them (RFC 7323 §3); seed
            // TS.Recent with its TSval so our SYN-ACK can echo it.
            ts_enabled: opts.timestamps.is_some(),
            ts_recent: opts.timestamps.map_or(0, |(tsval, _)| tsval),
            ts_val: now_ms as u32,
            // Doc 17: window scaling negotiates per-direction. We left-shift the peer's window field
            // by the shift it advertised; 0 (no scaling) if its SYN carried no window-scale option.
            snd_wscale: opts.window_scale.unwrap_or(0),
            // Doc 18: enable SACK only if the peer's SYN offered it; we echo SACK-Permitted in the
            // SYN-ACK below only in that case (RFC 2018 §2).
            sack_ok: opts.sack_permitted,
            peer_fin: false,   // Doc 19: no peer FIN seen yet
            pending_fin: None, // Doc 19: no out-of-order FIN deferred
            recover: iss,      // Doc 20: NewReno recovery point (only meaningful during recovery)
            max_snd_wnd: wnd as u32,                              // Doc 23: RFC 5961 §5 ACK window
            challenge_budget: 1 + rand::random::<u32>() % CHALLENGE_ACK_MAX, // Doc 23: randomized
            challenge_window_ms: now_ms,
            last_active_ms: now_ms, // Doc 23: reaper baseline
            tlp_deadline_ms: 0,     // Doc 24: Tail Loss Probe disarmed
            tlp_sent: false,
            keepalive_enabled: false,  // Doc 26: SO_KEEPALIVE off by default
            keepalive_probes_sent: 0,
            next_send_ms: 0,
        };

        // SYN-ACK: our seq = ISS, ack = what we next expect from them (their seq + 1). It carries
        // OUR MSS option (Doc 15), and — only if the peer offered each — a Window Scale option
        // (Doc 17) and the Timestamps option echoing the peer's SYN TSval (Doc 16, RFC 7323).
        let mut synack_opts = mss_option(OUR_MSS).to_vec();
        if opts.window_scale.is_some() {
            synack_opts.extend_from_slice(&ws_option(OUR_RCV_WSCALE));
        }
        if conn.ts_enabled {
            synack_opts.extend_from_slice(&ts_option(conn.ts_val, conn.ts_recent));
        }
        // Doc 18: echo SACK-Permitted only if the peer's SYN offered it (RFC 2018 §2).
        if conn.sack_ok {
            synack_opts.extend_from_slice(&sack_perm_option());
        }
        let synack = conn.segment_opts(conn.send.iss, conn.recv.nxt, SYN | ACK, &synack_opts, &[]);
        // Doc 12: the SYN-ACK consumes sequence number ISS (end = ISS + 1 = SND.NXT). Queue it for
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
            // Doc 15: until the SYN-ACK reveals the peer's MSS, segment at our own (updated below).
            send_mss: DEFAULT_SEND_MSS,
            // Doc 16: we OFFER timestamps in our SYN; they're enabled only if the SYN-ACK also
            // carries them (decided in on_segment's SYN_SENT branch).
            ts_enabled: false,
            ts_recent: 0,
            ts_val: now_ms as u32,
            // Doc 17: learned from the SYN-ACK's window-scale option (0 until then = no scaling).
            snd_wscale: 0,
            // Doc 18: we OFFER SACK-Permitted in our SYN (below); it's enabled only if the SYN-ACK
            // echoes it (decided in on_segment's SYN_SENT branch). RFC 2018 §2.
            sack_ok: false,
            peer_fin: false,   // Doc 19: no peer FIN seen yet
            pending_fin: None, // Doc 19: no out-of-order FIN deferred
            recover: iss,      // Doc 20: NewReno recovery point (only meaningful during recovery)
            max_snd_wnd: wnd as u32,                              // Doc 23: RFC 5961 §5 ACK window
            challenge_budget: 1 + rand::random::<u32>() % CHALLENGE_ACK_MAX, // Doc 23: randomized
            challenge_window_ms: now_ms,
            last_active_ms: now_ms, // Doc 23: reaper baseline
            tlp_deadline_ms: 0,     // Doc 24: Tail Loss Probe disarmed
            tlp_sent: false,
            keepalive_enabled: false,  // Doc 26: SO_KEEPALIVE off by default
            keepalive_probes_sent: 0,
            next_send_ms: 0,
        };
        // SYN: seq = ISS, no ACK (we don't know the peer's seq yet). Carries OUR MSS option, a
        // Window Scale option (Doc 17), and a Timestamps option offering RTTM/PAWS (TSecr = 0 — we
        // have nothing to echo yet).
        let mut syn_opts = mss_option(OUR_MSS).to_vec();
        syn_opts.extend_from_slice(&ws_option(OUR_RCV_WSCALE));
        syn_opts.extend_from_slice(&ts_option(conn.ts_val, 0));
        syn_opts.extend_from_slice(&sack_perm_option()); // Doc 18: offer SACK (RFC 2018 §2)
        let syn = conn.segment_opts(conn.send.iss, 0, SYN, &syn_opts, &[]);
        // Doc 12: the SYN consumes sequence number ISS (end = ISS + 1 = SND.NXT). Queue it so a
        // lost SYN is resent on RTO; the peer's SYN-ACK clears it (RFC 9293 §3.8.1).
        conn.retx.record(conn.send.iss, conn.send.nxt, syn.clone(), now_ms);
        (conn, syn)
    }

    /// Doc 27 — reconstruct an ESTABLISHED connection from a validated SYN cookie. Under a SYN flood
    /// the server allocates no TCB on the SYN; it returns a cookie as the SYN-ACK's ISS. When the
    /// client's final ACK echoes `cookie + 1`, `check_syn_cookie` validates it and we build the TCB
    /// directly in ESTABLISHED — no half-open state ever existed. `peer_isn` is the client's ISN (the
    /// final ACK's seq − 1); `cookie` was our ISS; `send_mss` was decoded from the cookie. SYN cookies
    /// carry only the MSS, so timestamps / window scale / SACK are NOT negotiated on this connection.
    pub fn from_syn_cookie(
        local: (Ipv4Addr, u16),
        remote: (Ipv4Addr, u16),
        peer_isn: u32,
        cookie: u32,
        send_mss: u16,
        now_ms: u64,
    ) -> Connection {
        let wnd: u16 = 1024;
        let iss = cookie; // our SYN-ACK used the cookie as ISS, so it consumed `cookie`; SND.NXT = cookie+1
        Connection {
            state: State::Established,
            send: SendSequence { iss, una: iss.wrapping_add(1), nxt: iss.wrapping_add(1), wnd: wnd as u32 },
            recv: RecvSequence { irs: peer_isn, nxt: peer_isn.wrapping_add(1), wnd },
            local,
            remote,
            retx: RetxQueue::default(),
            time_wait_ms: 0,
            rtt: RttEstimator::default(),
            reasm: Reassembler::new(peer_isn.wrapping_add(1)),
            cong: CongestionControl::default(),
            send_buf: VecDeque::new(),
            recv_buf: Vec::new(),
            nagle: true,
            persist_ms: 0,
            send_mss: send_mss.min(OUR_MSS),
            ts_enabled: false, // SYN cookies drop option negotiation — only the MSS survives
            ts_recent: 0,
            ts_val: now_ms as u32,
            snd_wscale: 0,
            sack_ok: false,
            peer_fin: false,
            pending_fin: None,
            recover: iss,
            max_snd_wnd: wnd as u32,
            challenge_budget: 1 + rand::random::<u32>() % CHALLENGE_ACK_MAX,
            challenge_window_ms: now_ms,
            last_active_ms: now_ms,
            tlp_deadline_ms: 0,
            tlp_sent: false,
            keepalive_enabled: false,
            keepalive_probes_sent: 0,
            next_send_ms: 0,
        }
    }

    /// Close our send side: emit our FIN. From ESTABLISHED this is an *active close* → FIN_WAIT_1;
    /// from CLOSE_WAIT (Doc 19) it finishes a *passive* half-close → LAST_ACK. Returns `None` from
    /// any other state (no FIN to send). `now_ms` timestamps the FIN for retransmission (Doc 12).
    /// The HTTP path in `main` actively closes; the echo path closes from CLOSE_WAIT once the peer's
    /// FIN has arrived and our send buffer is drained.
    pub fn close(&mut self, now_ms: u64) -> Option<Vec<u8>> {
        // The FIN is legal only while our send side is still open. ESTABLISHED → we initiate the
        // close (FIN_WAIT_1); CLOSE_WAIT → we are the passive closer finishing up (LAST_ACK).
        let next = match self.state {
            State::Established => State::FinWait1,
            State::CloseWait => State::LastAck,
            _ => return None,
        };
        self.ts_val = now_ms as u32; // Doc 16: stamp the FIN with the current clock
        let out = self.segment(self.send.nxt, self.recv.nxt, FIN | ACK, &[]);
        self.send.nxt = self.send.nxt.wrapping_add(1); // our FIN consumes a sequence number
        // Doc 12: queue the FIN (end = SND.NXT) so a lost FIN is resent until the peer ACKs it,
        // instead of leaving the teardown half-finished (RFC 9293 §3.8.1).
        self.retx.record(self.send.nxt.wrapping_sub(1), self.send.nxt, out.clone(), now_ms);
        self.state = next;
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

    /// Doc 19 — a connection is "synchronized" once both ISNs are fixed: ESTABLISHED and every
    /// close state (RFC 9293). RFC 5961's RST/SYN defenses apply only here; SYN_SENT and SYN_RCVD
    /// are still handshaking and handle SYN / SYN-ACK on their own.
    fn is_synchronized(&self) -> bool {
        matches!(
            self.state,
            State::Established
                | State::FinWait1
                | State::FinWait2
                | State::CloseWait
                | State::Closing
                | State::LastAck
                | State::TimeWait
        )
    }

    /// Doc 19 — is `seq` inside our receive window `[RCV.NXT, RCV.NXT + RCV.WND)` on the wrapping
    /// 32-bit circle (RFC 9293 §3.4 acceptability)? Used by the RFC 5961 RST check.
    fn in_window(&self, seq: u32) -> bool {
        let end = self.recv.nxt.wrapping_add(self.recv.wnd as u32);
        !seq::before(seq, self.recv.nxt) && seq::before(seq, end)
    }

    /// Doc 19 — a *challenge ACK* (RFC 5961): a bare ACK of our current state, `SEQ = SND.NXT`,
    /// `ACK = RCV.NXT`. Sent instead of trusting a suspicious in-window RST, instead of resetting on
    /// an in-window SYN, or instead of acting on an out-of-window ACK; a genuine peer answers it with
    /// a correctly-sequenced segment.
    fn challenge_ack(&self) -> Vec<u8> {
        self.segment(self.send.nxt, self.recv.nxt, ACK, &[])
    }

    /// Doc 23 — a *throttled* challenge ACK (RFC 5961 ACK throttling, hardened per CVE-2016-5696).
    /// Returns a challenge ACK only while this connection's randomized per-window budget lasts, then
    /// suppresses (returns `None`) until the next ~second refills it. A *shared, deterministic*
    /// counter (early Linux) let an off-path attacker probe whether a target connection existed by
    /// exhausting the global budget and watching for the missing challenge; a per-connection,
    /// randomized budget removes that signal.
    fn maybe_challenge(&mut self, now_ms: u64) -> Option<Vec<u8>> {
        const WINDOW_MS: u64 = 1000;
        if now_ms.wrapping_sub(self.challenge_window_ms) >= WINDOW_MS {
            self.challenge_window_ms = now_ms;
            self.challenge_budget = 1 + rand::random::<u32>() % CHALLENGE_ACK_MAX;
        }
        if self.challenge_budget == 0 {
            return None; // throttled — drop silently this window
        }
        self.challenge_budget -= 1;
        Some(self.challenge_ack())
    }

    /// Doc 23 — RFC 5961 §5 ACK acceptability: an ACK is acceptable iff
    /// `SND.UNA − MAX.SND.WND ≤ SEG.ACK ≤ SND.NXT` on the wrapping circle. The tight upper bound
    /// rejects an ACK for data we never sent (a blind injection probe); the lower bound tolerates
    /// genuinely old duplicate ACKs. An unacceptable ACK earns a challenge ACK, not blind action.
    fn ack_acceptable(&self, ack: u32) -> bool {
        let low = self.send.una.wrapping_sub(self.max_snd_wnd);
        !seq::before(ack, low) && !seq::after(ack, self.send.nxt)
    }

    /// Doc 19 — handle an incoming RST. SYN_SENT: a RST is acceptable only if it acknowledges our
    /// SYN (RFC 9293 §3.10.7.3) — the peer refused the connection. TIME_WAIT: ignore it (RFC 1337,
    /// "TIME-WAIT assassination" — a late RST must not free the 4-tuple early). Otherwise follow
    /// RFC 5961 §3.2: a RST whose seq is *exactly* RCV.NXT resets the connection; an in-window but
    /// inexact RST earns a challenge ACK (not a reset); an out-of-window RST is dropped. This blunts
    /// the blind-reset attack, where an off-path attacker need only land a RST anywhere in window.
    fn on_rst(&mut self, th: &TcpHeader, now_ms: u64) -> Option<Vec<u8>> {
        if self.state == State::SynSent {
            if th.flags & ACK != 0 && th.ack == self.send.nxt {
                self.state = State::Closed;
            }
            return None;
        }
        if self.state == State::TimeWait {
            return None; // RFC 1337: never honor a RST in TIME_WAIT
        }
        if th.seq == self.recv.nxt {
            self.state = State::Closed; // exactly expected → honor the reset
            None
        } else if self.in_window(th.seq) {
            self.maybe_challenge(now_ms) // in window but off-by-some → (throttled) challenge, no reset
        } else {
            None // out of window → ignore
        }
    }

    /// Full segment handler: like `on_packet_at` but also given the parsed TCP `options`, so the
    /// state machine can learn the peer's MSS (Doc 15) and, later, timestamps / SACK blocks. `main`
    /// calls this with the options parsed off the wire.
    pub fn on_segment(
        &mut self,
        th: &TcpHeader,
        payload: &[u8],
        opts: &TcpOptions,
        now_ms: u64,
    ) -> Option<Vec<u8>> {
        self.ts_val = now_ms as u32; // Doc 16: refresh our timestamp clock for anything we send
        self.last_active_ms = now_ms; // Doc 23: a segment arrived — reset the half-close reaper
        self.keepalive_probes_sent = 0; // Doc 26: a segment arrived — the peer is alive, reset probes

        // ── Incoming RST (RFC 5961 §3), Doc 19 ── A blind off-path attacker who guesses the
        // 4-tuple can try to tear the connection down with a forged RST. Rather than honor any
        // in-window RST (the loose RFC 793 rule), accept only one whose seq is exactly RCV.NXT;
        // challenge-ACK an in-window-but-inexact one; drop the rest. Checked before all else.
        if th.flags & RST != 0 {
            return self.on_rst(th, now_ms);
        }

        // Active open: we sent a SYN and are waiting for the peer's SYN-ACK.
        if self.state == State::SynSent {
            // Accept the SYN-ACK only if it acknowledges our SYN (ack == SND.NXT).
            if th.flags & (SYN | ACK) == (SYN | ACK) && th.ack == self.send.nxt {
                self.recv.irs = th.seq;
                self.recv.nxt = th.seq.wrapping_add(1);
                self.reasm = Reassembler::new(self.recv.nxt); // now we know the peer's ISN
                self.send.una = th.ack;
                // Doc 15: learn the peer's MSS from its SYN-ACK; bound our send segments by it.
                if let Some(mss) = opts.mss {
                    self.send_mss = mss.min(OUR_MSS);
                }
                // Doc 16: timestamps are enabled iff the SYN-ACK also carries them (we offered in
                // our SYN). Seed TS.Recent so our segments echo the peer's clock.
                if let Some((tsval, _)) = opts.timestamps {
                    self.ts_enabled = true;
                    self.ts_recent = tsval;
                }
                // Doc 17: adopt the peer's window scale from its SYN-ACK (we offered ours in the SYN).
                if let Some(shift) = opts.window_scale {
                    self.snd_wscale = shift;
                }
                // Doc 18: SACK is enabled iff the SYN-ACK also carried SACK-Permitted (RFC 2018 §2).
                if opts.sack_permitted {
                    self.sack_ok = true;
                }
                // Doc 12: the SYN-ACK acknowledges our SYN — drop it from the retx queue (no RTT
                // sample: a handshake segment can be ambiguous and isn't fed to the estimator here).
                let _ = self.retx.ack(self.send.una, now_ms);
                self.state = State::Established;
                // Complete the handshake with the final ACK.
                return Some(self.segment(self.send.nxt, self.recv.nxt, ACK, &[]));
            }
            return None; // not the SYN-ACK we expect → ignore
        }

        // ── Blind in-window SYN (RFC 5961 §4), Doc 19 ── A SYN to an already-synchronized
        // connection once forced a reset (RFC 793), letting an attacker kill connections with a
        // single in-window SYN. Instead send a challenge ACK and drop the SYN (irrespective of its
        // sequence number): a peer that truly restarted replies with a correctly-sequenced RST,
        // which the RST path above then honors. A retransmitted SYN-ACK arriving after our final
        // ACK was lost lands here too — the challenge ACK doubles as that missing ACK, completing
        // the peer's handshake.
        if th.flags & SYN != 0 && self.is_synchronized() {
            return self.maybe_challenge(now_ms); // Doc 23: throttled (RFC 5961 ACK rate limit)
        }

        // Complete the handshake if we're still waiting for the client's ACK. (That ACK may
        // also piggyback data, so we fall through to data handling afterwards.)
        if self.state == State::SynRcvd {
            if th.flags & ACK != 0 && th.ack == self.send.nxt {
                self.send.una = th.ack;
                // Doc 12: the final ACK acknowledges our SYN-ACK — drop it from the retx queue.
                let _ = self.retx.ack(self.send.una, now_ms);
                self.state = State::Established;
            } else {
                return None; // not the ACK we expect → ignore
            }
        }

        if self.state == State::Established || self.state == State::CloseWait {
            // Doc 16 — PAWS (Protect Against Wrapped Sequences, RFC 7323 §5): on a fast, long-lived
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
            // left-shifted by the peer's negotiated window scale (Doc 17) to recover the true
            // SND.WND. Keep the prior value so the duplicate-ACK test below can tell a real dup from
            // a pure window update (Doc 14).
            let prev_wnd = self.send.wnd;
            let new_wnd = (th.window as u32) << self.snd_wscale;
            self.send.wnd = new_wnd;
            self.max_snd_wnd = self.max_snd_wnd.max(new_wnd); // Doc 23: RFC 5961 §5 ACK window bound

            // Advance SND.UNA only if the ack is *acceptable*: SND.UNA < ACK <= SND.NXT, on the
            // wrapping 32-bit circle (RFC 9293 §3.4 via `seq::between`). A duplicate or
            // out-of-window ack is ignored rather than blindly trusted — the defensive version
            // of the earlier "store whatever they sent".
            if th.flags & ACK != 0 {
                // Doc 23 — RFC 5961 §5 blind-data-injection defence: an ACK outside
                // [SND.UNA − MAX.SND.WND, SND.NXT] (e.g. acking data we never sent) is not trusted —
                // answer with a (throttled) challenge ACK and drop the segment.
                if !self.ack_acceptable(th.ack) {
                    return self.maybe_challenge(now_ms);
                }
                // Doc 18: apply any SACK blocks first (RFC 2018 §4) — mark those out-of-order ranges
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
                    self.tlp_sent = false; // Doc 24: forward progress — re-arm the Tail Loss Probe
                    self.tlp_deadline_ms = 0;
                    // RTT: with timestamps (Doc 16) the echoed TSecr dates the acked data exactly, so
                    // every ACK yields a clean sample — even for retransmitted data, since the echo
                    // disambiguates which copy (no Karn restriction). Without timestamps, fall back to
                    // timing the retx queue (Karn-limited to never-retransmitted segments).
                    // Capture the RTT sample (if any) so BBR can feed it into its RTprop/BDP model;
                    // CUBIC ignores it. `None` means this ACK yielded no clean sample (Karn).
                    let mut rtt_sample: Option<u64> = None;
                    if self.ts_enabled {
                        if let Some((_, tsecr)) = opts.timestamps {
                            let s = self.ts_val.wrapping_sub(tsecr) as u64;
                            self.rtt.sample(s);
                            rtt_sample = Some(s);
                        }
                        let _ = self.retx.ack(self.send.una, now_ms);
                    } else if let Some(rtt_ms) = self.retx.ack(self.send.una, now_ms) {
                        self.rtt.sample(rtt_ms);
                        rtt_sample = Some(rtt_ms);
                    }
                    // Doc 20 — NewReno (RFC 6582). During fast recovery, a *partial* ACK (advances
                    // SND.UNA but stops short of `recover`, so a later segment in the same window was
                    // also lost) retransmits the next hole and STAYS in recovery; only a *full* ACK
                    // (SEG.ACK ≥ recover) ends the episode. Plain Reno (Doc 10) treated the first new
                    // ACK as "done" and then stalled on the second loss until an RTO. Outside
                    // recovery this is an ordinary slow-start / congestion-avoidance ACK.
                    if self.cong.in_recovery() && seq::before(th.ack, self.recover) {
                        self.cong.on_partial_ack(acked);
                        if let Some(pkt) = self.retx.fast_retransmit(now_ms) {
                            return Some(pkt); // retransmit the next hole immediately
                        }
                    } else {
                        // slow start / CUBIC CA / full-ACK exit (CUBIC), or the BBR model update.
                        self.cong.on_ack(acked, rtt_sample, now_ms);
                    }
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
                    // excluded here so they can't masquerade as loss (Doc 14).
                    if self.cong.on_dup_ack(self.flight_size()) {
                        // Doc 20 (RFC 6582): freeze the recovery point at the current SND.NXT, so the
                        // partial/full-ACK test above knows when this loss window is fully repaired.
                        self.recover = self.send.nxt;
                        if let Some(pkt) = self.retx.fast_retransmit(now_ms) {
                            return Some(pkt);
                        }
                    }
                }
            }

            // Data handling via the reassembler: it buffers out-of-order segments, drops duplicates,
            // and returns only the bytes now contiguous from RCV.NXT (RFC 9293 §3.4). Delivered
            // bytes go into the receive buffer for the application; we do NOT echo here — the app
            // reads (`take_received`) and responds. Doc 19: do NOT return yet — a FIN may ride on
            // this very segment (a peer may set FIN on its last data segment), and a previously
            // deferred FIN may now be deliverable, so fall through to the FIN handling below.
            let had_data = !payload.is_empty();
            if had_data {
                let delivered = self.reasm.recv(th.seq, payload, self.recv.nxt);
                if !delivered.is_empty() {
                    self.recv.nxt = self.recv.nxt.wrapping_add(delivered.len() as u32);
                    self.recv_buf.extend_from_slice(&delivered);
                }
            }

            // ── The peer's FIN (RFC 9293 §3.5), Doc 19 half-close ── A FIN occupies one sequence
            // number positioned AFTER the segment's data, at SEG.SEQ + SEG.LEN.
            if th.flags & FIN != 0 {
                let fin_seq = th.seq.wrapping_add(payload.len() as u32);
                if self.state == State::CloseWait && !seq::after(fin_seq, self.recv.nxt) {
                    // A retransmitted FIN we have already accepted (our earlier ACK was lost):
                    // re-acknowledge current state so the peer can finish its own teardown.
                    return Some(self.segment(self.send.nxt, self.recv.nxt, ACK, &[]));
                }
                // Record where the FIN sits (at or ahead of RCV.NXT). It is *honored* below once
                // everything up to it is in order — so an out-of-order data+FIN defers correctly
                // and still completes when its gap fills.
                if self.state == State::Established && !seq::before(fin_seq, self.recv.nxt) {
                    self.pending_fin = Some(fin_seq);
                }
            }

            // Honor a pending FIN (possibly deferred from an earlier out-of-order segment) now that
            // RCV.NXT has reached it. Doc 19: this is the real half-close. ACK the FIN with a *pure
            // ACK* and enter CLOSE_WAIT — our send side stays open. The local app closes when it is
            // done, which sends our FIN and advances to LAST_ACK (see `close`). We no longer fuse
            // our FIN onto this ACK, so a server can keep sending after the client half-closes.
            if self.state == State::Established && self.pending_fin == Some(self.recv.nxt) {
                self.recv.nxt = self.recv.nxt.wrapping_add(1); // the FIN consumes a sequence number
                self.pending_fin = None;
                self.peer_fin = true; // the application now sees EOF on reads
                self.state = State::CloseWait;
                return Some(self.segment(self.send.nxt, self.recv.nxt, ACK, &[]));
            }

            // Plain data with no FIN to honor on this segment: acknowledge. A fresh RCV.NXT for
            // in-order data, or a *duplicate ACK* for out-of-order/duplicate data (three of which
            // trigger the sender's fast retransmit). Doc 18: when SACK is on and out-of-order data
            // is buffered, this ACK also names those ranges in SACK blocks (RFC 2018 §3).
            if had_data {
                let ack_opts = self.ack_options();
                return Some(self.segment_opts(self.send.nxt, self.recv.nxt, ACK, &ack_opts, &[]));
            }
        }

        if self.state == State::LastAck {
            // The connection is fully closed once the peer ACKs our FIN.
            if th.flags & ACK != 0 && th.ack == self.send.nxt {
                let _ = self.retx.ack(th.ack, now_ms); // Doc 12: drop the now-acked FIN
                self.state = State::Closed;
            }
            return None;
        }

        // ── Active-close states (we initiated the close via `close()`) ── Doc 22: after we close
        // our SEND side our RECEIVE side stays open (the active half-close: send a request, then
        // `shutdown(SHUT_WR)`, then read the response). So FIN_WAIT_1/2 still deliver incoming data
        // and acknowledge it, in addition to driving the teardown (RFC 9293 §3.5).
        if self.state == State::FinWait1 {
            let acked_our_fin = th.flags & ACK != 0 && th.ack == self.send.nxt;
            // Doc 12: once our FIN is acknowledged, drop it from the retx queue (whichever close
            // variant we end up in below).
            if acked_our_fin {
                let _ = self.retx.ack(th.ack, now_ms);
            }
            // Doc 22: deliver any data the peer sent (our read side is still open).
            if !payload.is_empty() {
                let delivered = self.reasm.recv(th.seq, payload, self.recv.nxt);
                if !delivered.is_empty() {
                    self.recv.nxt = self.recv.nxt.wrapping_add(delivered.len() as u32);
                    self.recv_buf.extend_from_slice(&delivered);
                }
            }
            // The peer also sent its FIN (in order, possibly piggybacked on that data) — ACK it.
            let fin_seq = th.seq.wrapping_add(payload.len() as u32);
            if th.flags & FIN != 0 && fin_seq == self.recv.nxt {
                self.recv.nxt = self.recv.nxt.wrapping_add(1);
                self.peer_fin = true;
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
            // Data without an in-order FIN → acknowledge it.
            if !payload.is_empty() {
                return Some(self.segment(self.send.nxt, self.recv.nxt, ACK, &[]));
            }
            return None;
        }

        if self.state == State::FinWait2 {
            // Doc 22: our read side is still open — deliver incoming data first.
            if !payload.is_empty() {
                let delivered = self.reasm.recv(th.seq, payload, self.recv.nxt);
                if !delivered.is_empty() {
                    self.recv.nxt = self.recv.nxt.wrapping_add(delivered.len() as u32);
                    self.recv_buf.extend_from_slice(&delivered);
                }
            }
            // Await the peer's FIN (possibly piggybacked); acknowledge it and enter TIME_WAIT.
            let fin_seq = th.seq.wrapping_add(payload.len() as u32);
            if th.flags & FIN != 0 && fin_seq == self.recv.nxt {
                self.recv.nxt = self.recv.nxt.wrapping_add(1);
                self.peer_fin = true;
                let out = self.segment(self.send.nxt, self.recv.nxt, ACK, &[]);
                self.state = State::TimeWait;
                self.time_wait_ms = now_ms;
                return Some(out);
            }
            // Data without an in-order FIN → acknowledge it.
            if !payload.is_empty() {
                return Some(self.segment(self.send.nxt, self.recv.nxt, ACK, &[]));
            }
            return None;
        }

        if self.state == State::Closing {
            // Simultaneous close: we've ACKed their FIN; now wait for the ACK of ours.
            if th.flags & ACK != 0 && th.ack == self.send.nxt {
                let _ = self.retx.ack(th.ack, now_ms); // Doc 12: drop the now-acked FIN
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
        self.ts_val = now_ms as u32; // Doc 16: refresh the timestamp clock for any probe we send
        // Expire TIME_WAIT after 2·MSL so the connection can finally be reaped (RFC 9293).
        const TIME_WAIT_MS: u64 = 2 * 120_000; // 2·MSL, with MSL = 2 minutes
        if self.state == State::TimeWait
            && now_ms.saturating_sub(self.time_wait_ms) >= TIME_WAIT_MS
        {
            self.state = State::Closed;
        }
        // Doc 23 — reap a connection idling in a half-closed state: a peer that vanished after
        // sending its FIN (we're in CLOSE_WAIT) or after we closed our half (FIN_WAIT_2) must not pin
        // the TCB (and its memory) open forever. `last_active_ms` is the last time a segment arrived,
        // so an active half-close still exchanging data keeps resetting it — only a genuinely idle
        // connection is reaped (cf. Linux's `tcp_fin_timeout`).
        const FIN_WAIT2_TIMEOUT_MS: u64 = 60_000;
        const CLOSE_WAIT_TIMEOUT_MS: u64 = 120_000;
        let idle = now_ms.saturating_sub(self.last_active_ms);
        if (self.state == State::FinWait2 && idle >= FIN_WAIT2_TIMEOUT_MS)
            || (self.state == State::CloseWait && idle >= CLOSE_WAIT_TIMEOUT_MS)
        {
            self.state = State::Closed;
        }
        // Doc 24 — RACK (RFC 8985) time-based loss detection: resend any hole a later ACK exposed
        // once the reordering window (≈ RTO/4) has elapsed, without waiting for three dup-ACKs or
        // the full RTO. This is not a congestion event by itself (no cwnd collapse here).
        let reo_wnd = (self.rtt.rto() / 4).max(1);
        let mut out = self.retx.rack_mark_lost(now_ms, reo_wnd);

        // Doc 24 — Tail Loss Probe (RFC 8985 §7): the tail of a transfer is outstanding with nothing
        // new to send and we're not recovering; at the probe deadline (~RTO/2) retransmit the last
        // segment to elicit an ACK/SACK before the far longer RTO. One probe per tail.
        if self.tlp_deadline_ms != 0
            && now_ms >= self.tlp_deadline_ms
            && self.flight_size() > 0
            && !self.cong.in_recovery()
            && !self.tlp_sent
        {
            if let Some(probe) = self.retx.retransmit_last(now_ms) {
                out.push(probe);
                self.tlp_sent = true;
            }
            self.tlp_deadline_ms = 0;
        }

        // RTO backstop: anything still due after RACK/TLP is a genuine timeout — the strongest
        // congestion signal. Collapse cwnd to one segment and re-enter slow start (RFC 5681 §3.1).
        let due = self.retx.due(now_ms, self.rtt.rto());
        if !due.is_empty() {
            let flight = self.flight_size();
            self.cong.on_timeout(flight);
            self.rtt.back_off(); // double the RTO per timeout (RFC 6298 §5.5 / Karn's backoff)
            out.extend(due);
        }

        // Persist timer / zero-window probe (RFC 9293 §3.8.6.1). If the peer's window is shut but we
        // have data to send and nothing is in flight, there is no retransmission to lean on — and a
        // lost "window re-opened" ACK would deadlock both sides forever. So poke a single byte into
        // the closed window after one RTO. Once that probe is outstanding (FlightSize > 0) the
        // ordinary RTO retransmission keeps re-probing it; the peer's ACK (carrying its now-current
        // window) breaks the stall.
        if (self.state == State::Established || self.state == State::CloseWait)
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

        // Doc 26 — TCP keepalive (RFC 9293 §3.8.4). Probe an idle ESTABLISHED connection so a peer
        // that vanished WITHOUT a FIN/RST (a crash, a pulled cable) is eventually detected — the
        // reaper (Doc 23) only covers half-closed states, and an idle connection with nothing in
        // flight has no RTO/RACK timer to lean on. The probe is a segment at SND.NXT−1 (a byte the
        // peer has already acknowledged); a live peer answers with a bare ACK, which resets the
        // timer. After KEEPALIVE_PROBES unanswered probes, the peer is declared dead.
        if self.keepalive_enabled
            && self.state == State::Established
            && self.flight_size() == 0
            && self.send_buf.is_empty()
        {
            let next_probe_at = self
                .last_active_ms
                .saturating_add(KEEPALIVE_IDLE_MS)
                .saturating_add(self.keepalive_probes_sent as u64 * KEEPALIVE_INTVL_MS);
            if now_ms >= next_probe_at {
                if self.keepalive_probes_sent >= KEEPALIVE_PROBES {
                    self.state = State::Closed; // unanswered after the last probe → peer is gone
                } else {
                    self.keepalive_probes_sent += 1;
                    out.push(self.segment(self.send.nxt.wrapping_sub(1), self.recv.nxt, ACK, &[]));
                }
            }
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

    /// Doc 26 — `SO_KEEPALIVE` (RFC 9293 §3.8.4): when enabled, an idle ESTABLISHED connection is
    /// probed by `on_tick`, and a peer that has silently vanished is eventually reaped. Off by
    /// default, like the real socket option; the server binary leaves it off (exercised by tests).
    #[allow(dead_code)]
    pub fn set_keepalive(&mut self, on: bool) {
        self.keepalive_enabled = on;
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
        // Our send side is open in ESTABLISHED and, after a peer half-close, in CLOSE_WAIT (Doc 19).
        if self.state != State::Established && self.state != State::CloseWait {
            return out;
        }
        self.ts_val = now_ms as u32; // Doc 16: stamp outgoing data with the current clock

        // Doc 21 — RFC 6675 SACK loss recovery. While recovering on a SACK-enabled connection, pace
        // transmission by the `pipe` estimate (bytes truly in flight) rather than FlightSize, which
        // over-counts SACKed and lost data. Retransmit every hole the scoreboard reveals, then send
        // new data, keeping the pipe full at min(cwnd, SND.WND) — so a window with several losses is
        // repaired in ONE round trip and the link stays busy, not NewReno's one-hole-per-RTT crawl.
        if self.sack_ok && self.cong.in_recovery() {
            let limit = self.send.wnd.min(self.cong.window());
            while self.retx.pipe(DUP_THRESH) < limit {
                match self.retx.next_lost_retransmit(DUP_THRESH, now_ms) {
                    Some(pkt) => out.push(pkt), // (1) retransmit the next hole, oldest first
                    None => break,
                }
            }
            let mss = self.send_mss as usize;
            while !self.send_buf.is_empty() {
                let pipe = self.retx.pipe(DUP_THRESH);
                if pipe >= limit {
                    break;
                }
                // (2) fill the remaining pipe with NEW data (Nagle is irrelevant during recovery —
                // we are deliberately keeping the window full while the holes heal).
                let n = ((limit - pipe) as usize).min(mss).min(self.send_buf.len());
                if n == 0 {
                    break;
                }
                let payload: Vec<u8> = self.send_buf.drain(..n).collect();
                let seg = self.segment(self.send.nxt, self.recv.nxt, PSH | ACK, &payload);
                self.send.nxt = self.send.nxt.wrapping_add(n as u32);
                self.retx.record(self.send.nxt.wrapping_sub(n as u32), self.send.nxt, seg.clone(), now_ms);
                out.push(seg);
            }
            return out;
        }

        let mss = self.send_mss as usize; // Doc 15: the negotiated send MSS, not a fixed constant
        // Doc 28 — BBR pacing rate (bytes/sec). Non-zero only under the model-based controller; CUBIC
        // reports 0, so the pacing gate below is skipped and the sender stays purely window-clocked.
        let pacing_bps = self.cong.pacing_rate_bps();
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
            // Doc 28 — BBR pacing: release new data at the modelled `pacing_rate` rather than bursting
            // the whole window. Hold this segment until `next_send_ms`; once it goes, schedule the next
            // one `n / pacing_rate` later (≥1 ms). This is what keeps in-flight ≈ BDP with no standing
            // queue. The window (`usable_window`) is still the hard cap; pacing only smooths *within* it.
            if pacing_bps > 0.0 {
                if now_ms < self.next_send_ms {
                    break;
                }
                let gap_ms = (n as f64 * 1000.0 / pacing_bps).ceil() as u64;
                self.next_send_ms = now_ms.saturating_add(gap_ms.max(1));
            }
            let payload: Vec<u8> = self.send_buf.drain(..n).collect();
            let seg = self.segment(self.send.nxt, self.recv.nxt, PSH | ACK, &payload);
            self.send.nxt = self.send.nxt.wrapping_add(n as u32);
            self.retx.record(self.send.nxt.wrapping_sub(n as u32), self.send.nxt, seg.clone(), now_ms);
            out.push(seg);
        }

        // Doc 24 — arm the Tail Loss Probe (RFC 8985 §7): data is outstanding with nothing new
        // queued (a possible tail loss) and we're not already recovering → schedule a probe at
        // ~RTO/2, ahead of the full RTO. Re-armed on each new send; disarmed when there's no tail.
        if self.flight_size() > 0 && self.send_buf.is_empty() && !self.cong.in_recovery() {
            if self.tlp_deadline_ms == 0 {
                self.tlp_deadline_ms = now_ms.saturating_add((self.rtt.rto() / 2).max(1));
            }
        } else {
            self.tlp_deadline_ms = 0;
            self.tlp_sent = false;
        }
        out
    }

    /// Application receive: take all reassembled, in-order bytes delivered so far, draining the
    /// receive buffer. Empty if nothing new has arrived.
    pub fn take_received(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.recv_buf)
    }

    /// Switch this connection to **BBR** congestion control (`src/bbr.rs`), the model-based
    /// alternative to the default CUBIC/Reno controller. A real stack chooses per-socket; the live
    /// `main` server selects BBR for every connection it accepts. Safe to call on a fresh connection
    /// (no congestion state has accumulated yet); the rest of the state machine is unaffected.
    pub fn use_bbr(&mut self) {
        self.cong = CongestionControl::bbr();
    }

    /// BBR's modelled paced send rate (bytes/sec) for this connection: `0.0` until the model has
    /// learned a bottleneck bandwidth, and always `0.0` under the window-only CUBIC controller.
    pub fn pacing_rate_bps(&self) -> f64 {
        self.cong.pacing_rate_bps()
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
    #[cfg(test)]
    fn cwnd(&self) -> u32 {
        self.cong.window()
    }
    #[cfg(test)]
    fn in_recovery(&self) -> bool {
        self.cong.in_recovery()
    }

    /// Build a segment from THIS connection's perspective (src = us, dst = peer). The advertised
    /// window is *our* receive window (`RCV.WND`) — how much WE can accept — never `send.wnd`,
    /// which is the peer's window and bounds only how much we may send. When timestamps are
    /// negotiated (Doc 16) every such segment carries a Timestamps option (TSval = our clock,
    /// TSecr = TS.Recent); SYN/SYN-ACK build their options explicitly via `segment_opts`.
    fn segment(&self, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        if self.ts_enabled {
            self.segment_opts(seq, ack, flags, &ts_option(self.ts_val, self.ts_recent), payload)
        } else {
            self.segment_opts(seq, ack, flags, &[], payload)
        }
    }

    /// `segment` with explicit TCP options (must be 4-byte aligned). Used by the SYN/SYN-ACK path to
    /// carry the MSS option (Doc 15) and, later, timestamps / window scale / SACK-permitted.
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

/// Doc 27 — a cheap keyed mix folding the secret, 4-tuple, client ISN, and counter into 32 bits.
/// NOT cryptographic (a real stack uses SipHash) — enough to demonstrate the SYN-cookie structure.
fn cookie_mix(
    secret: u64,
    local: (Ipv4Addr, u16),
    remote: (Ipv4Addr, u16),
    peer_isn: u32,
    counter: u32,
) -> u32 {
    let mut h = secret;
    for v in [
        u32::from(remote.0) as u64,
        remote.1 as u64,
        u32::from(local.0) as u64,
        local.1 as u64,
        peer_isn as u64,
        counter as u64,
    ] {
        h = (h ^ v).wrapping_mul(0x0000_0100_0000_01B3); // FNV-1a 64-bit prime, one mixing round each
    }
    (h ^ (h >> 32)) as u32
}

/// Doc 27 — compute a SYN cookie to use as our SYN-ACK ISS for the `(local, remote)` handshake whose
/// SYN carried `peer_isn` and advertised `peer_mss`. Encodes a coarse time counter (for expiry), the
/// MSS as a 2-bit table index, and a keyed 24-bit MAC. No connection state is stored — the cookie is
/// the state. RFC 4987 (TCP SYN-flood mitigations).
pub fn syn_cookie(
    secret: u64,
    local: (Ipv4Addr, u16),
    remote: (Ipv4Addr, u16),
    peer_isn: u32,
    peer_mss: u16,
    now_ms: u64,
) -> u32 {
    let counter = (now_ms / COOKIE_TICK_MS) as u32;
    let mss_idx = COOKIE_MSS_TABLE.iter().rposition(|&m| m <= peer_mss).unwrap_or(0) as u32;
    let mac = cookie_mix(secret, local, remote, peer_isn, counter) & 0x00FF_FFFF;
    ((counter & 0x3f) << 26) | ((mss_idx & 0x3) << 24) | mac
}

/// Doc 27 — validate a returned SYN cookie (the final ACK's `ack − 1`). Returns the encoded send MSS
/// iff the cookie is authentic for this 4-tuple/secret/`peer_isn` AND recent (within a couple of
/// counter ticks of `now_ms`); else `None` (a stray ACK or a forged/expired cookie → caller RSTs).
pub fn check_syn_cookie(
    secret: u64,
    local: (Ipv4Addr, u16),
    remote: (Ipv4Addr, u16),
    peer_isn: u32,
    cookie: u32,
    now_ms: u64,
) -> Option<u16> {
    let counter_bits = (cookie >> 26) & 0x3f;
    let mss_idx = ((cookie >> 24) & 0x3) as usize;
    let mac = cookie & 0x00FF_FFFF;
    let now_counter = (now_ms / COOKIE_TICK_MS) as u32;
    // Accept the current counter tick or the previous two (clock/RTT skew); reject older (expired).
    for back in 0..=2u32 {
        let c = now_counter.wrapping_sub(back);
        if (c & 0x3f) == counter_bits && (cookie_mix(secret, local, remote, peer_isn, c) & 0x00FF_FFFF) == mac {
            return Some(COOKIE_MSS_TABLE[mss_idx]);
        }
    }
    None
}

/// Doc 27 — the SYN-ACK for a cookie handshake: ISS = `cookie`, ack = `peer_isn + 1`, carrying ONLY
/// our MSS option (SYN cookies drop the rest). Builds the bytes directly — no `Connection` exists.
pub fn build_syn_cookie_synack(ip_src: Ipv4Addr, ip_dst: Ipv4Addr, th: &TcpHeader, cookie: u32) -> Vec<u8> {
    let opts = mss_option(OUR_MSS).to_vec();
    build_packet(
        (ip_dst, th.dst_port), // src = us (the SYN's destination)
        (ip_src, th.src_port), // dst = the client
        cookie,
        th.seq.wrapping_add(1),
        SYN | ACK,
        1024,
        &opts,
        &[],
    )
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
    /// First sequence number this segment covers (Doc 18) — its left edge, for matching SACK blocks.
    start_seq: u32,
    /// One past the last sequence number this segment covers; fully acked when SND.UNA reaches it.
    end_seq: u32,
    /// The complete IP+TCP bytes, ready to resend verbatim.
    packet: Vec<u8>,
    /// When it was (last) sent, in milliseconds — supplied by the caller's clock.
    sent_at_ms: u64,
    /// How many times it's been retransmitted (for backoff / giving up).
    retries: u32,
    /// Selectively acknowledged by a peer SACK block (Doc 18, RFC 2018): the peer holds this range
    /// out of order, so loss recovery skips it and resends only the holes that precede it.
    sacked: bool,
}

/// The per-connection retransmission queue (RFC 9293 §3.8.1) — the heart of TCP reliability.
/// Time is passed in (`now_ms`) rather than read from a clock, so the logic is unit-testable
/// without sleeping; the event loop supplies the real time and resends whatever is `due`.
#[derive(Debug, Default)]
pub struct RetxQueue {
    segments: Vec<Unacked>,
    /// Doc 24 — RACK (RFC 8985): the transmit time and right edge of the most recently SENT segment
    /// that has since been acked or SACKed. A still-outstanding segment sent before this, once the
    /// reordering window has elapsed, is presumed lost. `0` until the first ack/sack.
    rack_xmit_ts: u64,
    rack_end_seq: u32,
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
        let (mut rack_ts, mut rack_end) = (self.rack_xmit_ts, self.rack_end_seq);
        self.segments.retain(|s| {
            // `una` still "before" end_seq ⇒ segment not yet fully acked ⇒ keep it.
            let still_unacked = seq::before(una, s.end_seq);
            if !still_unacked {
                if s.retries == 0 && sample.is_none() {
                    sample = Some(now_ms.saturating_sub(s.sent_at_ms));
                }
                // Doc 24 — RACK: remember the most-recently-sent of the segments now acked.
                if s.sent_at_ms >= rack_ts {
                    rack_ts = s.sent_at_ms;
                    rack_end = s.end_seq;
                }
            }
            still_unacked
        });
        self.rack_xmit_ts = rack_ts;
        self.rack_end_seq = rack_end;
        sample
    }

    /// Packets whose retransmission timeout (`rto_ms`) has elapsed. Resets each one's timer and
    /// bumps its retry count, then returns clones for the caller to re-send.
    pub fn due(&mut self, now_ms: u64, rto_ms: u64) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for s in &mut self.segments {
            // Doc 18: never resend a SACKed range — the peer already has it (RFC 2018 §4); only the
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
        // Doc 18: resend the oldest segment the peer has NOT selectively acked — the first genuine
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
        let (mut rack_ts, mut rack_end) = (self.rack_xmit_ts, self.rack_end_seq);
        for s in &mut self.segments {
            if s.sacked {
                continue;
            }
            for &(left, right) in blocks {
                let covered = !seq::before(s.start_seq, left) && !seq::after(s.end_seq, right);
                if covered {
                    s.sacked = true;
                    // Doc 24 — RACK: a SACKed segment is "received"; track the most recent of them.
                    if s.sent_at_ms >= rack_ts {
                        rack_ts = s.sent_at_ms;
                        rack_end = s.end_seq;
                    }
                    break;
                }
            }
        }
        self.rack_xmit_ts = rack_ts;
        self.rack_end_seq = rack_end;
    }

    /// Doc 24 — RACK (RFC 8985 §6.2) time-based loss detection. A still-outstanding segment is
    /// presumed lost if a more-recently-SENT segment has already been acked/SACKed (so this one is
    /// sequenced below `rack_end_seq` and was sent before `rack_xmit_ts`) AND more than the
    /// reordering window `reo_wnd_ms` has elapsed since it was sent. Retransmits each such hole
    /// (resetting its timer) and returns the packets. Catches losses that reordering hides from a
    /// pure dup-ACK count — and, with the Tail Loss Probe, the tail an RTO would otherwise wait on.
    pub fn rack_mark_lost(&mut self, now_ms: u64, reo_wnd_ms: u64) -> Vec<Vec<u8>> {
        let (rack_ts, rack_end) = (self.rack_xmit_ts, self.rack_end_seq);
        let mut out = Vec::new();
        for s in &mut self.segments {
            if s.sacked {
                continue;
            }
            let sent_before_acked = s.sent_at_ms < rack_ts && seq::before(s.start_seq, rack_end);
            if sent_before_acked && now_ms.saturating_sub(s.sent_at_ms) > reo_wnd_ms {
                s.retries += 1;
                s.sent_at_ms = now_ms;
                out.push(s.packet.clone());
            }
        }
        out
    }

    /// Doc 24 — the Tail Loss Probe target (RFC 8985 §7): the highest-sequence outstanding
    /// (non-SACKed) segment. Retransmitting it when the tail of a transfer is outstanding and no
    /// dup-ACKs are coming elicits an ACK/SACK before the (far longer) RTO. Marks it retransmitted.
    /// (Segments are recorded in ascending order, so the last non-SACKed one is the highest.)
    pub fn retransmit_last(&mut self, now_ms: u64) -> Option<Vec<u8>> {
        let idx = (0..self.segments.len()).rev().find(|&i| !self.segments[i].sacked)?;
        let s = &mut self.segments[idx];
        s.retries += 1;
        s.sent_at_ms = now_ms;
        Some(s.packet.clone())
    }

    /// Doc 21 — RFC 6675 §4 `IsLost`: treat the segment at `idx` as lost if at least `dup_thresh`
    /// segments with HIGHER sequence numbers have been SACKed — the SACK analogue of three duplicate
    /// ACKs (the receiver holds later data but not this, so this is presumed dropped). An
    /// already-SACKed segment is never "lost." (We count SACKed *segments* above, each ≈ one MSS,
    /// rather than RFC 6675's discontiguous *blocks* / `(dup_thresh−1)·SMSS bytes`; equivalent for
    /// our one-record-per-segment queue.)
    fn is_lost(&self, idx: usize, dup_thresh: u32) -> bool {
        let seg = &self.segments[idx];
        if seg.sacked {
            return false;
        }
        let sacked_above = self
            .segments
            .iter()
            .filter(|s| s.sacked && seq::after(s.start_seq, seg.start_seq))
            .count() as u32;
        sacked_above >= dup_thresh
    }

    /// Doc 21 — RFC 6675 §4 `Pipe()`: an estimate of the bytes actually in flight between us and the
    /// receiver — the rate-control signal for SACK loss recovery. A segment counts toward `pipe`
    /// unless the receiver already holds it (SACKed) or it is presumed lost and not yet
    /// retransmitted; a retransmitted segment counts again (it is back on the wire). `pipe < cwnd`
    /// is the gate that lets the sender keep the pipe full *during* recovery — retransmitting holes
    /// AND sending new data — instead of going quiet, which is SACK recovery's edge over NewReno.
    pub fn pipe(&self, dup_thresh: u32) -> u32 {
        let mut pipe = 0u32;
        for i in 0..self.segments.len() {
            let s = &self.segments[i];
            if s.sacked {
                continue; // the receiver holds it → not in flight
            }
            let retransmitted = s.retries > 0;
            if !self.is_lost(i, dup_thresh) || retransmitted {
                pipe = pipe.wrapping_add(s.end_seq.wrapping_sub(s.start_seq));
            }
            // a lost, never-retransmitted segment has left the network → contributes nothing
        }
        pipe
    }

    /// Doc 21 — RFC 6675 §4 `NextSeg` (the retransmission case): the lowest-sequence segment that
    /// `IsLost` reports and that we have not already retransmitted this recovery. Marks it
    /// retransmitted (resets its timer, bumps `retries`) and returns its bytes. `None` when no
    /// un-retransmitted lost segment remains — then the caller may send NEW data to fill the pipe.
    /// (Segments are recorded in ascending sequence order, so the first match is the lowest.)
    pub fn next_lost_retransmit(&mut self, dup_thresh: u32, now_ms: u64) -> Option<Vec<u8>> {
        let idx = (0..self.segments.len()).find(|&i| {
            let s = &self.segments[i];
            !s.sacked && s.retries == 0 && self.is_lost(i, dup_thresh)
        })?;
        let s = &mut self.segments[idx];
        s.retries += 1;
        s.sent_at_ms = now_ms;
        Some(s.packet.clone())
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

        // The SYN-ACK advertises OUR receive MSS (Doc 15).
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

        // Client closes: FIN at seq 101. Doc 19 — half-close: we ACK with a *pure ACK* (not the old
        // fused FIN|ACK) and enter CLOSE_WAIT; our send side stays open.
        let fin = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 1,
            data_offset: 20, flags: FIN | ACK, window: 0xffff,
        };
        let ack = conn.on_packet(&fin, &[]).expect("a pure ACK of their FIN");
        assert_eq!(conn.state(), State::CloseWait);
        assert!(conn.peer_closed()); // the application now sees EOF

        let t = parse(&ack[20..]).unwrap();
        assert_eq!(t.flags, ACK); // a bare ACK — no FIN yet
        assert_eq!(t.seq, 1); // our send position, unconsumed
        assert_eq!(t.ack, 102); // acknowledges their FIN (101 + 1)
        assert_eq!(tcp_checksum(ME, PEER, &ack[20..]), 0, "TCP checksum invalid");

        // The application has nothing more to send, so it closes its half → our FIN, LAST_ACK.
        let our_fin = conn.close(0).expect("our FIN");
        assert_eq!(conn.state(), State::LastAck);
        let f = parse(&our_fin[20..]).unwrap();
        assert_eq!(f.flags, FIN | ACK);
        assert_eq!(f.seq, 1); // our FIN at SND.NXT
        assert_eq!(f.ack, 102);

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

        // No RTT sample yet → RTO is the 200 ms default, so the Tail Loss Probe (Doc 24) is due at
        // ~RTO/2 = 100 ms — ahead of the full RTO.
        assert_eq!(conn.rto(), 200);
        assert!(conn.on_tick(50).is_empty()); // before the probe deadline
        let resent = conn.on_tick(150); // the tail loss probe resends the echo (ahead of the RTO)
        assert_eq!(resent, vec![echo]);

        // Peer ACKs our echoed data (SND.NXT advanced to 3) → the retx queue clears. The segment was
        // retransmitted, so Karn suppresses the RTT sample (no fresh sample; a probe doesn't back
        // off) — the RTO stays at the 200 ms default.
        let ack = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 103, ack: 3,
            data_offset: 20, flags: ACK, window: 0xffff,
        };
        conn.on_packet_at(&ack, &[], 300);
        assert_eq!(conn.rto(), 200);
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

    // ── Doc 12: control-segment (SYN / SYN-ACK / FIN) retransmission ──

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

        // Peer closes; Doc 19: we ACK and enter CLOSE_WAIT (no FIN queued yet).
        let fin = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 1,
            data_offset: 20, flags: FIN | ACK, window: 0xffff,
        };
        conn.on_packet_at(&fin, &[], 0).expect("a pure ACK of their FIN");
        assert_eq!(conn.state(), State::CloseWait);

        // The app closes its half → our FIN (LAST_ACK), queued at t=0, end_seq = SND.NXT = 2.
        let our_fin = conn.close(0).expect("our FIN");
        assert_eq!(conn.state(), State::LastAck);
        assert_eq!(conn.on_tick(250), vec![our_fin.clone()]); // resent after the RTO

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

    // ── Doc 13: Nagle's algorithm + TCP_NODELAY ──

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

    // ── Doc 14: zero-window probes (persist timer) ──

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

    // ── Doc 15: MSS option + outgoing segmentation ──

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

    // ── Doc 16: TCP timestamps + RTTM + PAWS ──

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

    // ── Doc 17: window scaling ──

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

    // ── Doc 18: Selective Acknowledgment (SACK, RFC 2018) ──

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

    // ── Doc 19: half-close (CLOSE_WAIT) + RFC 5961 RST/SYN validation ──

    /// A peer's pure FIN at seq 101 (helper): the common "client half-closes" segment.
    fn peer_fin_segment() -> TcpHeader {
        TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 1,
            data_offset: 20, flags: FIN | ACK, window: 0xffff,
        }
    }

    #[test]
    fn data_and_fin_in_one_segment_delivers_data_and_enters_close_wait() {
        // The peer sends its last 2 bytes "hi" AND its FIN in a single segment at seq 101. The FIN
        // sits at seq 103 (one past the data). We must deliver "hi", consume the FIN, ACK through
        // 104, and reach CLOSE_WAIT — the pre-Doc-19 code returned on the data branch and dropped a
        // piggybacked FIN entirely.
        let mut conn = established_conn();
        let data_fin = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 1,
            data_offset: 20, flags: FIN | PSH | ACK, window: 0xffff,
        };
        let ack = conn.on_packet(&data_fin, b"hi").expect("an ACK of data + FIN");
        assert_eq!(conn.state(), State::CloseWait);
        assert!(conn.peer_closed());
        assert_eq!(conn.take_received(), b"hi"); // data delivered, not dropped
        let h = parse(&ack[20..]).unwrap();
        assert_eq!(h.flags, ACK);
        assert_eq!(h.ack, 104); // 101 + 2 data + 1 FIN
        assert_eq!(conn.rcv_nxt(), 104);
    }

    #[test]
    fn half_close_lets_local_side_keep_sending() {
        let mut conn = established_conn();
        // Peer closes its half (pure FIN at 101) → we ACK, CLOSE_WAIT.
        let ack = conn.on_packet(&peer_fin_segment(), &[]).expect("a pure ACK");
        assert_eq!(conn.state(), State::CloseWait);
        assert_eq!(parse(&ack[20..]).unwrap().ack, 102);

        // Our send side is still open: the app writes and poll_transmit puts it on the wire even in
        // CLOSE_WAIT (this is the whole point of half-close).
        conn.write(b"bye");
        let segs = conn.poll_transmit(0);
        assert_eq!(segs.len(), 1);
        assert_eq!(payload_of(&segs[0]), b"bye");
        assert_eq!(parse(&segs[0][20..]).unwrap().seq, 1); // our data at SND.NXT

        // The peer ACKs our 3 bytes (ack 4) — handled in CLOSE_WAIT just like ESTABLISHED.
        let peer_ack = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 102, ack: 4,
            data_offset: 20, flags: ACK, window: 0xffff,
        };
        assert!(conn.on_packet_at(&peer_ack, &[], 0).is_none());

        // Now the app closes its half → our FIN, LAST_ACK, sequenced after the data.
        let our_fin = conn.close(0).expect("our FIN");
        assert_eq!(conn.state(), State::LastAck);
        let f = parse(&our_fin[20..]).unwrap();
        assert_eq!(f.flags, FIN | ACK);
        assert_eq!(f.seq, 4); // after the 3 sent bytes (1 + 3)
        assert_eq!(f.ack, 102);
    }

    #[test]
    fn close_wait_reacks_a_retransmitted_fin() {
        let mut conn = established_conn();
        conn.on_packet(&peer_fin_segment(), &[]).expect("first ACK");
        assert_eq!(conn.state(), State::CloseWait);

        // The peer never saw our ACK and retransmits its FIN. We must re-ACK current state (RCV.NXT
        // is already past the FIN) rather than ignore it, so the peer can complete its teardown.
        let reack = conn.on_packet(&peer_fin_segment(), &[]).expect("a re-ACK");
        let h = parse(&reack[20..]).unwrap();
        assert_eq!(h.flags, ACK);
        assert_eq!(h.ack, 102);
        assert_eq!(conn.state(), State::CloseWait); // unchanged
    }

    #[test]
    fn out_of_order_data_with_fin_defers_then_completes_the_close() {
        let mut conn = established_conn(); // RCV.NXT = 101
        // A data+FIN segment arrives out of order (seq 103, the [101,103) gap missing). The FIN sits
        // at seq 105 and MUST be deferred — we stay ESTABLISHED and dup-ACK 101, not jump to
        // CLOSE_WAIT on a FIN whose preceding bytes we don't yet have.
        let ooo = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 103, ack: 1,
            data_offset: 20, flags: FIN | PSH | ACK, window: 0xffff,
        };
        let dup = conn.on_packet(&ooo, b"XY").expect("a dup ACK");
        assert_eq!(parse(&dup[20..]).unwrap().ack, 101); // gap remains
        assert_eq!(conn.state(), State::Established); // FIN not yet honored
        assert!(!conn.peer_closed());

        // The missing bytes arrive (seq 101) → the gap fills, "ABXY" delivers, and the deferred FIN
        // is now honored in the same call: CLOSE_WAIT, ACK through 106 (101 + 4 data + 1 FIN).
        let fill = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 1,
            data_offset: 20, flags: PSH | ACK, window: 0xffff,
        };
        let ack = conn.on_packet(&fill, b"AB").expect("an ACK");
        assert_eq!(conn.state(), State::CloseWait);
        assert!(conn.peer_closed());
        assert_eq!(parse(&ack[20..]).unwrap().ack, 106);
        assert_eq!(conn.take_received(), b"ABXY");
    }

    #[test]
    fn rst_at_rcv_nxt_resets_the_connection() {
        // RFC 5961 §3.2: a RST whose seq is exactly RCV.NXT is honored — the connection is reset.
        let mut conn = established_conn(); // RCV.NXT = 101
        let rst = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 1,
            data_offset: 20, flags: RST, window: 0,
        };
        assert!(conn.on_packet(&rst, &[]).is_none()); // honored silently, no reply
        assert_eq!(conn.state(), State::Closed);
    }

    #[test]
    fn in_window_rst_is_challenged_not_honored() {
        // RFC 5961 §3.2: a RST inside the window but NOT exactly at RCV.NXT is suspicious → send a
        // challenge ACK and do NOT reset. (RCV.NXT = 101, RCV.WND = 1024 → window [101, 1125).)
        let mut conn = established_conn();
        let rst = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 200, ack: 1,
            data_offset: 20, flags: RST, window: 0,
        };
        let chal = conn.on_packet(&rst, &[]).expect("a challenge ACK");
        let h = parse(&chal[20..]).unwrap();
        assert_eq!(h.flags, ACK);
        assert_eq!(h.seq, 1); // SND.NXT
        assert_eq!(h.ack, 101); // RCV.NXT
        assert_eq!(conn.state(), State::Established); // NOT reset
    }

    #[test]
    fn out_of_window_rst_is_ignored() {
        // A RST far outside the receive window is dropped silently (RFC 5961 §3.2).
        let mut conn = established_conn(); // window [101, 1125)
        let rst = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 5000, ack: 1,
            data_offset: 20, flags: RST, window: 0,
        };
        assert!(conn.on_packet(&rst, &[]).is_none());
        assert_eq!(conn.state(), State::Established); // untouched
    }

    #[test]
    fn rst_in_time_wait_is_ignored() {
        // RFC 1337: a RST in TIME_WAIT can only be a delayed segment from the old connection; honoring
        // it risks "TIME-WAIT assassination". Drive a full active close to TIME_WAIT, then RST it.
        let mut conn = established_conn();
        conn.close(0).expect("our FIN"); // → FIN_WAIT_1
        let ack = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 2,
            data_offset: 20, flags: ACK, window: 0xffff,
        };
        conn.on_packet_at(&ack, &[], 0); // our FIN acked → FIN_WAIT_2
        let peer_fin = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 2,
            data_offset: 20, flags: FIN | ACK, window: 0xffff,
        };
        conn.on_packet_at(&peer_fin, &[], 0); // their FIN → TIME_WAIT
        assert_eq!(conn.state(), State::TimeWait);

        // A RST exactly at RCV.NXT (102) would reset a synchronized connection — but not in TIME_WAIT.
        let rst = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 102, ack: 2,
            data_offset: 20, flags: RST, window: 0,
        };
        assert!(conn.on_packet_at(&rst, &[], 0).is_none());
        assert_eq!(conn.state(), State::TimeWait); // ignored, not assassinated
    }

    #[test]
    fn in_window_syn_gets_a_challenge_ack() {
        // RFC 5961 §4: a SYN into a synchronized connection earns a challenge ACK and is dropped —
        // never a reset (which an attacker could exploit to kill connections).
        let mut conn = established_conn();
        let syn = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 0,
            data_offset: 20, flags: SYN, window: 0xffff,
        };
        let chal = conn.on_packet(&syn, &[]).expect("a challenge ACK");
        let h = parse(&chal[20..]).unwrap();
        assert_eq!(h.flags, ACK);
        assert_eq!(h.seq, 1);
        assert_eq!(h.ack, 101);
        assert_eq!(conn.state(), State::Established); // NOT reset
    }

    #[test]
    fn syn_sent_rst_that_acks_our_syn_refuses_the_connection() {
        // RFC 9293 §3.10.7.3: in SYN_SENT a RST is acceptable only if it acknowledges our SYN.
        let (mut conn, _syn) = Connection::connect_with_iss((ME, 50000), (PEER, 80), 0, 0);
        assert_eq!(conn.state(), State::SynSent);
        let rst = TcpHeader {
            src_port: 80, dst_port: 50000, seq: 0, ack: 1, // ack == SND.NXT (ISS 0 + 1)
            data_offset: 20, flags: RST | ACK, window: 0,
        };
        assert!(conn.on_packet(&rst, &[]).is_none());
        assert_eq!(conn.state(), State::Closed); // connection refused

        // A RST that does NOT acknowledge our SYN is ignored in SYN_SENT.
        let (mut conn2, _s2) = Connection::connect_with_iss((ME, 50000), (PEER, 80), 0, 0);
        let stray = TcpHeader {
            src_port: 80, dst_port: 50000, seq: 0, ack: 999,
            data_offset: 20, flags: RST | ACK, window: 0,
        };
        assert!(conn2.on_packet(&stray, &[]).is_none());
        assert_eq!(conn2.state(), State::SynSent); // unchanged
    }

    // ── Doc 20: NewReno fast recovery (RFC 6582) ──

    #[test]
    fn newreno_partial_ack_retransmits_the_next_hole_and_stays_in_recovery() {
        use crate::congestion::MSS;
        let mut conn = established_conn(); // cwnd = 1·MSS, SND.NXT = 1

        // Grow cwnd to 3·MSS over two slow-start rounds so three segments can be in flight together.
        conn.write(&vec![b'x'; 6 * MSS as usize]);
        assert_eq!(conn.poll_transmit(0).len(), 1); // seg1 [1, 1+MSS)
        let ack1 = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 1 + MSS,
            data_offset: 20, flags: ACK, window: 0xffff,
        };
        conn.on_packet_at(&ack1, &[], 0); // cwnd → 2·MSS
        assert_eq!(conn.poll_transmit(0).len(), 2); // seg2, seg3
        let ack2 = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 1 + 3 * MSS,
            data_offset: 20, flags: ACK, window: 0xffff,
        };
        conn.on_packet_at(&ack2, &[], 0); // cwnd → 3·MSS
        assert_eq!(conn.poll_transmit(0).len(), 3); // seg4, seg5, seg6 → SND.NXT = 1 + 6·MSS

        // seg4 and seg5 are "lost"; seg6 arrives → the peer dup-ACKs at 1+3·MSS.
        let dup = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 1 + 3 * MSS,
            data_offset: 20, flags: ACK, window: 0xffff,
        };
        assert!(conn.on_packet_at(&dup, &[], 1).is_none()); // dup #1
        assert!(conn.on_packet_at(&dup, &[], 2).is_none()); // dup #2
        let rx4 = conn.on_packet_at(&dup, &[], 3).expect("fast retransmit"); // dup #3
        assert_eq!(parse(&rx4[20..]).unwrap().seq, 1 + 3 * MSS); // the first hole, seg4
        assert!(conn.in_recovery());

        // The retransmitted seg4 reaches the peer; seg5 is still missing, so the cumulative ACK only
        // advances to 1+4·MSS — a PARTIAL ACK. NewReno retransmits the next hole (seg5) and stays in
        // recovery, rather than declaring victory and waiting for an RTO to find the second loss.
        let partial = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 1 + 4 * MSS,
            data_offset: 20, flags: ACK, window: 0xffff,
        };
        let rx5 = conn.on_packet_at(&partial, &[], 4).expect("partial-ACK retransmit");
        assert_eq!(parse(&rx5[20..]).unwrap().seq, 1 + 4 * MSS); // the next hole, seg5
        assert!(conn.in_recovery());

        // seg5 arrives → everything through `recover` (1+6·MSS) is acked: a FULL ACK ends recovery.
        let full = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 1 + 6 * MSS,
            data_offset: 20, flags: ACK, window: 0xffff,
        };
        assert!(conn.on_packet_at(&full, &[], 5).is_none()); // no more holes to retransmit
        assert!(!conn.in_recovery());
        // On exit cwnd deflates to ssthresh, set at the 3rd dup ACK by CUBIC (Doc 25) to
        // max(cwnd·0.7, 2·MSS). cwnd was 3·MSS there → ssthresh = 3·MSS·7/10 = 3066 bytes.
        assert_eq!(conn.cwnd(), 3 * MSS * 7 / 10);
    }

    // ── Doc 21: RFC 6675 SACK-based loss recovery (the pipe estimator) ──

    #[test]
    fn pipe_excludes_sacked_and_lost_counts_retransmitted() {
        let mut q = RetxQueue::default();
        for i in 0..5u32 {
            q.record(i * 100, i * 100 + 100, vec![i as u8], 0); // [0,100) … [400,500)
        }
        // SACK the top three segments → the bottom two each have 3 SACKed above ⇒ presumed lost.
        q.mark_sacked(&[(200, 300), (300, 400), (400, 500)]);
        // Nothing in flight: seg0/seg1 lost-not-retransmitted (0), seg2/3/4 SACKed (0).
        assert_eq!(q.pipe(3), 0);
        // Retransmit the first hole → it re-enters the pipe.
        assert!(q.next_lost_retransmit(3, 10).is_some());
        assert_eq!(q.pipe(3), 100);
        // Retransmit the second hole → both holes now in flight.
        assert!(q.next_lost_retransmit(3, 10).is_some());
        assert_eq!(q.pipe(3), 200);
        // No more lost, un-retransmitted segments remain.
        assert!(q.next_lost_retransmit(3, 10).is_none());
    }

    #[test]
    fn pipe_does_not_presume_loss_below_threshold() {
        let mut q = RetxQueue::default();
        for i in 0..4u32 {
            q.record(i * 100, i * 100 + 100, vec![i as u8], 0);
        }
        q.mark_sacked(&[(200, 300), (300, 400)]); // only TWO SACKed above the holes (< DupThresh 3)
        // seg0, seg1 are NOT presumed lost → still in flight; seg2, seg3 SACKed → out. pipe = 200.
        assert_eq!(q.pipe(3), 200);
        assert!(q.next_lost_retransmit(3, 0).is_none()); // nothing crosses the loss threshold yet
    }

    #[test]
    fn sack_recovery_retransmits_all_holes_in_one_round() {
        use crate::congestion::MSS;
        let mut conn = established_sack_conn(); // SACK negotiated; cwnd = 1·MSS

        // A bare cumulative ACK carrying `ack`.
        let cum = |ack: u32| TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack,
            data_offset: 20, flags: ACK, window: 0xffff,
        };

        // Ramp cwnd to 5·MSS over slow-start rounds so five segments (s11..s15) end up in flight.
        conn.write(&vec![b'x'; 15 * MSS as usize]);
        conn.poll_transmit(0); // s1                       (cwnd 1)
        conn.on_packet_at(&cum(1 + MSS), &[], 0); //         → cwnd 2
        conn.poll_transmit(0); // s2, s3
        conn.on_packet_at(&cum(1 + 3 * MSS), &[], 0); //     → cwnd 3
        conn.poll_transmit(0); // s4, s5, s6
        conn.on_packet_at(&cum(1 + 6 * MSS), &[], 0); //     → cwnd 4
        conn.poll_transmit(0); // s7..s10
        conn.on_packet_at(&cum(1 + 10 * MSS), &[], 0); //    → cwnd 5
        conn.poll_transmit(0); // s11..s15, SND.NXT = 1 + 15·MSS
        assert_eq!(conn.snd_nxt(), 1 + 15 * MSS);

        // The peer receives s13,s14,s15 but loses s11,s12 → dup-ACKs at 1+10·MSS, SACKing the top
        // three as one coalesced block [1+12·MSS, 1+15·MSS).
        let sack_opts = TcpOptions {
            sack_blocks: [(1 + 12 * MSS, 1 + 15 * MSS), (0, 0), (0, 0), (0, 0)],
            sack_block_count: 1,
            ..Default::default()
        };
        let dup = cum(1 + 10 * MSS);
        conn.on_segment(&dup, &[], &sack_opts, 1); // dup #1 (SACK marks s13..s15)
        conn.on_segment(&dup, &[], &sack_opts, 2); // dup #2
        let rx11 = conn.on_segment(&dup, &[], &sack_opts, 3).expect("fast retransmit"); // dup #3
        assert_eq!(parse(&rx11[20..]).unwrap().seq, 1 + 10 * MSS); // first hole, s11
        assert!(conn.in_recovery());

        // RFC 6675: the SACK scoreboard already shows the SECOND hole (s12) is lost, so poll_transmit
        // retransmits it in the SAME round — no waiting an RTT for a partial ACK (NewReno) or an RTO.
        let more = conn.poll_transmit(3);
        assert_eq!(more.len(), 1);
        assert_eq!(parse(&more[0][20..]).unwrap().seq, 1 + 11 * MSS); // second hole, s12
    }

    // ── Doc 23: robustness — RFC 5961 §5 ACK acceptability, challenge-ACK throttle, reaper timeouts ──

    #[test]
    fn ack_for_unsent_data_gets_challenge_ack() {
        // RFC 5961 §5: an ACK above SND.NXT (acking data we never sent) is a blind-injection probe —
        // answer with a challenge ACK and drop it, rather than acting on it.
        let mut conn = established_conn(); // SND.NXT = 1, RCV.NXT = 101
        let bogus = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 5000, // far above SND.NXT
            data_offset: 20, flags: ACK, window: 0xffff,
        };
        let chal = conn.on_packet(&bogus, &[]).expect("a challenge ACK");
        let h = parse(&chal[20..]).unwrap();
        assert_eq!(h.flags, ACK);
        assert_eq!(h.seq, 1); // SND.NXT
        assert_eq!(h.ack, 101); // RCV.NXT
        assert_eq!(conn.state(), State::Established); // unperturbed
    }

    #[test]
    fn challenge_acks_are_rate_limited() {
        // RFC 5961 ACK throttling (CVE-2016-5696 hardening): within one window the number of challenge
        // ACKs is capped by the randomized budget, so they can't be farmed as an off-path oracle.
        let mut conn = established_conn();
        // An in-window-but-inexact RST is challenged (Doc 19); fire many at the SAME time so the
        // budget never refills between them.
        let rst = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 300, ack: 1,
            data_offset: 20, flags: RST, window: 0,
        };
        let challenges = (0..50).filter(|_| conn.on_packet_at(&rst, &[], 0).is_some()).count() as u32;
        assert!(challenges >= 1, "the first challenge is sent");
        assert!(challenges <= CHALLENGE_ACK_MAX, "but they are capped per window (got {challenges})");
        assert_eq!(conn.state(), State::Established); // an in-window RST never resets
    }

    #[test]
    fn fin_wait2_reaped_after_idle_timeout() {
        // A peer that vanishes after ACKing our FIN leaves us in FIN_WAIT_2; the reaper collects it.
        let mut conn = established_conn();
        conn.close(0).expect("our FIN"); // → FIN_WAIT_1
        let ack = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 2,
            data_offset: 20, flags: ACK, window: 0xffff,
        };
        conn.on_packet_at(&ack, &[], 0); // ACK of our FIN → FIN_WAIT_2 (last activity at t=0)
        assert_eq!(conn.state(), State::FinWait2);
        conn.on_tick(59_000); // within tcp_fin_timeout — still waiting
        assert_eq!(conn.state(), State::FinWait2);
        conn.on_tick(61_000); // idle past the timeout → reaped
        assert_eq!(conn.state(), State::Closed);
    }

    #[test]
    fn close_wait_reaped_after_idle_timeout() {
        // A peer that sends FIN then disappears (the app never calls close) leaves us in CLOSE_WAIT —
        // the famous fd leak. The reaper bounds it.
        let mut conn = established_conn();
        let fin = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 1,
            data_offset: 20, flags: FIN | ACK, window: 0xffff,
        };
        conn.on_packet_at(&fin, &[], 0); // peer FIN → CLOSE_WAIT (last activity at t=0)
        assert_eq!(conn.state(), State::CloseWait);
        conn.on_tick(119_000);
        assert_eq!(conn.state(), State::CloseWait);
        conn.on_tick(121_000); // idle past the CLOSE_WAIT reaper → reaped
        assert_eq!(conn.state(), State::Closed);
    }

    // ── Doc 24: RACK-TLP — time-based loss detection + Tail Loss Probe (RFC 8985) ──

    #[test]
    fn tail_loss_probe_retransmits_the_last_segment() {
        // The classic tail loss: the last segment is dropped, so NO dup-ACKs come and there's nothing
        // above it to SACK. Pre-RACK that waits for the full RTO; the TLP probes at ~RTO/2 instead.
        let mut conn = established_conn(); // cwnd 1·MSS, no RTT sample → RTO 200, PTO ≈ 100
        conn.write(b"hi");
        let segs = conn.poll_transmit(0); // sends the tail; arms the TLP at ~100 ms
        assert_eq!(segs.len(), 1);
        let sent = segs[0].clone();
        assert!(conn.on_tick(50).is_empty()); // before the PTO
        // At the PTO (before the RTO) the probe retransmits the last segment.
        assert_eq!(conn.on_tick(120), vec![sent.clone()]);
        // One probe per tail — it doesn't fire again.
        assert!(conn.on_tick(150).is_empty());
    }

    #[test]
    fn rack_marks_earlier_segment_lost_once_reorder_window_passes() {
        // RACK detects a loss by TIME: a later-sent segment was SACKed, and the reordering window has
        // elapsed since the earlier one — so it was dropped, not merely reordered. (Exercised on the
        // queue directly, where the per-segment send times live.)
        let mut q = RetxQueue::default();
        q.record(0, 100, vec![0xAA], 0); //    segment A, sent at t=0
        q.record(100, 200, vec![0xBB], 10); // segment B, sent at t=10
        q.mark_sacked(&[(100, 200)]); //       B SACKed → RACK reference = (xmit_ts 10, end_seq 200)
        // Within the reordering window, A is NOT yet declared lost (it may still be in transit)…
        assert!(q.rack_mark_lost(15, 20).is_empty()); // elapsed since A = 15 ≤ reo_wnd 20
        // …but once more than the reordering window has elapsed, RACK retransmits A.
        assert_eq!(q.rack_mark_lost(30, 20), vec![vec![0xAAu8]]); // elapsed 30 > 20
        // Its timer reset on retransmit, so it isn't resent again immediately.
        assert!(q.rack_mark_lost(40, 20).is_empty());
    }

    // ── Doc 26: TCP keepalive (SO_KEEPALIVE, RFC 9293 §3.8.4) ──

    #[test]
    fn keepalive_probes_idle_connection_then_declares_it_dead() {
        let mut conn = established_conn(); // last activity at t=0 (the handshake)
        conn.set_keepalive(true);
        // Nothing before the idle threshold.
        assert!(conn.on_tick(KEEPALIVE_IDLE_MS - 1).is_empty());
        // First probe at the idle threshold: a segment at SND.NXT − 1 (a byte the peer has acked).
        let p1 = conn.on_tick(KEEPALIVE_IDLE_MS);
        assert_eq!(p1.len(), 1);
        assert_eq!(parse(&p1[0][20..]).unwrap().seq, conn.snd_nxt().wrapping_sub(1));
        // Probes repeat every interval; the connection survives while probing, up to the limit.
        assert!(conn.on_tick(KEEPALIVE_IDLE_MS + 1).is_empty()); // before the next interval
        assert_eq!(conn.on_tick(KEEPALIVE_IDLE_MS + KEEPALIVE_INTVL_MS).len(), 1); // 2nd probe
        assert_eq!(conn.on_tick(KEEPALIVE_IDLE_MS + 2 * KEEPALIVE_INTVL_MS).len(), 1); // 3rd probe
        assert_eq!(conn.state(), State::Established); // still alive while probes go unanswered
        // After KEEPALIVE_PROBES unanswered probes → the peer is declared dead.
        conn.on_tick(KEEPALIVE_IDLE_MS + 3 * KEEPALIVE_INTVL_MS);
        assert_eq!(conn.state(), State::Closed);
    }

    #[test]
    fn keepalive_is_reset_by_a_peer_response() {
        let mut conn = established_conn();
        conn.set_keepalive(true);
        assert_eq!(conn.on_tick(KEEPALIVE_IDLE_MS).len(), 1); // 1st probe sent
        // The peer answers (a bare ACK) → it's alive; keepalive restarts from this moment.
        let ack = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: 101, ack: 1,
            data_offset: 20, flags: ACK, window: 0xffff,
        };
        let t = KEEPALIVE_IDLE_MS + 1;
        conn.on_packet_at(&ack, &[], t);
        // No probe until idle again, now measured from the response.
        assert!(conn.on_tick(t + KEEPALIVE_IDLE_MS - 1).is_empty());
        assert_eq!(conn.on_tick(t + KEEPALIVE_IDLE_MS).len(), 1);
        assert_eq!(conn.state(), State::Established);
    }

    // ── Doc 27: SYN cookies (RFC 4987) ──

    #[test]
    fn syn_cookie_round_trips_and_recovers_mss() {
        let secret = 0xdead_beef_cafe_f00d;
        let (local, remote) = ((ME, 80), (PEER, 0x1234));
        let cookie = syn_cookie(secret, local, remote, 1000, 1460, 5000);
        // The matching final ACK validates and recovers the (table-rounded) MSS.
        assert_eq!(check_syn_cookie(secret, local, remote, 1000, cookie, 5000), Some(1460));
        // A smaller advertised MSS rounds down to the nearest table entry (1220).
        let c2 = syn_cookie(secret, local, remote, 1000, 1300, 5000);
        assert_eq!(check_syn_cookie(secret, local, remote, 1000, c2, 5000), Some(1220));
    }

    #[test]
    fn syn_cookie_rejects_tampering() {
        let secret = 0x1111_2222_3333_4444;
        let (local, remote) = ((ME, 80), (PEER, 0x1234));
        let cookie = syn_cookie(secret, local, remote, 1000, 1460, 5000);
        // A wrong secret, 4-tuple, peer ISN, or a flipped bit all fail to validate.
        assert!(check_syn_cookie(0xffff, local, remote, 1000, cookie, 5000).is_none());
        assert!(check_syn_cookie(secret, (ME, 81), remote, 1000, cookie, 5000).is_none());
        assert!(check_syn_cookie(secret, local, (PEER, 0x9999), 1000, cookie, 5000).is_none());
        assert!(check_syn_cookie(secret, local, remote, 1001, cookie, 5000).is_none());
        assert!(check_syn_cookie(secret, local, remote, 1000, cookie ^ 1, 5000).is_none());
    }

    #[test]
    fn syn_cookie_expires() {
        let secret = 0xabcd_1234;
        let (local, remote) = ((ME, 80), (PEER, 0x1234));
        let cookie = syn_cookie(secret, local, remote, 1000, 1460, 0);
        // Valid now and a tick later…
        assert!(check_syn_cookie(secret, local, remote, 1000, cookie, 0).is_some());
        assert!(check_syn_cookie(secret, local, remote, 1000, cookie, COOKIE_TICK_MS).is_some());
        // …but a cookie many ticks old no longer validates.
        assert!(check_syn_cookie(secret, local, remote, 1000, cookie, 10 * COOKIE_TICK_MS).is_none());
    }

    #[test]
    fn from_syn_cookie_builds_established_connection() {
        // The cookie SYN-ACK used ISS = cookie (ack = peer_isn+1); the client's final ACK
        // (seq = peer_isn+1, ack = cookie+1) reconstructs an ESTABLISHED connection with no TCB
        // having existed in between.
        let cookie = 0x5000_0000u32;
        let peer_isn = 100u32;
        let mut conn = Connection::from_syn_cookie((ME, 80), (PEER, 0x1234), peer_isn, cookie, 1460, 0);
        assert_eq!(conn.state(), State::Established);
        assert_eq!(conn.snd_nxt(), cookie.wrapping_add(1)); // the SYN-ACK consumed the cookie
        assert_eq!(conn.rcv_nxt(), peer_isn.wrapping_add(1));
        // It behaves like any established connection: data is delivered and acknowledged.
        let data = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: peer_isn + 1, ack: cookie.wrapping_add(1),
            data_offset: 20, flags: PSH | ACK, window: 0xffff,
        };
        let ack = conn.on_packet(&data, b"hi").expect("an ACK");
        assert_eq!(parse(&ack[20..]).unwrap().ack, peer_isn + 3); // the 2 bytes delivered
        assert_eq!(conn.take_received(), b"hi");
    }

    // ── BBR congestion control (src/bbr.rs) wired into the connection ──

    #[test]
    fn use_bbr_selects_model_based_control_and_keeps_the_connection_working() {
        let cookie = 0x5000_0000u32;
        let peer_isn = 100u32;
        let mut conn = Connection::from_syn_cookie((ME, 80), (PEER, 0x1234), peer_isn, cookie, 1460, 0);
        conn.use_bbr();
        // BBR starts at its 4-segment floor, not CUBIC's 1·MSS — proof the controller was swapped.
        assert_eq!(conn.cwnd(), 4 * crate::congestion::MSS);
        assert!(!conn.in_recovery()); // BBR has no Reno fast-recovery episode
        // The connection still delivers and acknowledges data with BBR driving the window.
        let data = TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: peer_isn + 1, ack: cookie.wrapping_add(1),
            data_offset: 20, flags: PSH | ACK, window: 0xffff,
        };
        let ack = conn.on_packet(&data, b"hi").expect("an ACK");
        assert_eq!(parse(&ack[20..]).unwrap().ack, peer_isn + 3);
        assert_eq!(conn.take_received(), b"hi");
    }

    #[test]
    fn bbr_paces_new_data_by_the_modelled_rate() {
        // Establish a BBR connection, teach it a bottleneck bandwidth via timed ACKs, then show that
        // transmission is spread by the *clock* (the pacing rate), not just gated by the window.
        let cookie = 0x5000_0000u32;
        let peer_isn = 100u32;
        let mut conn = Connection::from_syn_cookie((ME, 80), (PEER, 0x1234), peer_isn, cookie, 1460, 0);
        conn.use_bbr();
        let mk_ack = |ack: u32| TcpHeader {
            src_port: 0x1234, dst_port: 80, seq: peer_isn + 1, ack,
            data_offset: 20, flags: ACK, window: 0xffff,
        };
        conn.write(&vec![0u8; 60 * 1460]); // plenty of data so the buffer never empties

        // Pump send/ACK rounds, advancing the clock, so BBR's delivery-rate filter learns a BtlBw and
        // its pacing rate becomes positive (each ACK opens the window and feeds a delivery sample).
        let mut t = 0u64;
        for _ in 0..10 {
            t += 10;
            conn.poll_transmit(t);
            let nxt = conn.snd_nxt();
            // on_segment (not the fixed-clock on_packet helper) so each ACK carries the advancing
            // time — that's what gives BBR a non-zero delivery interval to estimate bandwidth from.
            conn.on_segment(&mk_ack(nxt), &[], &TcpOptions::default(), t);
        }
        assert!(conn.pacing_rate_bps() > 0.0, "BBR learned a pacing rate from the delivery samples");

        // Two polls at the SAME instant: the first releases a segment and arms the pacing clock; the
        // second is held back — even though the window and the send buffer both still allow more.
        t += 50;
        let first = conn.poll_transmit(t).len();
        let second = conn.poll_transmit(t).len();
        assert!(first >= 1, "a paced segment is released when the clock allows");
        assert_eq!(second, 0, "the next segment is held until the pacing clock advances");
        assert!(!conn.send_buffer_empty(), "data remains — so it's pacing, not an empty buffer/window");

        // Advancing the clock past the pacing deadline releases more data.
        assert!(!conn.poll_transmit(t + 100_000).is_empty(), "advancing the clock lets paced data flow");
    }
}
