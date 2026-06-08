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
    wnd: u16, // our send window (advertised by the peer)
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
        now_ms: u64,
    ) -> Option<(Connection, Vec<u8>)> {
        Self::accept_with_iss_at(ip_src, ip_dst, th, rand::random::<u32>(), now_ms)
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
        Self::accept_with_iss_at(ip_src, ip_dst, th, iss, 0)
    }

    /// Passive open with a caller-chosen initial send sequence number (ISS) and send time. `accept`
    /// wraps this with a random ISS; tests pass a fixed ISS so the handshake's seq/ack numbers are
    /// predictable.
    pub fn accept_with_iss_at(
        ip_src: Ipv4Addr,
        ip_dst: Ipv4Addr,
        th: &TcpHeader,
        iss: u32,
        now_ms: u64,
    ) -> Option<(Connection, Vec<u8>)> {
        if th.flags & SYN == 0 {
            return None;
        }

        let wnd = 1024;

        let mut conn = Connection {
            state: State::SynRcvd,
            // A SYN consumes one sequence number, so nxt = iss + 1.
            send: SendSequence { iss, una: iss, nxt: iss.wrapping_add(1), wnd },
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
        };

        // SYN-ACK: our seq = ISS, ack = what we next expect from them (their seq + 1).
        let synack = conn.segment(conn.send.iss, conn.recv.nxt, SYN | ACK, &[]);
        // Day 12: the SYN-ACK consumes sequence number ISS (end = ISS + 1 = SND.NXT). Queue it for
        // retransmission so a lost SYN-ACK is resent on RTO instead of hanging the handshake — the
        // peer's final ACK clears it (RFC 9293 §3.8.1).
        conn.retx.record(conn.send.nxt, synack.clone(), now_ms);
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
        let wnd = 1024;
        let mut conn = Connection {
            state: State::SynSent,
            send: SendSequence { iss, una: iss, nxt: iss.wrapping_add(1), wnd },
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
        };
        // SYN: seq = ISS, no ACK (we don't know the peer's seq yet).
        let syn = conn.segment(conn.send.iss, 0, SYN, &[]);
        // Day 12: the SYN consumes sequence number ISS (end = ISS + 1 = SND.NXT). Queue it so a
        // lost SYN is resent on RTO; the peer's SYN-ACK clears it (RFC 9293 §3.8.1).
        conn.retx.record(conn.send.nxt, syn.clone(), now_ms);
        (conn, syn)
    }

    /// Active close: send our FIN (valid only from ESTABLISHED) and enter FIN_WAIT_1. `now_ms`
    /// timestamps the FIN for retransmission (Day 12). The HTTP path in `main` calls this; the
    /// echo path closes passively.
    pub fn close(&mut self, now_ms: u64) -> Option<Vec<u8>> {
        if self.state != State::Established {
            return None;
        }
        let out = self.segment(self.send.nxt, self.recv.nxt, FIN | ACK, &[]);
        self.send.nxt = self.send.nxt.wrapping_add(1); // our FIN consumes a sequence number
        // Day 12: queue the FIN (end = SND.NXT) so a lost FIN is resent until the peer ACKs it,
        // instead of leaving the teardown half-finished (RFC 9293 §3.8.1).
        self.retx.record(self.send.nxt, out.clone(), now_ms);
        self.state = State::FinWait1;
        Some(out)
    }

    /// Handle a packet on an existing connection. Convenience wrapper (timestamps with 0) for
    /// callers/tests that don't track retransmission time. (`main` uses `on_packet_at`.)
    #[allow(dead_code)]
    pub fn on_packet(&mut self, th: &TcpHeader, payload: &[u8]) -> Option<Vec<u8>> {
        self.on_packet_at(th, payload, 0)
    }

    /// Time-aware packet handler: `now_ms` lets sent data be queued for retransmission and
    /// incoming ACKs clear the queue. Returns bytes to send back, if any.
    pub fn on_packet_at(&mut self, th: &TcpHeader, payload: &[u8], now_ms: u64) -> Option<Vec<u8>> {
        // Active open: we sent a SYN and are waiting for the peer's SYN-ACK.
        if self.state == State::SynSent {
            // Accept the SYN-ACK only if it acknowledges our SYN (ack == SND.NXT).
            if th.flags & (SYN | ACK) == (SYN | ACK) && th.ack == self.send.nxt {
                self.recv.irs = th.seq;
                self.recv.nxt = th.seq.wrapping_add(1);
                self.reasm = Reassembler::new(self.recv.nxt); // now we know the peer's ISN
                self.send.una = th.ack;
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
            // Flow control: track the peer's advertised receive window so we never send more
            // unacknowledged data than it can hold (RFC 9293 §3.4). SND.WND was previously stuck
            // at our own init value and never updated — this is the fix.
            self.send.wnd = th.window;

            // Advance SND.UNA only if the ack is *acceptable*: SND.UNA < ACK <= SND.NXT, on the
            // wrapping 32-bit circle (RFC 9293 §3.4 via `seq::between`). A duplicate or
            // out-of-window ack is ignored rather than blindly trusted — the defensive version
            // of the earlier "store whatever they sent".
            if th.flags & ACK != 0 {
                if seq::between(self.send.una, th.ack, self.send.nxt) {
                    // New data acknowledged: advance SND.UNA, drop what was acked, sample the RTT
                    // (Karn's algorithm skips retransmitted segments), and grow the congestion
                    // window (slow start / congestion avoidance, RFC 5681).
                    let acked = th.ack.wrapping_sub(self.send.una);
                    self.send.una = th.ack;
                    if let Some(rtt_ms) = self.retx.ack(self.send.una, now_ms) {
                        self.rtt.sample(rtt_ms);
                    }
                    self.cong.on_ack(acked);
                } else if th.ack == self.send.una
                    && self.send.una != self.send.nxt
                    && payload.is_empty()
                {
                    // Duplicate ACK: acknowledges no new data while data is still in flight. The
                    // third in a row triggers fast retransmit — resend the oldest unacked segment
                    // at once, without waiting for the RTO (RFC 5681 §3.2).
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
                return Some(self.segment(self.send.nxt, self.recv.nxt, ACK, &[]));
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
                self.retx.record(self.send.nxt, out.clone(), now_ms);
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
        // Expire TIME_WAIT after 2·MSL so the connection can finally be reaped (RFC 9293).
        const TIME_WAIT_MS: u64 = 2 * 120_000; // 2·MSL, with MSL = 2 minutes
        if self.state == State::TimeWait
            && now_ms.saturating_sub(self.time_wait_ms) >= TIME_WAIT_MS
        {
            self.state = State::Closed;
        }
        let due = self.retx.due(now_ms, self.rtt.rto());
        if !due.is_empty() {
            // The retransmission timer fired — the strongest congestion signal. Collapse cwnd to
            // one segment and re-enter slow start (RFC 5681 §3.1).
            let flight = self.flight_size();
            self.cong.on_timeout(flight);
            self.rtt.back_off(); // double the RTO per timeout (RFC 6298 §5.5 / Karn's backoff)
        }
        due
    }

    /// Bytes sent but not yet acknowledged — the "FlightSize" of RFC 5681 (`SND.NXT − SND.UNA`).
    fn flight_size(&self) -> u32 {
        self.send.nxt.wrapping_sub(self.send.una)
    }

    /// Bytes we may still send right now. Bounded by BOTH the receiver and the network: the
    /// classic `min(SND.WND, cwnd) − FlightSize` (RFC 5681). Saturates at 0 when the window is full.
    pub fn usable_window(&self) -> u32 {
        let limit = (self.send.wnd as u32).min(self.cong.window());
        limit.saturating_sub(self.flight_size())
    }

    /// Application send: queue `data` for transmission. The bytes go out on the next
    /// `poll_transmit`, as fast as the send window allows.
    pub fn write(&mut self, data: &[u8]) {
        self.send_buf.extend(data.iter().copied());
    }

    /// Drain the send buffer into wire segments, bounded by the **usable window**
    /// (`min(SND.WND, cwnd) − FlightSize`) and chopped to the MSS. Each segment advances SND.NXT
    /// and is recorded for retransmission. Returns the segments to send (possibly empty when the
    /// window is full — exactly how slow start throttles a bulk sender, RFC 5681). Valid only once
    /// ESTABLISHED.
    pub fn poll_transmit(&mut self, now_ms: u64) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        if self.state != State::Established {
            return out;
        }
        let mss = crate::congestion::MSS as usize;
        while !self.send_buf.is_empty() {
            let n = (self.usable_window() as usize).min(mss).min(self.send_buf.len());
            if n == 0 {
                break; // window full — wait for an ACK to slide it open
            }
            let payload: Vec<u8> = self.send_buf.drain(..n).collect();
            let seg = self.segment(self.send.nxt, self.recv.nxt, PSH | ACK, &payload);
            self.send.nxt = self.send.nxt.wrapping_add(n as u32);
            self.retx.record(self.send.nxt, seg.clone(), now_ms);
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
    /// which is the peer's window and bounds only how much we may send.
    fn segment(&self, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        build_packet(self.local, self.remote, seq, ack, flags, self.recv.wnd, payload)
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

/// One sent-but-unacknowledged segment, kept so we can resend it if its ACK never comes.
#[derive(Debug, Clone)]
struct Unacked {
    /// One past the last sequence number this segment covers; fully acked when SND.UNA reaches it.
    end_seq: u32,
    /// The complete IP+TCP bytes, ready to resend verbatim.
    packet: Vec<u8>,
    /// When it was (last) sent, in milliseconds — supplied by the caller's clock.
    sent_at_ms: u64,
    /// How many times it's been retransmitted (for backoff / giving up).
    retries: u32,
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
    /// Record a segment we just sent. `end_seq` = seq one past its last byte.
    pub fn record(&mut self, end_seq: u32, packet: Vec<u8>, now_ms: u64) {
        self.segments.push(Unacked { end_seq, packet, sent_at_ms: now_ms, retries: 0 });
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
            if now_ms.saturating_sub(s.sent_at_ms) >= rto_ms {
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
        self.segments.first_mut().map(|s| {
            s.retries += 1;
            s.sent_at_ms = now_ms;
            s.packet.clone()
        })
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
        assert!(Connection::accept(PEER, ME, &th, 0).is_none());
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
        q.record(11, vec![1, 2, 3], 0); // segment ending at seq 11
        q.record(21, vec![4, 5, 6], 0); // segment ending at seq 21
        assert_eq!(q.len(), 2);
        assert_eq!(q.ack(11, 30), Some(30)); // UNA=11 → first acked at t=30 → RTT sample 30
        assert_eq!(q.len(), 1);
        assert_eq!(q.ack(21, 40), Some(40)); // second fully acked → sample 40
        assert!(q.is_empty());
    }

    #[test]
    fn retx_partial_ack_keeps_unacked() {
        let mut q = RetxQueue::default();
        q.record(11, vec![1], 0);
        q.record(21, vec![2], 0);
        q.ack(15, 0); // covers the first (end 11 <= 15), not the second (end 21 > 15)
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn retx_fires_after_rto() {
        let mut q = RetxQueue::default();
        q.record(11, vec![0xAB], 0);
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
        q.record(3, vec![9], 0); // end_seq 3, conceptually after wrapping from ~0xFFFFFFFF
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
}
