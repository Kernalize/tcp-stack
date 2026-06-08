//! TCP congestion control (RFC 5681): slow start, congestion avoidance, fast retransmit/recovery.
//!
//! Flow control (Day 8) caps the sender at what the *receiver* can hold. Congestion control caps
//! it at what the *network* can carry — the receiver's window says nothing about the routers in
//! between. The sender keeps a second window, `cwnd`, and may have at most `min(cwnd, rwnd)` bytes
//! in flight. `cwnd` grows while ACKs flow and collapses on loss: that AIMD feedback (additive
//! increase, multiplicative decrease) is what keeps the whole internet stable and fair.
//!
//! Honest caveat: our echo server never sends in bulk, so `cwnd` won't actually *bind* here — but
//! the state machine below is the real RFC 5681 one and is fully unit-tested. A bulk sender (the
//! socket API, Day 11) would gate transmission on `window()`. Theory: `docs/day10-book.md`.

/// Maximum segment size (bytes). We don't negotiate the MSS option, so we assume a typical
/// Ethernet-sized payload; a real stack learns it from the peer's SYN (RFC 9293 §3.7.1).
pub const MSS: u32 = 1460;

const INIT_SSTHRESH: u32 = 65_535; // "infinite" until the first loss tightens it (RFC 5681 §3.1)
const DUP_ACK_THRESHOLD: u32 = 3; //  3 duplicate ACKs ⇒ fast retransmit (RFC 5681 §3.2)

/// Per-connection congestion state.
#[derive(Debug)]
pub struct CongestionControl {
    cwnd: u32,        // congestion window (bytes)
    ssthresh: u32,    // below it → slow start; at/above it → congestion avoidance
    dup_acks: u32,    // consecutive duplicate ACKs seen
    in_recovery: bool, // inside a fast-recovery episode
}

impl Default for CongestionControl {
    fn default() -> Self {
        // Classic initial window of 1 MSS so slow start's doubling is visible. Modern stacks
        // (RFC 6928) start at 10·MSS.
        Self { cwnd: MSS, ssthresh: INIT_SSTHRESH, dup_acks: 0, in_recovery: false }
    }
}

impl CongestionControl {
    /// Bytes the network will currently let us keep in flight.
    pub fn window(&self) -> u32 {
        self.cwnd
    }

    /// An ACK that acknowledges `acked` NEW bytes. Grows `cwnd` (slow start or congestion
    /// avoidance) and ends any fast-recovery episode.
    pub fn on_ack(&mut self, acked: u32) {
        self.dup_acks = 0;
        if self.in_recovery {
            // Fast recovery complete: deflate the window back to ssthresh (RFC 5681 §3.2 step 6).
            self.in_recovery = false;
            self.cwnd = self.ssthresh;
            return;
        }
        if acked == 0 {
            return;
        }
        if self.cwnd < self.ssthresh {
            // Slow start: +1 MSS per ACK ⇒ ~doubles each RTT (exponential ramp-up).
            self.cwnd = self.cwnd.saturating_add(MSS);
        } else {
            // Congestion avoidance: +MSS²/cwnd per ACK ⇒ ~+1 MSS per RTT (linear — AIMD's "AI").
            self.cwnd = self.cwnd.saturating_add((MSS * MSS / self.cwnd).max(1));
        }
    }

    /// A duplicate ACK (acknowledges no new data while data is outstanding). Returns `true` exactly
    /// on the threshold-th one, when the caller should fast-retransmit the oldest unacked segment.
    pub fn on_dup_ack(&mut self, flight_size: u32) -> bool {
        self.dup_acks += 1;
        if self.dup_acks == DUP_ACK_THRESHOLD {
            // Multiplicative decrease: halve FlightSize, floored at 2·MSS (RFC 5681 §3.2 step 2),
            // then inflate by the three segments that have already left the network (step 3).
            self.ssthresh = (flight_size / 2).max(2 * MSS);
            self.cwnd = self.ssthresh + DUP_ACK_THRESHOLD * MSS;
            self.in_recovery = true;
            return true;
        }
        if self.in_recovery {
            // Each further dup-ACK = another segment drained from the net: inflate (step 4).
            self.cwnd = self.cwnd.saturating_add(MSS);
        }
        false
    }

    /// The retransmission timer fired (RTO) — the strongest congestion signal. Collapse to one
    /// segment and re-enter slow start (RFC 5681 §3.1).
    pub fn on_timeout(&mut self, flight_size: u32) {
        self.ssthresh = (flight_size / 2).max(2 * MSS);
        self.cwnd = MSS;
        self.dup_acks = 0;
        self.in_recovery = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_in_slow_start_at_one_mss() {
        assert_eq!(CongestionControl::default().window(), MSS);
    }

    #[test]
    fn slow_start_adds_one_mss_per_ack() {
        let mut c = CongestionControl::default();
        c.on_ack(MSS); // 1460 → 2920
        assert_eq!(c.window(), 2 * MSS);
        c.on_ack(MSS); // 2920 → 4380
        assert_eq!(c.window(), 3 * MSS);
    }

    #[test]
    fn three_dup_acks_trigger_fast_retransmit() {
        let mut c = CongestionControl::default();
        let flight = 10 * MSS; // 14600
        assert!(!c.on_dup_ack(flight)); // 1st
        assert!(!c.on_dup_ack(flight)); // 2nd
        assert!(c.on_dup_ack(flight)); // 3rd → fast retransmit
        // ssthresh = 14600/2 = 7300 = 5·MSS; cwnd = ssthresh + 3·MSS = 8·MSS.
        assert_eq!(c.window(), 8 * MSS);
    }

    #[test]
    fn extra_dup_acks_inflate_during_recovery() {
        let mut c = CongestionControl::default();
        let flight = 10 * MSS;
        c.on_dup_ack(flight);
        c.on_dup_ack(flight);
        c.on_dup_ack(flight); // enter recovery, cwnd = 8·MSS
        assert!(!c.on_dup_ack(flight)); // 4th inflates by 1 MSS
        assert_eq!(c.window(), 9 * MSS);
    }

    #[test]
    fn new_ack_deflates_out_of_recovery() {
        let mut c = CongestionControl::default();
        let flight = 10 * MSS;
        c.on_dup_ack(flight);
        c.on_dup_ack(flight);
        c.on_dup_ack(flight); // recovery, ssthresh = 5·MSS, cwnd = 8·MSS
        c.on_ack(MSS); // new data acked → deflate to ssthresh
        assert_eq!(c.window(), 5 * MSS);
    }

    #[test]
    fn congestion_avoidance_grows_sub_linearly() {
        let mut c = CongestionControl::default();
        let flight = 10 * MSS;
        c.on_dup_ack(flight);
        c.on_dup_ack(flight);
        c.on_dup_ack(flight);
        c.on_ack(MSS); // cwnd = ssthresh = 5·MSS (7300); now cwnd == ssthresh → CA
        let before = c.window();
        c.on_ack(MSS); // +MSS²/cwnd ≈ +292, far less than a full MSS
        let grew = c.window() - before;
        assert!(grew > 0 && grew < MSS, "CA grew by {grew}, expected 0 < grew < {MSS}");
    }

    #[test]
    fn timeout_collapses_to_one_mss_and_slow_start() {
        let mut c = CongestionControl::default();
        for _ in 0..5 {
            c.on_ack(MSS); // ramp cwnd up in slow start
        }
        c.on_timeout(6 * MSS); // RTO → cwnd = 1 MSS, ssthresh = 3·MSS
        assert_eq!(c.window(), MSS);
        // Back in slow start (cwnd < ssthresh): the next ACK adds a full MSS again.
        c.on_ack(MSS);
        assert_eq!(c.window(), 2 * MSS);
    }
}
