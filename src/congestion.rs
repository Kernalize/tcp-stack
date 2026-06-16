//! TCP congestion control: slow start, fast retransmit/recovery (RFC 5681), NewReno partial-ACK
//! recovery (RFC 6582, Day 20), and **CUBIC** congestion avoidance (RFC 8312/9438, Day 25).
//!
//! Flow control (Day 8) caps the sender at what the *receiver* can hold. Congestion control caps
//! it at what the *network* can carry — the receiver's window says nothing about the routers in
//! between. The sender keeps a second window, `cwnd`, and may have at most `min(cwnd, rwnd)` bytes
//! in flight. `cwnd` grows while ACKs flow and collapses on loss.
//!
//! Day 25 replaces Reno's *linear* congestion-avoidance increase (+1 MSS/RTT) with **CUBIC**: after
//! a loss, `cwnd` follows a cubic curve in *time* — `W(t) = C·(t − K)³ + W_max` — that climbs back
//! quickly toward the pre-loss window `W_max`, flattens (the concave "plateau") around it to probe
//! gently, then accelerates past it (the convex region) to find new bandwidth. On high
//! bandwidth-delay-product links this fills the pipe far faster than Reno's slope, while staying
//! gentle near the last known-safe point. The multiplicative decrease softens from Reno's ½ to
//! CUBIC's β = 0.7, so a single loss costs less window.
//!
//! Honest caveat: our echo server never sends in bulk, so `cwnd` won't actually *bind* here — but
//! the machinery below is real and fully unit-tested with a simulated clock. Theory: `docs/day10-book.md`
//! (Reno) and `docs/day25-book.md` (CUBIC).
//!
//! [`CongestionControl`] is an enum dispatching to one of two controllers: the loss-based **CUBIC**
//! ([`Cubic`], the default, here) or the model-based **BBR** ([`crate::bbr::Bbr`]). A connection
//! calls the same six methods regardless; `default()` is CUBIC and `CongestionControl::bbr()` opts
//! into BBR (a real stack chooses per-socket via sysctl / `setsockopt`).

use crate::bbr::Bbr;

/// Maximum segment size (bytes). We don't negotiate the MSS option, so we assume a typical
/// Ethernet-sized payload; a real stack learns it from the peer's SYN (RFC 9293 §3.7.1).
pub const MSS: u32 = 1460;

const INIT_SSTHRESH: u32 = 65_535; // "infinite" until the first loss tightens it (RFC 5681 §3.1)
const DUP_ACK_THRESHOLD: u32 = 3; //  3 duplicate ACKs ⇒ fast retransmit (RFC 5681 §3.2)

// Day 25 — CUBIC constants (RFC 9438). β is the multiplicative-decrease factor (kept as an integer
// fraction so `ssthresh` stays deterministic); C scales the cubic growth in time.
const CUBIC_BETA_NUM: u32 = 7; //  β = 0.7 (Reno uses 0.5) — a single loss costs 30% of cwnd, not 50%
const CUBIC_BETA_DEN: u32 = 10;
const CUBIC_C: f64 = 0.4; //       the cubic scaling constant (RFC 9438 §4.1)

/// Per-connection **CUBIC/Reno** state — the loss-based controller, and the `CongestionControl`
/// default; the model-based alternative is [`crate::bbr::Bbr`].
#[derive(Debug)]
pub struct Cubic {
    cwnd: u32,         // congestion window (bytes)
    ssthresh: u32,     // below it → slow start; at/above it → congestion avoidance (CUBIC)
    dup_acks: u32,     // consecutive duplicate ACKs seen
    in_recovery: bool, // inside a fast-recovery episode
    // Day 25 (CUBIC):
    w_max: u32,        // cwnd at the last reduction — the inflection point the curve aims back at
    epoch_ms: u64,     // start of the current CUBIC epoch (0 = no CA epoch in progress yet)
}

impl Default for Cubic {
    fn default() -> Self {
        // Classic initial window of 1 MSS so slow start's doubling is visible. Modern stacks
        // (RFC 6928) start at 10·MSS.
        Self { cwnd: MSS, ssthresh: INIT_SSTHRESH, dup_acks: 0, in_recovery: false, w_max: 0, epoch_ms: 0 }
    }
}

impl Cubic {
    /// Bytes the network will currently let us keep in flight.
    pub fn window(&self) -> u32 {
        self.cwnd
    }

    /// An ACK that acknowledges `acked` NEW bytes, at time `now_ms`. Grows `cwnd` (slow start or
    /// CUBIC congestion avoidance) and ends any fast-recovery episode. `now_ms` drives CUBIC's
    /// time-based curve (Day 25); it is ignored in slow start and on the recovery-exit path.
    pub fn on_ack(&mut self, acked: u32, now_ms: u64) {
        self.dup_acks = 0;
        if self.in_recovery {
            // Fast recovery complete: deflate the window back to ssthresh (RFC 5681 §3.2 step 6).
            // A fresh CUBIC epoch begins on the next ACK (epoch reset so K/W_max are recomputed).
            self.in_recovery = false;
            self.cwnd = self.ssthresh;
            self.epoch_ms = 0;
            return;
        }
        if acked == 0 {
            return;
        }
        if self.cwnd < self.ssthresh {
            // Slow start: +1 MSS per ACK ⇒ ~doubles each RTT (exponential ramp-up). Unchanged.
            self.cwnd = self.cwnd.saturating_add(MSS);
        } else {
            // Day 25 — CUBIC congestion avoidance. Start a new epoch on the first CA ACK after a
            // loss (or after slow start), anchoring W_max at the current cwnd if no recent loss set
            // a higher one.
            if self.epoch_ms == 0 {
                self.epoch_ms = now_ms;
                if self.w_max < self.cwnd {
                    self.w_max = self.cwnd;
                }
            }
            let target = self.cubic_target(now_ms);
            if target > self.cwnd {
                // Climb toward the cubic target, spread over ~one RTT (≈ cwnd/MSS ACKs per RTT), so
                // the per-ACK step approaches `target` smoothly rather than jumping.
                let acks_per_rtt = (self.cwnd / MSS).max(1);
                self.cwnd = self.cwnd.saturating_add(((target - self.cwnd) / acks_per_rtt).max(1));
            } else {
                // At/above the cubic target (the concave plateau around W_max): creep up like Reno,
                // +MSS²/cwnd per ACK ⇒ ~+1 MSS/RTT, so we keep probing gently for more bandwidth.
                self.cwnd = self.cwnd.saturating_add((MSS * MSS / self.cwnd).max(1));
            }
        }
    }

    /// Day 25 — the CUBIC window for the current epoch at time `now_ms` (bytes):
    /// `W(t) = C·(t − K)³ + W_max`, where `K = ∛(W_max·(1 − β) / C)` is the time to climb back to
    /// `W_max`, and `t` is seconds since the epoch began. Below K the curve is concave (fast early
    /// recovery, then a gentle plateau under W_max); above K it is convex (probing past W_max).
    fn cubic_target(&self, now_ms: u64) -> u32 {
        let w_max = self.w_max as f64 / MSS as f64; // in MSS units, as RFC 9438 defines the curve
        let beta = CUBIC_BETA_NUM as f64 / CUBIC_BETA_DEN as f64;
        let k = (w_max * (1.0 - beta) / CUBIC_C).cbrt(); // seconds to regain W_max
        let t = now_ms.saturating_sub(self.epoch_ms) as f64 / 1000.0;
        let w = CUBIC_C * (t - k).powi(3) + w_max; // MSS units
        (w.max(1.0) * MSS as f64) as u32
    }

    /// A duplicate ACK (acknowledges no new data while data is outstanding). Returns `true` exactly
    /// on the threshold-th one, when the caller should fast-retransmit the oldest unacked segment.
    /// Day 25: the multiplicative decrease is CUBIC's `cwnd·β` (β = 0.7), anchoring `W_max` at the
    /// pre-loss window so the cubic curve can aim the recovery back at it.
    pub fn on_dup_ack(&mut self, _flight: u32) -> bool {
        self.dup_acks += 1;
        if self.dup_acks == DUP_ACK_THRESHOLD {
            self.w_max = self.cwnd; // CUBIC inflection point: where the curve will aim back to
            self.ssthresh = (self.cwnd * CUBIC_BETA_NUM / CUBIC_BETA_DEN).max(2 * MSS);
            self.cwnd = self.ssthresh + DUP_ACK_THRESHOLD * MSS; // inflate by the 3 segments that left
            self.epoch_ms = 0;
            self.in_recovery = true;
            return true;
        }
        if self.in_recovery {
            // Each further dup-ACK = another segment drained from the net: inflate (RFC 5681 step 4).
            self.cwnd = self.cwnd.saturating_add(MSS);
        }
        false
    }

    /// The retransmission timer fired (RTO) — the strongest congestion signal. Collapse to one
    /// segment and re-enter slow start (RFC 5681 §3.1). Day 25: `ssthresh` uses CUBIC's β, and
    /// `W_max` records the window we fell from so the curve can climb back after slow start.
    pub fn on_timeout(&mut self, _flight: u32) {
        self.w_max = self.cwnd;
        self.ssthresh = (self.cwnd * CUBIC_BETA_NUM / CUBIC_BETA_DEN).max(2 * MSS);
        self.cwnd = MSS;
        self.dup_acks = 0;
        self.in_recovery = false;
        self.epoch_ms = 0;
    }

    /// Day 20 — are we inside a fast-recovery episode? NewReno (RFC 6582) needs this to route an
    /// incoming ACK: during recovery a *partial* ACK is handled specially (see `on_partial_ack`),
    /// while outside recovery an ACK grows the window normally (`on_ack`).
    pub fn in_recovery(&self) -> bool {
        self.in_recovery
    }

    /// Day 20 — NewReno **partial ACK** (RFC 6582 §3). During fast recovery, an ACK advanced
    /// SND.UNA but did *not* reach `recover` (the SND.NXT at recovery start), so at least one more
    /// segment in that window was also lost. Deflate `cwnd` by the `acked` bytes (they left the
    /// network) and add back one MSS for the segment the ACK just freed, then **stay in recovery** —
    /// the caller retransmits the next hole.
    pub fn on_partial_ack(&mut self, acked: u32) {
        self.dup_acks = 0;
        self.cwnd = self.cwnd.saturating_sub(acked).saturating_add(MSS).max(MSS);
    }
}

/// The congestion controller a connection uses: loss-based **CUBIC/Reno** ([`Cubic`], the default)
/// or model-based **BBR** ([`Bbr`]). The connection drives the same six methods either way and this
/// enum forwards to the active arm — so swapping algorithms touches nothing in `tcp.rs`.
#[derive(Debug)]
pub enum CongestionControl {
    Cubic(Cubic),
    Bbr(Bbr),
}

impl Default for CongestionControl {
    /// CUBIC/Reno, to match every connection's historical behaviour.
    fn default() -> Self {
        CongestionControl::Cubic(Cubic::default())
    }
}

impl CongestionControl {
    /// Opt into model-based **BBR** congestion control (`src/bbr.rs`).
    pub fn bbr() -> Self {
        CongestionControl::Bbr(Bbr::new())
    }

    /// Bytes the network will currently let us keep in flight (`min(cwnd, rwnd)` is applied by the
    /// connection).
    pub fn window(&self) -> u32 {
        match self {
            CongestionControl::Cubic(c) => c.window(),
            CongestionControl::Bbr(b) => b.window(),
        }
    }

    /// An ACK acknowledging `acked` new bytes, with RTT sample `rtt_ms` when one was measured, at
    /// `now_ms`. CUBIC ignores `rtt_ms` (its curve is time-based); BBR feeds it into RTprop/BDP.
    pub fn on_ack(&mut self, acked: u32, rtt_ms: Option<u64>, now_ms: u64) {
        match self {
            CongestionControl::Cubic(c) => c.on_ack(acked, now_ms),
            CongestionControl::Bbr(b) => b.on_ack(acked, rtt_ms, now_ms),
        }
    }

    /// A duplicate ACK; returns `true` on the threshold-th one so the caller fast-retransmits. BBR
    /// returns `true` likewise but, unlike CUBIC, does not shrink the window.
    pub fn on_dup_ack(&mut self, flight: u32) -> bool {
        match self {
            CongestionControl::Cubic(c) => c.on_dup_ack(flight),
            CongestionControl::Bbr(b) => b.on_dup_ack(),
        }
    }

    /// NewReno partial-ACK handling during fast recovery — CUBIC only; BBR has no Reno recovery
    /// episode (`in_recovery()` is always false), so this is a no-op under BBR.
    pub fn on_partial_ack(&mut self, acked: u32) {
        if let CongestionControl::Cubic(c) = self {
            c.on_partial_ack(acked);
        }
    }

    /// The retransmission timer fired — the strongest congestion signal.
    pub fn on_timeout(&mut self, flight: u32) {
        match self {
            CongestionControl::Cubic(c) => c.on_timeout(flight),
            CongestionControl::Bbr(b) => b.on_timeout(),
        }
    }

    /// Are we inside a fast-recovery episode? (Always false under BBR — loss isn't its signal.)
    pub fn in_recovery(&self) -> bool {
        match self {
            CongestionControl::Cubic(c) => c.in_recovery(),
            CongestionControl::Bbr(b) => b.in_recovery(),
        }
    }

    /// The paced send rate (bytes/sec): BBR's model output, `0.0` for the window-only CUBIC arm.
    pub fn pacing_rate_bps(&self) -> f64 {
        match self {
            CongestionControl::Cubic(_) => 0.0,
            CongestionControl::Bbr(b) => b.pacing_rate_bps(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Grow `cwnd` to `n`·MSS through slow start (each ACK adds one MSS from the 1·MSS default).
    fn grow_to(c: &mut Cubic, n: u32) {
        for _ in 0..(n - 1) {
            c.on_ack(MSS, 0);
        }
        assert_eq!(c.window(), n * MSS);
    }

    #[test]
    fn starts_in_slow_start_at_one_mss() {
        assert_eq!(Cubic::default().window(), MSS);
    }

    #[test]
    fn slow_start_adds_one_mss_per_ack() {
        let mut c = Cubic::default();
        c.on_ack(MSS, 0); // 1460 → 2920
        assert_eq!(c.window(), 2 * MSS);
        c.on_ack(MSS, 0); // 2920 → 4380
        assert_eq!(c.window(), 3 * MSS);
    }

    #[test]
    fn cubic_reduces_cwnd_by_beta_on_three_dup_acks() {
        let mut c = Cubic::default();
        grow_to(&mut c, 10); // cwnd = 10·MSS
        assert!(!c.on_dup_ack(0)); // 1st
        assert!(!c.on_dup_ack(0)); // 2nd
        assert!(c.on_dup_ack(0)); // 3rd → fast retransmit
        // CUBIC β = 0.7: ssthresh = 10·MSS·0.7 = 7·MSS; cwnd = ssthresh + 3·MSS = 10·MSS.
        assert_eq!(c.window(), 10 * MSS);
    }

    #[test]
    fn extra_dup_acks_inflate_during_recovery() {
        let mut c = Cubic::default();
        grow_to(&mut c, 10);
        c.on_dup_ack(0);
        c.on_dup_ack(0);
        c.on_dup_ack(0); // enter recovery, cwnd = 10·MSS
        assert!(!c.on_dup_ack(0)); // 4th inflates by 1 MSS
        assert_eq!(c.window(), 11 * MSS);
    }

    #[test]
    fn new_ack_deflates_out_of_recovery_to_ssthresh() {
        let mut c = Cubic::default();
        grow_to(&mut c, 10);
        c.on_dup_ack(0);
        c.on_dup_ack(0);
        c.on_dup_ack(0); // recovery: ssthresh = 7·MSS, cwnd = 10·MSS
        c.on_ack(MSS, 1000); // new data acked → deflate to ssthresh
        assert_eq!(c.window(), 7 * MSS);
    }

    #[test]
    fn reports_recovery_state() {
        let mut c = Cubic::default();
        assert!(!c.in_recovery());
        c.on_dup_ack(0);
        c.on_dup_ack(0);
        c.on_dup_ack(0); // 3rd dup ACK → enter fast recovery
        assert!(c.in_recovery());
        c.on_ack(MSS, 1000); // a full ACK ends recovery (the on_ack deflate path)
        assert!(!c.in_recovery());
    }

    #[test]
    fn newreno_partial_ack_deflates_and_stays_in_recovery() {
        let mut c = Cubic::default();
        grow_to(&mut c, 10);
        c.on_dup_ack(0);
        c.on_dup_ack(0);
        c.on_dup_ack(0); // recovery: ssthresh = 7·MSS, cwnd = 10·MSS
        assert_eq!(c.window(), 10 * MSS);
        // A partial ACK for one MSS: cwnd −= MSS then += MSS ⇒ unchanged, and we stay in recovery.
        c.on_partial_ack(MSS);
        assert_eq!(c.window(), 10 * MSS);
        assert!(c.in_recovery());
        // A partial ACK for two MSS: cwnd = 10·MSS − 2·MSS + MSS = 9·MSS, still in recovery.
        c.on_partial_ack(2 * MSS);
        assert_eq!(c.window(), 9 * MSS);
        assert!(c.in_recovery());
    }

    #[test]
    fn cubic_recovers_toward_and_past_w_max() {
        let mut c = Cubic::default();
        grow_to(&mut c, 10); // cwnd = 10·MSS
        c.on_dup_ack(0);
        c.on_dup_ack(0);
        c.on_dup_ack(0); // loss: W_max = 10·MSS, ssthresh = 7·MSS
        c.on_ack(MSS, 1000); // exit recovery → cwnd = ssthresh = 7·MSS, CUBIC CA begins
        let early = c.window();
        assert_eq!(early, 7 * MSS);
        // Drive CA ACKs across several seconds of simulated time: the cubic curve climbs back to
        // W_max (the concave region) and then probes past it (the convex region).
        let mut t = 1000u64;
        for _ in 0..200 {
            t += 25;
            c.on_ack(MSS, t);
        }
        let late = c.window();
        assert!(late > early, "CUBIC grew the window during congestion avoidance");
        assert!(late >= 10 * MSS, "CUBIC probes back to/past W_max (got {} MSS)", late / MSS);
    }

    #[test]
    fn timeout_collapses_to_one_mss_and_slow_start() {
        let mut c = Cubic::default();
        grow_to(&mut c, 6); // cwnd = 6·MSS
        c.on_timeout(0); // RTO → cwnd = 1·MSS, ssthresh = 6·MSS·0.7 ≈ 4·MSS
        assert_eq!(c.window(), MSS);
        // Back in slow start (cwnd < ssthresh): the next ACK adds a full MSS again.
        c.on_ack(MSS, 100);
        assert_eq!(c.window(), 2 * MSS);
    }

    // ── The CongestionControl enum: algorithm selection + dispatch ──

    #[test]
    fn default_dispatches_to_cubic() {
        // The default controller behaves exactly like Cubic (slow start adds one MSS per ACK).
        let mut cc = CongestionControl::default();
        assert!(matches!(cc, CongestionControl::Cubic(_)));
        assert_eq!(cc.window(), MSS);
        cc.on_ack(MSS, None, 0);
        assert_eq!(cc.window(), 2 * MSS);
        assert_eq!(cc.pacing_rate_bps(), 0.0); // window-only controller has no pacing rate
    }

    #[test]
    fn bbr_is_selectable_and_dispatches_to_bbr() {
        let mut cc = CongestionControl::bbr();
        assert!(matches!(cc, CongestionControl::Bbr(_)));
        assert!(!cc.in_recovery()); // BBR never enters Reno recovery
        // Drive a few rate samples; BBR learns a bandwidth and exposes a non-zero pacing rate.
        let mut t = 0u64;
        for _ in 0..6 {
            t += 10;
            cc.on_ack(10 * MSS, Some(10), t);
        }
        assert!(cc.window() >= 4 * MSS);
        assert!(cc.pacing_rate_bps() > 0.0, "BBR paces at gain·BtlBw");
    }
}
