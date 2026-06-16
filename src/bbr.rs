//! **BBR** — Bottleneck Bandwidth and Round-trip propagation time (Cardwell et al., ACM Queue 2016;
//! draft-cardwell-iccrg-bbr-congestion-control). The model-based alternative to the loss-based
//! family in `src/congestion.rs` (Reno / CUBIC).
//!
//! Loss-based control treats a *dropped packet* as the congestion signal: it fills the bottleneck
//! queue until a router drops, then backs off. On deep buffers ("bufferbloat") that means it runs
//! with a queue permanently full — high throughput but terrible latency — and on shallow buffers a
//! single random loss needlessly halves the window. BBR ignores loss as a signal. It builds an
//! explicit *model* of the path from two measured quantities and paces to sit exactly at the knee of
//! the throughput/latency curve:
//!
//!   * **BtlBw** — the bottleneck bandwidth: the *maximum* delivery rate observed, taken over a
//!     sliding window of recent round trips (a windowed-max filter, so a transient dip doesn't lower
//!     the estimate).
//!   * **RTprop** — the round-trip propagation delay: the *minimum* RTT observed over a longer
//!     window (a windowed-min filter, so standing queue can't inflate it).
//!
//! Their product is the **bandwidth-delay product** `BDP = BtlBw · RTprop` — the exact amount of
//! data needed to keep the pipe full with *no* queue. BBR paces at `pacing_gain · BtlBw` and caps
//! inflight at `cwnd_gain · BDP`. A small state machine probes both quantities, because you cannot
//! measure max-bandwidth and min-RTT at the same instant (filling the pipe to measure bandwidth
//! creates queue that hides the true RTT):
//!
//! ```text
//!   STARTUP  ── exponential ramp (gain 2/ln2 ≈ 2.89) until bandwidth plateaus ──▶ DRAIN
//!   DRAIN    ── pace below 1× to drain the queue STARTUP just built ───────────▶ PROBE_BW
//!   PROBE_BW ── steady state: cycle pacing_gain [1.25, 0.75, 1,1,1,1,1,1] per RTT,
//!               briefly probing for more bandwidth then giving the queue back ──▶ (loops)
//!   PROBE_RTT── every 10 s, drop to 4 packets for ~200 ms to re-measure RTprop ▶ back to PROBE_BW
//! ```
//!
//! This is a faithful, teaching-grade BBRv1: the filters, the four states, and the gain schedule are
//! the real thing, driven by a simulated millisecond clock so the whole module is deterministic and
//! unit-tested offline. The simplifications versus a production kernel implementation (per-packet
//! `delivered`/`delivered_time` rate samples, app-limited detection, the exact DRAIN/PROBE_RTT exit
//! conditions on inflight) are called out at each site. Like CUBIC here, BBR's window won't actually
//! *bind* on our echo server (it never sends in bulk) — but the model below is real.

use std::collections::VecDeque;

use crate::congestion::MSS;

// ── Gains (draft-cardwell §4.2). pacing_gain scales the send *rate*; cwnd_gain scales the inflight
// *cap*. The startup gain 2/ln2 is the smallest constant that doubles delivery rate each round. ──
const HIGH_GAIN: f64 = 2.885_390_081_777_927; //   2/ln(2): STARTUP pacing & cwnd gain
const DRAIN_GAIN: f64 = 1.0 / HIGH_GAIN; //         ln(2)/2 ≈ 0.346: DRAIN pacing gain (undo STARTUP)
const CWND_GAIN: f64 = 2.0; //                      PROBE_BW inflight cap = 2·BDP (tolerate delayed ACKs)
/// PROBE_BW pacing-gain cycle: one phase per round trip. 1.25 probes for more bandwidth (builds a
/// little queue); 0.75 gives it back (drains what 1.25 added); the six 1.0 phases cruise at the
/// estimated rate. The net over a cycle is ≈ 1.0, so the standing queue stays near zero.
const PROBE_BW_GAINS: [f64; 8] = [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];

const BW_WINDOW_ROUNDS: u64 = 10; //   BtlBw windowed-max length (round trips), draft §4.1.1
const RTPROP_WINDOW_MS: u64 = 10_000; // RTprop windowed-min length: re-probe min-RTT every 10 s
const PROBE_RTT_DURATION_MS: u64 = 200; // hold the reduced cwnd long enough to drain & measure
const MIN_PIPE_CWND: u32 = 4 * MSS; //  floor: never throttle below 4 segments (and PROBE_RTT target)
const FULL_BW_THRESH: f64 = 1.25; //   STARTUP "pipe full" when bandwidth grows < 25% for…
const FULL_BW_COUNT: u32 = 3; //       …3 rounds in a row (draft §4.3.2.2)
const DUP_ACK_THRESHOLD: u32 = 3; //   still fast-retransmit on 3 dup-ACKs — BBR just doesn't cut cwnd

/// The four BBR states. `Startup`/`Drain` happen once at connection start; `ProbeBw` is the steady
/// state; `ProbeRtt` is visited briefly (~200 ms) every 10 s from `ProbeBw`/`Drain`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Startup,
    Drain,
    ProbeBw,
    ProbeRtt,
}

/// A sliding-window **maximum** filter over (time, value) samples, kept as a monotonically
/// decreasing deque: the front is always the window's max. Used for BtlBw (time = round count) so a
/// brief delivery-rate dip can't lower the bandwidth estimate, yet a stale high sample eventually
/// expires once it falls out of the window.
#[derive(Debug, Default)]
struct WindowedMax {
    window: u64,
    dq: VecDeque<(u64, f64)>,
}

impl WindowedMax {
    fn new(window: u64) -> Self {
        Self { window, dq: VecDeque::new() }
    }

    fn update(&mut self, t: u64, v: f64) {
        // Drop tail samples no larger than `v`: they can never be the max while `v` is in window.
        while let Some(&(_, back)) = self.dq.back() {
            if back <= v {
                self.dq.pop_back();
            } else {
                break;
            }
        }
        self.dq.push_back((t, v));
        // Expire stale samples off the front.
        while let Some(&(ft, _)) = self.dq.front() {
            if t.saturating_sub(ft) > self.window {
                self.dq.pop_front();
            } else {
                break;
            }
        }
    }

    fn get(&self) -> f64 {
        self.dq.front().map(|&(_, v)| v).unwrap_or(0.0)
    }
}

/// Per-connection BBR state. Exposes the same shape the connection needs (`window`, `on_ack`,
/// `on_dup_ack`, `on_timeout`) plus BBR-specific `pacing_rate_bps` / `mode` for inspection & tests.
#[derive(Debug)]
pub struct Bbr {
    mode: Mode,
    cwnd: u32,            // inflight cap (bytes) the connection reads via `window()`
    pacing_gain: f64,     // current send-rate multiplier (for `pacing_rate_bps`)
    cwnd_gain: f64,       // current inflight-cap multiplier

    bw_filter: WindowedMax, // BtlBw: windowed-max delivery rate (bytes/sec), keyed by round count
    rtprop_ms: u64,         // RTprop: windowed-min RTT (ms); u64::MAX until the first sample
    rtprop_stamp_ms: u64,   // when RTprop was last refreshed (drives the 10 s PROBE_RTT trigger)

    delivered_time_ms: u64, // time of the most recent delivery (for the rate-sample interval)
    has_delivery: bool,     // false until the first ACK seeds delivered_time

    round_count: u64,       // round-trip counter; the BtlBw filter and gain cycling key off it
    round_stamp_ms: u64,    // start time of the current round (a round ≈ one RTprop)

    full_bw: f64,           // bandwidth at the last STARTUP plateau check
    full_bw_count: u32,     // consecutive rounds with < 25% growth
    filled_pipe: bool,      // STARTUP done — the pipe is full

    cycle_index: usize,     // PROBE_BW gain-cycle phase (0..8)
    probe_rtt_done_ms: u64, // when the current PROBE_RTT episode may end (0 = not probing)

    dup_acks: u32,          // consecutive duplicate ACKs (for fast-retransmit triggering only)
}

impl Default for Bbr {
    fn default() -> Self {
        Self {
            mode: Mode::Startup,
            cwnd: MIN_PIPE_CWND,
            pacing_gain: HIGH_GAIN,
            cwnd_gain: HIGH_GAIN,
            bw_filter: WindowedMax::new(BW_WINDOW_ROUNDS),
            rtprop_ms: u64::MAX,
            rtprop_stamp_ms: 0,
            delivered_time_ms: 0,
            has_delivery: false,
            round_count: 0,
            round_stamp_ms: 0,
            full_bw: 0.0,
            full_bw_count: 0,
            filled_pipe: false,
            cycle_index: 0,
            probe_rtt_done_ms: 0,
            dup_acks: 0,
        }
    }
}

impl Bbr {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bytes the model will currently let us keep in flight (`cwnd_gain · BDP`, floored). The
    /// connection reads this exactly like CUBIC's `window()`.
    pub fn window(&self) -> u32 {
        self.cwnd
    }

    /// The current paced send rate in bytes/sec (`pacing_gain · BtlBw`). Not yet enforced by the
    /// connection (which is window-, not rate-, limited), but it is the heart of BBR and is tested.
    pub fn pacing_rate_bps(&self) -> f64 {
        self.pacing_gain * self.bw_filter.get()
    }

    /// The current state-machine mode (inspection only — used by the tests).
    #[cfg(test)]
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// The current BtlBw estimate (bytes/sec) — inspection only.
    #[cfg(test)]
    pub fn btlbw_bps(&self) -> f64 {
        self.bw_filter.get()
    }

    /// The current pacing gain — inspection only.
    #[cfg(test)]
    pub fn pacing_gain(&self) -> f64 {
        self.pacing_gain
    }

    /// BBR never enters Reno-style fast recovery — loss isn't its signal — so the connection's
    /// NewReno/SACK recovery paths stay dormant under BBR (retransmission still happens via the
    /// dup-ACK fast retransmit, RACK-TLP, and the RTO).
    pub fn in_recovery(&self) -> bool {
        false
    }

    /// An ACK acknowledging `acked` NEW bytes, carrying RTT sample `rtt_ms` (when one was measured),
    /// at `now_ms`. Updates the delivery-rate and min-RTT models, advances the round counter and the
    /// state machine, and recomputes `cwnd`/`pacing_gain`.
    pub fn on_ack(&mut self, acked: u32, rtt_ms: Option<u64>, now_ms: u64) {
        self.dup_acks = 0;

        // 1. RTprop: a windowed-min RTT. Compute the 10 s expiry ONCE — it both gates the update and
        //    triggers PROBE_RTT below (refreshing the stamp here would otherwise hide the expiry).
        let rtprop_expired = now_ms.saturating_sub(self.rtprop_stamp_ms) > RTPROP_WINDOW_MS;
        if let Some(r) = rtt_ms {
            // Adopt the sample if it's a new minimum, or if the current estimate has aged out of the
            // window (so a path that genuinely slowed is re-learned).
            if r <= self.rtprop_ms || rtprop_expired || self.rtprop_ms == u64::MAX {
                self.rtprop_ms = r;
                self.rtprop_stamp_ms = now_ms;
            }
        }

        // 2. Round counting. A round ≈ one RTprop of wall time; the BtlBw window and PROBE_BW gain
        //    cycle are measured in rounds. (Production BBR ends a round when the byte sent at the
        //    round's start is acked; we approximate with time, which the simulated clock makes exact.)
        let rtt_for_round = if self.rtprop_ms == u64::MAX { 1 } else { self.rtprop_ms.max(1) };
        let mut round_start = false;
        if now_ms.saturating_sub(self.round_stamp_ms) >= rtt_for_round {
            self.round_count += 1;
            self.round_stamp_ms = now_ms;
            round_start = true;
        }

        // 3. Delivery-rate sample → BtlBw windowed-max. The first ACK only seeds the interval.
        if self.has_delivery {
            let interval_ms = now_ms.saturating_sub(self.delivered_time_ms);
            if interval_ms > 0 && acked > 0 {
                let rate_bps = acked as f64 * 1000.0 / interval_ms as f64; // bytes/sec
                self.bw_filter.update(self.round_count, rate_bps);
            }
        } else {
            self.has_delivery = true;
        }
        self.delivered_time_ms = now_ms;

        // 4. Drive the state machine, then recompute the window from the refreshed model.
        self.update_model(round_start, rtprop_expired, now_ms);
        self.recompute_cwnd();
    }

    /// State transitions (draft §4.3). Called once per ACK; `round_start` gates the per-round logic
    /// and `rtprop_expired` (the min-RTT window aged out) triggers PROBE_RTT.
    fn update_model(&mut self, round_start: bool, rtprop_expired: bool, now_ms: u64) {
        let btlbw = self.bw_filter.get();

        match self.mode {
            Mode::Startup => {
                self.pacing_gain = HIGH_GAIN;
                self.cwnd_gain = HIGH_GAIN;
                if round_start {
                    // "Pipe full" when BtlBw stops growing ≥ 25% for FULL_BW_COUNT rounds.
                    if btlbw >= self.full_bw * FULL_BW_THRESH {
                        self.full_bw = btlbw;
                        self.full_bw_count = 0;
                    } else {
                        self.full_bw_count += 1;
                        if self.full_bw_count >= FULL_BW_COUNT {
                            self.filled_pipe = true;
                            self.mode = Mode::Drain;
                        }
                    }
                }
            }
            Mode::Drain => {
                // Pace below 1× to drain the queue STARTUP built. Production exits when inflight ≤ BDP;
                // we exit on the next round boundary (one RTprop of draining), which is enough here.
                self.pacing_gain = DRAIN_GAIN;
                self.cwnd_gain = HIGH_GAIN;
                if round_start {
                    self.enter_probe_bw();
                }
            }
            Mode::ProbeBw => {
                self.cwnd_gain = CWND_GAIN;
                if round_start {
                    self.cycle_index = (self.cycle_index + 1) % PROBE_BW_GAINS.len();
                }
                self.pacing_gain = PROBE_BW_GAINS[self.cycle_index];
                self.maybe_enter_probe_rtt(rtprop_expired, now_ms);
            }
            Mode::ProbeRtt => {
                // Hold cwnd at MIN_PIPE_CWND (4 packets) so the queue drains and the next RTT samples
                // reveal the true RTprop; then resume steady state.
                self.pacing_gain = 1.0;
                self.cwnd_gain = 1.0;
                if now_ms >= self.probe_rtt_done_ms {
                    self.rtprop_stamp_ms = now_ms; // we just re-measured the min RTT
                    self.probe_rtt_done_ms = 0;
                    if self.filled_pipe {
                        self.enter_probe_bw();
                    } else {
                        self.mode = Mode::Startup;
                    }
                }
            }
        }
    }

    fn enter_probe_bw(&mut self) {
        self.mode = Mode::ProbeBw;
        self.cwnd_gain = CWND_GAIN;
        // Start one phase past the 1.25 probe so steady state doesn't open with an immediate burst.
        self.cycle_index = 2;
        self.pacing_gain = PROBE_BW_GAINS[self.cycle_index];
    }

    /// Enter PROBE_RTT once the min-RTT window has aged out (no new RTprop minimum for 10 s).
    fn maybe_enter_probe_rtt(&mut self, rtprop_expired: bool, now_ms: u64) {
        if rtprop_expired {
            self.mode = Mode::ProbeRtt;
            self.pacing_gain = 1.0;
            self.cwnd_gain = 1.0;
            self.probe_rtt_done_ms = now_ms + PROBE_RTT_DURATION_MS;
        }
    }

    /// `cwnd = cwnd_gain · BDP`, floored at 4 packets; pinned to the floor during PROBE_RTT.
    fn recompute_cwnd(&mut self) {
        if self.mode == Mode::ProbeRtt {
            self.cwnd = MIN_PIPE_CWND;
            return;
        }
        let btlbw = self.bw_filter.get(); // bytes/sec
        let rtprop = if self.rtprop_ms == u64::MAX { 0 } else { self.rtprop_ms };
        let bdp = btlbw * rtprop as f64 / 1000.0; // bytes
        let target = (self.cwnd_gain * bdp) as u32;
        self.cwnd = target.max(MIN_PIPE_CWND);
    }

    /// A duplicate ACK. BBR does **not** treat loss as a congestion signal, so cwnd is untouched; we
    /// still report the 3rd dup-ACK so the connection fast-retransmits the missing segment.
    pub fn on_dup_ack(&mut self) -> bool {
        self.dup_acks += 1;
        self.dup_acks == DUP_ACK_THRESHOLD
    }

    /// The retransmission timer fired — the path stalled entirely. Restart probing: floor the window,
    /// reset the STARTUP plateau detector, and re-enter STARTUP to rediscover the bandwidth. The
    /// RTprop estimate is kept (the path length didn't change just because a packet was lost).
    pub fn on_timeout(&mut self) {
        self.mode = Mode::Startup;
        self.cwnd = MIN_PIPE_CWND;
        self.pacing_gain = HIGH_GAIN;
        self.cwnd_gain = HIGH_GAIN;
        self.full_bw = 0.0;
        self.full_bw_count = 0;
        self.filled_pipe = false;
        self.cycle_index = 0;
        self.dup_acks = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RTT: u64 = 10; // ms — a fixed propagation delay for the simulated path

    /// Feed one ACK: advance the clock by `dt` ms, deliver `acked` bytes with a `RTT` sample.
    fn ack(b: &mut Bbr, clock: &mut u64, acked: u32, dt: u64) {
        *clock += dt;
        b.on_ack(acked, Some(RTT), *clock);
    }

    #[test]
    fn starts_in_startup_at_the_floor() {
        let b = Bbr::new();
        assert_eq!(b.mode(), Mode::Startup);
        assert_eq!(b.window(), MIN_PIPE_CWND);
    }

    #[test]
    fn windowed_max_filter_tracks_the_max_and_expires_it() {
        let mut f = WindowedMax::new(3);
        f.update(0, 100.0);
        f.update(1, 50.0);
        assert_eq!(f.get(), 100.0); // 100 still in window, dominates the 50
        f.update(2, 70.0);
        assert_eq!(f.get(), 100.0);
        f.update(4, 60.0); // t=4: the t=0 sample (100) is now older than window 3 → expires
        assert_eq!(f.get(), 70.0); // next-highest still in window
    }

    #[test]
    fn estimates_bandwidth_and_sizes_cwnd_to_bdp() {
        let mut b = Bbr::new();
        let mut t = 0u64;
        // Deliver 10·MSS every RTT (10 ms) → a steady 1.46 MB/s bottleneck.
        for _ in 0..6 {
            ack(&mut b, &mut t, 10 * MSS, RTT);
        }
        let bw = b.btlbw_bps();
        assert!(bw > 0.0, "BtlBw learned from delivery-rate samples");
        // cwnd should be ≈ cwnd_gain · BtlBw · RTprop, and at least the floor.
        let bdp = bw * RTT as f64 / 1000.0;
        let expected = (2.0 * bdp) as u32; // CWND_GAIN once in steady state
        assert!(b.window() >= MIN_PIPE_CWND);
        // within a generous tolerance (gain differs across STARTUP vs PROBE_BW phases)
        assert!(
            b.window() as f64 >= bdp,
            "cwnd ({}) covers at least one BDP ({:.0})",
            b.window(),
            bdp
        );
        let _ = expected;
    }

    #[test]
    fn startup_fills_the_pipe_then_drains_to_probe_bw() {
        let mut b = Bbr::new();
        let mut t = 0u64;
        // A constant delivery rate makes BtlBw plateau: after FULL_BW_COUNT flat rounds, STARTUP ends.
        for _ in 0..12 {
            ack(&mut b, &mut t, 10 * MSS, RTT);
        }
        assert!(b.filled_pipe, "STARTUP detected the bandwidth plateau");
        assert_eq!(b.mode(), Mode::ProbeBw, "DRAIN handed off to steady-state PROBE_BW");
    }

    #[test]
    fn probe_bw_cycles_the_pacing_gain() {
        let mut b = Bbr::new();
        let mut t = 0u64;
        for _ in 0..12 {
            ack(&mut b, &mut t, 10 * MSS, RTT); // reach PROBE_BW
        }
        assert_eq!(b.mode(), Mode::ProbeBw);
        let mut gains = std::collections::HashSet::new();
        for _ in 0..16 {
            ack(&mut b, &mut t, 10 * MSS, RTT);
            // bit-pattern key so f64 is hashable
            gains.insert(b.pacing_gain().to_bits());
        }
        assert!(gains.contains(&1.25f64.to_bits()), "probes up at gain 1.25");
        assert!(gains.contains(&0.75f64.to_bits()), "gives back at gain 0.75");
        assert!(gains.contains(&1.0f64.to_bits()), "cruises at gain 1.0");
    }

    #[test]
    fn rtprop_tracks_the_minimum_rtt() {
        let mut b = Bbr::new();
        let mut t = 0u64;
        b.on_ack(MSS, Some(50), {
            t += 50;
            t
        });
        assert_eq!(b.rtprop_ms, 50);
        // A lower sample lowers RTprop…
        b.on_ack(MSS, Some(20), {
            t += 20;
            t
        });
        assert_eq!(b.rtprop_ms, 20);
        // …a higher one does not (windowed-min ignores standing queue).
        b.on_ack(MSS, Some(80), {
            t += 80;
            t
        });
        assert_eq!(b.rtprop_ms, 20);
    }

    #[test]
    fn enters_probe_rtt_after_ten_idle_seconds_and_drops_cwnd() {
        let mut b = Bbr::new();
        let mut t = 0u64;
        for _ in 0..12 {
            ack(&mut b, &mut t, 10 * MSS, RTT); // reach PROBE_BW with a real cwnd
        }
        assert_eq!(b.mode(), Mode::ProbeBw);
        // Keep delivering, but never present a new RTprop minimum, for > 10 s. The min-RTT estimate
        // ages out and BBR drops into PROBE_RTT (a transient ~200 ms state), pinning cwnd to the
        // 4-packet floor. Break the moment we observe it — PROBE_RTT exits on its own afterward.
        let mut entered_probe_rtt = false;
        for _ in 0..200 {
            // RTT samples all > current RTprop, spaced 100 ms apart → no new min for > 10 s.
            t += 100;
            b.on_ack(10 * MSS, Some(RTT + 5), t);
            if b.mode() == Mode::ProbeRtt {
                entered_probe_rtt = true;
                break;
            }
        }
        assert!(entered_probe_rtt, "BBR enters PROBE_RTT after the 10 s min-RTT window expires");
        assert_eq!(b.window(), MIN_PIPE_CWND);
    }

    #[test]
    fn timeout_restarts_startup_and_floors_the_window() {
        let mut b = Bbr::new();
        let mut t = 0u64;
        for _ in 0..12 {
            ack(&mut b, &mut t, 10 * MSS, RTT);
        }
        assert_eq!(b.mode(), Mode::ProbeBw);
        b.on_timeout();
        assert_eq!(b.mode(), Mode::Startup);
        assert_eq!(b.window(), MIN_PIPE_CWND);
        assert!(!b.filled_pipe);
    }

    #[test]
    fn dup_acks_signal_retransmit_without_cutting_cwnd() {
        let mut b = Bbr::new();
        let mut t = 0u64;
        for _ in 0..12 {
            ack(&mut b, &mut t, 10 * MSS, RTT);
        }
        let before = b.window();
        assert!(!b.on_dup_ack()); // 1st
        assert!(!b.on_dup_ack()); // 2nd
        assert!(b.on_dup_ack()); //  3rd → fast retransmit
        assert_eq!(b.window(), before, "BBR ignores loss as a congestion signal — cwnd unchanged");
    }

    #[test]
    fn pacing_rate_is_gain_times_bandwidth() {
        let mut b = Bbr::new();
        let mut t = 0u64;
        for _ in 0..12 {
            ack(&mut b, &mut t, 10 * MSS, RTT);
        }
        let expected = b.pacing_gain() * b.btlbw_bps();
        assert!((b.pacing_rate_bps() - expected).abs() < 1e-6);
    }
}
