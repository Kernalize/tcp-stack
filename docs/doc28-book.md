# Doc 28 — TCP, Part 26: BBR — Congestion Control by Model, Not by Loss (Cardwell et al., 2016)

> Goal: build the *other kind* of congestion control. Every controller so far — Reno (Doc 10),
> NewReno (Doc 20), CUBIC (Doc 25) — is **loss-based**: it grows the window until a packet drops, then
> backs off. That made sense in 1988, when a drop almost always meant a full queue. It is a poor proxy
> today. On a router with a deep buffer, a loss-based sender fills that buffer *to the brim* before it
> ever sees a drop — so it runs with a permanently full queue, adding tens or hundreds of milliseconds
> of standing latency to every packet on the link ("**bufferbloat**"). On a link with a shallow buffer,
> or any path with the occasional *random* (non-congestive) loss, the same sender needlessly halves its
> window on a drop that signalled nothing. Loss is both too *late* a signal (you've already overfilled
> the queue) and too *noisy* a one (not every loss is congestion).
>
> **BBR** — Bottleneck Bandwidth and Round-trip propagation time — throws loss out as the primary
> signal and controls from a *model* of the path instead. It continuously measures two physical
> quantities: the **bottleneck bandwidth** (`BtlBw`, the fastest the path can deliver) and the
> **round-trip propagation delay** (`RTprop`, the path's latency with *no* queue). Their product is the
> **bandwidth-delay product** — the exact amount of data in flight that keeps the pipe *full* with the
> queue *empty*. BBR paces its sending to sit right at that knee: maximum throughput, minimum latency,
> regardless of how deep the bottleneck's buffer is or whether the path drops the odd packet. It is the
> control that fills Google's WAN and a large share of the public internet (YouTube, GCP).
>
> This chapter builds a faithful, teaching-grade **BBRv1** in `src/bbr.rs`: the two windowed filters,
> the four-state machine (STARTUP → DRAIN → PROBE_BW → PROBE_RTT), the pacing/cwnd gain schedule, and
> the delivery-rate estimator that turns each ACK into a bandwidth sample — all driven by a simulated
> millisecond clock so the whole thing is deterministic and unit-tested offline. We wire it in beside
> CUBIC as a *selectable* controller (`CongestionControl` becomes an enum), and the live server runs
> it. Honest caveat up front, same as CUBIC's: our echo server never sends in bulk, so the window
> won't actually *bind* here — but the model below is the real algorithm.

**Contents**

Volume I — the chapter
1. The mental model: model the pipe, don't react to loss
2. Why loss-based control mis-sizes the window
3. The two quantities — BtlBw and RTprop — and why you can't see both at once
4. The operating point: the bandwidth-delay product and Kleinrock's optimum
5. Delivery rate: how a single ACK measures bandwidth
6. The filters: windowed-max for BtlBw, windowed-min for RTprop
7. The state machine: STARTUP, DRAIN, PROBE_BW, PROBE_RTT
8. The gains: `pacing_gain` and `cwnd_gain`
9. Pacing vs windowing — what BBR really controls
10. The Rust: the filter, the state machine, the enum dispatch
11. A fully worked trace — startup to steady state
12. The code, walked end to end
13. Verification — the eleven new tests
14. Why this, not that
15. Honesty: what production BBR does that we don't
16. Rebuild it yourself — checklist + exercises
17. What comes after

Volume II — the exhaustive reference
- A. The BBR control loop, in pseudocode
- B. Delivery-rate sampling, derived from first principles
- C. The four states as a table — gains, entry and exit
- D. BBR vs CUBIC vs Reno — a side-by-side
- E. BBRv1 vs BBRv2/v3 — what changed, and why v1 was unfair
- F. Extended FAQ — twenty-five questions a careful reader asks
- G. Anki starter deck
- H. Glossary
- I. Reference tables

---

# Volume I — the chapter

## 1. The mental model: model the pipe, don't react to loss

Picture the path from sender to receiver as a physical pipe. It has a **width** — the bottleneck
link's bandwidth, the narrowest point — and a **length** — the round-trip propagation time, the
time-of-flight with nothing queued. The pipe holds exactly `width × length` bytes "in the air" when
it is full and uncongested. Put that much data in flight and the link runs at 100% with no waiting;
put *more* in flight and the excess has nowhere to go but a router's queue, where it sits adding
latency without adding throughput; put *less* and the pipe runs partly empty, wasting bandwidth.

Loss-based control never learns the pipe's dimensions. It probes by *overflowing*: push harder until
something drops, infer "that was too much," retreat, repeat. BBR instead **measures** the two
dimensions directly and aims for the fill line:

- **`BtlBw`** (bottleneck bandwidth) = the maximum rate at which ACKs report data being delivered.
  The bottleneck is, by definition, the link that paces delivery; the rate ACKs come back at *is* its
  bandwidth.
- **`RTprop`** (round-trip propagation time) = the minimum RTT ever seen. Any RTT above the minimum is
  minimum-plus-queue; the floor is the queue-free path latency.

Given those two numbers, the right amount of in-flight data is their product, and the right *rate* to
send at is `BtlBw`. BBR sets a pacing rate of `BtlBw` and caps in-flight at ~`2 × BtlBw × RTprop`, and
spends its life refining the two estimates. Loss, when it happens, is handled by the retransmission
machinery we already built (dup-ACK fast retransmit, RACK-TLP, the RTO) — but it does *not* move the
window. That's the one-sentence summary: **BBR controls to a measured model; loss is a repair event,
not a control signal.**

## 2. Why loss-based control mis-sizes the window

Let `B` be the bottleneck bandwidth, `R` the propagation RTT, and `BDP = B·R`. Let the bottleneck
router have a buffer of `Q` bytes. A loss-based sender (Reno/CUBIC) grows `cwnd` until the buffer
overflows, i.e. until in-flight ≈ `BDP + Q`, then halves. Two regimes, both bad:

```text
   Deep buffer  (Q ≫ BDP):  in-flight oscillates around BDP + Q.
       throughput: full (good)        but latency: R + Q/B  ← the standing queue is always there
       → bufferbloat: a 1 Gbit/s link with a 64 MB buffer adds ~512 ms of delay to every packet

   Shallow buffer (Q ≪ BDP): the window halves on the first overflow, far below BDP.
       latency: ≈ R (good)            but throughput: collapses to ~0.75·BDP and saws downward
       → and a single *random* loss (wireless, optical) triggers the same halving for no reason
```

The loss-based sender has no way to tell "queue is full, back off" from "a photon flipped a bit, no
need." Both look like a drop. BBR sidesteps the dilemma by not asking the question: it knows `BDP`
because it measured `B` and `R`, so it simply *stays at* `BDP` and never fills the buffer in the first
place. A random loss costs a retransmit, not a window cut.

## 3. The two quantities — BtlBw and RTprop — and why you can't see both at once

Here is the deep problem BBR's whole machine exists to solve: **the two quantities cannot be measured
at the same time.**

- To measure `BtlBw` you must *fill the pipe* — send fast enough that the bottleneck is the limiting
  factor, so the delivery rate you observe is its true capacity. But filling the pipe builds a queue,
  and a queue inflates the RTT. So while you're measuring bandwidth well, you're measuring RTT badly.
- To measure `RTprop` you must *drain the pipe* — send slowly enough that no queue forms, so the RTT
  you observe is the bare propagation delay. But draining the pipe means you're not filling it, so you
  can't see the true bandwidth at the same time.

This is a genuine uncertainty principle of networking (it falls out of queueing theory; see §4). BBR's
answer is to measure each quantity in its own regime and remember the result with a *filter*: take the
**maximum** delivery rate over a recent window (the moments you happened to be probing high) as
`BtlBw`, and the **minimum** RTT over a longer window (the moments you happened to be draining) as
`RTprop`. It then spends most of its time at the operating point, dipping deliberately above and below
to keep both estimates fresh (the PROBE_BW gain cycle and PROBE_RTT, §7).

## 4. The operating point: the bandwidth-delay product and Kleinrock's optimum

Leonard Kleinrock showed in 1979 that the optimal operating point for a connection — maximum delivered
throughput *and* minimum delay simultaneously — is exactly when in-flight data equals the BDP. Below
it, throughput is left on the table; above it, every extra byte only adds queueing delay. The curve:

```text
   delivery       ┌───────────────────────  BtlBw  (flat: bottleneck saturated)
   rate           │
            ▲     /
            │    /
            │   /   ← throughput rises linearly with in-flight…
            │  /
            └─/──────┬──────────────────────▶  in-flight
                     BDP

   RTT      ▲                        /
            │                       /  ← …but past BDP, RTT rises linearly (queue grows)
            │   ___________________/
            │  R (flat: no queue)
            └──────────┬──────────────────▶  in-flight
                       BDP
                    ^ the knee — BBR lives here
```

A worked instance, used throughout this chapter: a **10 Mbit/s** bottleneck with a **40 ms** RTprop.

```text
   BtlBw  = 10 Mbit/s          = 1.25 × 10⁶ bytes/s
   RTprop = 40 ms              = 0.040 s
   BDP    = BtlBw × RTprop     = 1.25e6 × 0.040 = 50 000 bytes ≈ 34 MSS  (at 1460 B)
   cwnd   = cwnd_gain × BDP    = 2 × 50 000      = 100 000 bytes ≈ 68 segments
   pacing = pacing_gain × BtlBw (= 1.25 MB/s in steady state, ×1.25 or ×0.75 while probing)
```

BBR aims to keep ~`BDP` in flight and pace at `BtlBw`. The `cwnd_gain = 2` cap (not `1`) is slack to
tolerate delayed/aggregated ACKs and the natural burstiness of real networks — it bounds in-flight so
a stall can't run away, while pacing, not the window, does the real rate control (§9).

## 5. Delivery rate: how a single ACK measures bandwidth

The bottleneck paces delivery, so the rate at which data is *delivered* (acknowledged) is the rate at
which the bottleneck forwards — its bandwidth, when the pipe is full. So every ACK is a bandwidth
sample. The canonical estimator tracks a cumulative `delivered` byte counter and the time of the last
delivery; for each ACK,

```text
   delivery_rate = (delivered_now − delivered_then) / (time_now − time_then)
```

over the interval since the data being acked was itself sent (production BBR times it from each
packet's send timestamp, the "rate sample"; see §B). Our teaching version computes the per-ACK delta
directly: bytes newly acked over the time since the previous ACK.

```rust
// src/bbr.rs — on_ack, step 3
if self.has_delivery {
    let interval_ms = now_ms.saturating_sub(self.delivered_time_ms);
    if interval_ms > 0 && acked > 0 {
        let rate_bps = acked as f64 * 1000.0 / interval_ms as f64; // bytes/sec
        self.bw_filter.update(self.round_count, rate_bps);         // → windowed-max
    }
} else {
    self.has_delivery = true; // the first ACK only seeds the interval; no rate yet
}
self.delivered_time_ms = now_ms;
```

Worked: an ACK that frees `10·MSS = 14 600` bytes, arriving 10 ms after the previous one, samples
`14 600 × 1000 / 10 = 1.46 × 10⁶ bytes/s` — 11.7 Mbit/s, in the ballpark of our 10 Mbit/s link. Noisy
single samples are fine; the windowed-max filter (§6) keeps the *best* recent one as the estimate.

## 6. The filters: windowed-max for BtlBw, windowed-min for RTprop

A single sample is noisy — an ACK delayed by the OS undersamples bandwidth; an ACK that arrives during
a queue overstates RTT. BBR keeps each estimate as a **windowed extreme**:

- **`BtlBw` = max** delivery rate over the last `BW_WINDOW_ROUNDS = 10` round trips. A transient *dip*
  (a missed ACK) can't lower it; only genuinely sustained lower bandwidth, after the old high sample
  ages out of the window, brings it down.
- **`RTprop` = min** RTT over the last `RTPROP_WINDOW_MS = 10 000` ms. A *queue* can't raise it; only
  a genuinely longer path, after the old low sample expires, raises it.

We implement the BtlBw max-filter as a **monotonic deque** keyed by the round counter — the front is
always the window's maximum:

```rust
// src/bbr.rs — WindowedMax::update (a sliding-window maximum)
fn update(&mut self, t: u64, v: f64) {
    while let Some(&(_, back)) = self.dq.back() {
        if back <= v { self.dq.pop_back(); } else { break; }   // drop tails ≤ v: they can't be the max
    }
    self.dq.push_back((t, v));
    while let Some(&(ft, _)) = self.dq.front() {
        if t.saturating_sub(ft) > self.window { self.dq.pop_front(); } else { break; } // expire stale
    }
}
```

`RTprop` uses the simpler "adopt if lower or expired" form (the classic BBR `update_min_rtt`), tracking
the time of the last refresh so we know when the 10-second window has aged out:

```rust
// src/bbr.rs — on_ack, step 1
let rtprop_expired = now_ms.saturating_sub(self.rtprop_stamp_ms) > RTPROP_WINDOW_MS;
if let Some(r) = rtt_ms {
    if r <= self.rtprop_ms || rtprop_expired || self.rtprop_ms == u64::MAX {
        self.rtprop_ms = r;
        self.rtprop_stamp_ms = now_ms;
    }
}
```

`rtprop_expired` is computed *once* and used for two things: to let a higher RTT replace a stale
minimum, and to trigger PROBE_RTT (§7). Computing it once is essential — refreshing the stamp inside
the update would hide the expiry from the PROBE_RTT check.

## 7. The state machine: STARTUP, DRAIN, PROBE_BW, PROBE_RTT

BBR sequences its probing through four states.

```text
   STARTUP ── exponential ramp (gain 2/ln2 ≈ 2.89): double the rate each round until BtlBw
   │            stops growing ≥ 25% for 3 rounds — the pipe is "full"
   ▼
   DRAIN ──── pace below 1× (gain ln2/2 ≈ 0.35) to drain the queue STARTUP overshot into
   │            (one round in our model; "inflight ≤ BDP" in production)
   ▼
   PROBE_BW ─ steady state: cwnd_gain = 2, and pacing_gain cycles [1.25, 0.75, 1,1,1,1,1,1]
   │            one phase per round — 1.25 briefly probes for more bandwidth, 0.75 gives the
   │            little queue back, the six 1.0 phases cruise. Net over a cycle ≈ 1.0.
   ▼
   PROBE_RTT ─ every 10 s with no new RTprop minimum, drop cwnd to 4 packets for ~200 ms so the
                queue drains and the true min-RTT is visible again; then back to PROBE_BW.
```

- **STARTUP** is BBR's slow-start: a high gain so the rate roughly doubles per round, discovering the
  bandwidth fast. It exits when the bandwidth estimate plateaus — three rounds where `BtlBw` failed to
  grow by `FULL_BW_THRESH = 1.25×` means the pipe is full and further pushing only builds queue.
- **DRAIN** undoes STARTUP's overshoot. STARTUP's `2.89×` gain inevitably puts ~`2·BDP`–`BDP` of extra
  data in the queue by the time it notices the plateau; DRAIN paces *below* line rate to give it back,
  so PROBE_BW starts from an empty queue.
- **PROBE_BW** is where a long-lived connection spends ~98% of its life. `cwnd` is held at `2·BDP`;
  `pacing_gain` walks an eight-phase cycle, one phase per RTprop. The `1.25` phase sends 25% faster for
  one round to *test* whether more bandwidth has appeared (a competing flow left); the `0.75` phase
  immediately drains the small queue that probe created; the six `1.0` phases cruise at the estimate.
- **PROBE_RTT** keeps `RTprop` honest. If 10 seconds pass with no new minimum RTT (a persistent queue,
  perhaps from BBR's own steady-state cruise or a competing flow), BBR briefly cuts to 4 packets so the
  queue empties and the bare path latency is measurable again, then resumes.

## 8. The gains: `pacing_gain` and `cwnd_gain`

Two multipliers do all the work:

```rust
const HIGH_GAIN:  f64 = 2.885_390_081_777_927; // 2/ln(2): STARTUP pacing & cwnd gain
const DRAIN_GAIN: f64 = 1.0 / HIGH_GAIN;        // ln(2)/2 ≈ 0.346: DRAIN pacing gain
const CWND_GAIN:  f64 = 2.0;                     // PROBE_BW inflight cap = 2·BDP
const PROBE_BW_GAINS: [f64; 8] = [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];
```

- **`pacing_gain`** scales the send *rate*: `pacing_rate = pacing_gain × BtlBw`. `2/ln2` is the
  smallest constant gain that makes the delivery rate *double* every round trip (the `ln2` falls out of
  the exponential; see §A), so STARTUP ramps as fast as slow-start without bursting.
- **`cwnd_gain`** scales the in-flight *cap*: `cwnd = cwnd_gain × BDP`. The `2×` (rather than `1×`)
  absorbs delayed-ACK and ACK-aggregation effects so the sender doesn't starve waiting for ACKs that
  arrive in clumps.

## 9. Pacing vs windowing — what BBR really controls

This is the conceptual break from everything prior. Reno/CUBIC are **window-controlled**: they allow a
burst of up to `cwnd` bytes and let ACK-clocking spread it out. BBR is **rate-controlled**: it spaces
each packet by `packet_size / pacing_rate` so data leaves at a smooth `BtlBw`, and uses `cwnd` only as
a *safety cap*, not the primary throttle. Pacing is what lets BBR sit at `BDP` without building a
queue — a windowed burst of `BDP` bytes would transiently overflow a shallow buffer even though the
average is right.

Our connection (`src/tcp.rs`) now **paces** new data: `poll_transmit` releases a segment only once the
clock reaches `next_send_ms`, then schedules the following one `segment_len / pacing_rate` later, so
data leaves at ~`pacing_gain · BtlBw` instead of bursting the whole window (the `cwnd` cap, via
`window()`, still bounds it). CUBIC reports a `0` pacing rate, so it stays purely window-clocked. The
effect only *shows* under bulk transfer, which our echo server never drives — but the mechanism is
real and tested (§13).

## 10. The Rust: the filter, the state machine, the enum dispatch

`window()` returns the in-flight cap; `recompute_cwnd` derives it from the model each ACK:

```rust
// src/bbr.rs — cwnd = cwnd_gain · BDP, floored at 4 packets; pinned to the floor in PROBE_RTT
fn recompute_cwnd(&mut self) {
    if self.mode == Mode::ProbeRtt { self.cwnd = MIN_PIPE_CWND; return; }
    let btlbw  = self.bw_filter.get();                 // bytes/sec
    let rtprop = if self.rtprop_ms == u64::MAX { 0 } else { self.rtprop_ms };
    let bdp    = btlbw * rtprop as f64 / 1000.0;        // bytes
    let target = (self.cwnd_gain * bdp) as u32;
    self.cwnd  = target.max(MIN_PIPE_CWND);             // never throttle below 4 segments
}
```

The state transitions live in `update_model`, called once per ACK (`round_start` gates per-round logic;
`rtprop_expired` triggers PROBE_RTT):

```rust
// src/bbr.rs — the heart of the state machine (abridged)
match self.mode {
    Mode::Startup => {
        self.pacing_gain = HIGH_GAIN; self.cwnd_gain = HIGH_GAIN;
        if round_start {
            if btlbw >= self.full_bw * FULL_BW_THRESH { self.full_bw = btlbw; self.full_bw_count = 0; }
            else {
                self.full_bw_count += 1;
                if self.full_bw_count >= FULL_BW_COUNT { self.filled_pipe = true; self.mode = Mode::Drain; }
            }
        }
    }
    Mode::Drain => {
        self.pacing_gain = DRAIN_GAIN; self.cwnd_gain = HIGH_GAIN;
        if round_start { self.enter_probe_bw(); }
    }
    Mode::ProbeBw => {
        self.cwnd_gain = CWND_GAIN;
        if round_start { self.cycle_index = (self.cycle_index + 1) % PROBE_BW_GAINS.len(); }
        self.pacing_gain = PROBE_BW_GAINS[self.cycle_index];
        self.maybe_enter_probe_rtt(rtprop_expired, now_ms);
    }
    Mode::ProbeRtt => {
        self.pacing_gain = 1.0; self.cwnd_gain = 1.0;
        if now_ms >= self.probe_rtt_done_ms {
            self.rtprop_stamp_ms = now_ms;          // we just re-measured the min RTT
            if self.filled_pipe { self.enter_probe_bw(); } else { self.mode = Mode::Startup; }
        }
    }
}
```

We expose BBR beside CUBIC by making `CongestionControl` an **enum** that dispatches the same six
methods the connection already calls — so `tcp.rs` is untouched except for threading the per-ACK RTT
sample into `on_ack`:

```rust
// src/congestion.rs
pub enum CongestionControl { Cubic(Cubic), Bbr(Bbr) }   // default() = Cubic; bbr() opts in

pub fn on_ack(&mut self, acked: u32, rtt_ms: Option<u64>, now_ms: u64) {
    match self {
        CongestionControl::Cubic(c) => c.on_ack(acked, now_ms),       // ignores rtt (time-based curve)
        CongestionControl::Bbr(b)   => b.on_ack(acked, rtt_ms, now_ms), // feeds RTprop / BDP
    }
}
```

The connection switches controllers with `Connection::use_bbr()`, and `main` calls it on every
accepted connection, so the **live server runs BBR**:

```rust
// src/main.rs — passive open
if let Some((mut conn, synack)) = tcp::Connection::accept(hdr.src, hdr.dst, &th, &opts, now_ms) {
    conn.use_bbr();                  // live stack runs model-based BBR
    iface.send(&synack)?;
    connections.insert(quad, conn);
}
```

## 11. A fully worked trace — startup to steady state

A connection over the 10 Mbit/s / 40 ms path (RTprop = 40 ms; we feed `10·MSS` per round). Times are
"rounds" (one RTprop each); the delivery rate is what the windowed-max filter reports.

```text
   round  pacing_gain  delivery rate (BtlBw)         mode / event
   ─────  ───────────  ───────────────────────────   ──────────────────────────────────────────
     0      2.885       —  (first ACK seeds interval)  STARTUP
     1      2.885       3.1 Mbit/s                      STARTUP  (rate doubling as gain fills pipe)
     2      2.885       6.2 Mbit/s                      STARTUP  (≥25% growth → full_bw updated)
     3      2.885       10  Mbit/s  ← plateau           STARTUP  (growth < 25% → full_bw_count = 1)
     4      2.885       10  Mbit/s                      STARTUP  (full_bw_count = 2)
     5      2.885       10  Mbit/s                      STARTUP  (full_bw_count = 3 → filled_pipe!) → DRAIN
     6      0.346       10  Mbit/s                      DRAIN → (round boundary) → PROBE_BW
     7      1.0         10  Mbit/s                      PROBE_BW  (enters at cycle phase 1.0)
     8      1.25        10  Mbit/s                      PROBE_BW  probe up (look for more bw)
     9      0.75        10  Mbit/s                      PROBE_BW  give the queue back
    10      1.0         10  Mbit/s                      PROBE_BW  cruise …
   ───────────────────────────────────────────────────────────────────────────────────────────
   … 10 s later with no new RTprop minimum → PROBE_RTT: cwnd = 4·MSS for 200 ms, re-measure, resume.
```

`cwnd` after the pipe fills ≈ `2 × BDP = 100 000 bytes ≈ 68 segments`; the pacing rate cruises at
`BtlBw = 1.25 MB/s`, dipping to `0.9375 MB/s` (×0.75) and rising to `1.5625 MB/s` (×1.25) for one round
each cycle.

## 12. The code, walked end to end

`on_ack` is the whole per-ACK pipeline (`src/bbr.rs`):

1. **RTprop update** — compute `rtprop_expired` once; adopt the RTT sample if it's a new min or the
   window aged out (§6).
2. **Round counting** — a round elapses each `RTprop` of wall time; `round_count++` and `round_start`
   gate the per-round logic. (Production ends a round when the byte sent at the round's start is acked;
   we approximate with time, which the simulated clock makes exact.)
3. **Delivery-rate sample** — bytes acked over the inter-ACK interval, fed into the BtlBw windowed-max
   keyed by `round_count` (§5).
4. **`update_model`** — run the state machine (§7), then **`recompute_cwnd`** from the refreshed model.

`on_dup_ack` returns `true` on the third duplicate so the connection still fast-retransmits the hole —
but, crucially, **does not shrink the window**: loss is not BBR's signal. `on_timeout` is the one
strong signal it heeds: the path stalled entirely, so restart probing (re-enter STARTUP, floor the
window, reset the plateau detector) while keeping `RTprop` (a lost packet didn't change the path
length). `in_recovery()` is always `false`, so the connection's NewReno/RFC-6675 recovery paths stay
dormant under BBR — retransmission still happens, via dup-ACK fast retransmit, RACK-TLP, and the RTO.

## 13. Verification — the eleven new tests

All offline, simulated-clock, deterministic (`src/bbr.rs` + `src/congestion.rs`):

```text
   bbr::starts_in_startup_at_the_floor              — default mode + cwnd = 4·MSS
   bbr::windowed_max_filter_tracks_the_max_and_expires_it — the deque filter in isolation
   bbr::estimates_bandwidth_and_sizes_cwnd_to_bdp   — cwnd grows to ≥ one BDP from rate samples
   bbr::startup_fills_the_pipe_then_drains_to_probe_bw — plateau → DRAIN → PROBE_BW
   bbr::probe_bw_cycles_the_pacing_gain             — gains 1.25, 0.75, 1.0 all appear
   bbr::rtprop_tracks_the_minimum_rtt               — min-filter adopts lower, ignores higher
   bbr::enters_probe_rtt_after_ten_idle_seconds_and_drops_cwnd — 10 s expiry → PROBE_RTT, cwnd floor
   bbr::timeout_restarts_startup_and_floors_the_window — RTO → STARTUP, cwnd = 4·MSS
   bbr::dup_acks_signal_retransmit_without_cutting_cwnd — 3rd dup-ACK true; cwnd unchanged
   bbr::pacing_rate_is_gain_times_bandwidth         — pacing_rate == pacing_gain · BtlBw
   congestion::bbr_is_selectable_and_dispatches_to_bbr — the enum routes to BBR; pacing rate > 0
```

plus `congestion::default_dispatches_to_cubic` (the enum still behaves as CUBIC by default) and
`tcp::use_bbr_selects_model_based_control_and_keeps_the_connection_working` (a real connection switched
to BBR still delivers and ACKs data, and starts at the 4-segment floor). 151 tests total, green,
clippy `-D warnings` clean.

## 14. Why this, not that

- **Why not just lower CUBIC's queue target?** You can't tune away the fundamental problem: a
  loss-based controller still needs a loss to learn, so it still fills *some* queue, and still
  can't distinguish congestive from random loss. BBR removes loss from the control loop entirely.
- **Why a max-filter for bandwidth but a min-filter for RTT?** Because the *true* values are the
  extremes: real bandwidth is the best you ever see (lower samples are undersampling), real latency is
  the least you ever see (higher samples are queue). The filters reject the noise that points the wrong
  way each time.
- **Why pace instead of just setting cwnd = BDP?** A window lets the whole `BDP` leave as a burst, which
  transiently overflows a shallow buffer. Pacing spreads it across the RTT so in-flight stays smooth.
- **Why the `1.25 / 0.75` probe pair?** They cancel: 1.25 for one round builds a small queue to test for
  spare bandwidth; 0.75 for the next round drains exactly that queue. The net is ≈ 1.0, so steady state
  doesn't accumulate standing queue while still probing.
- **Why keep CUBIC at all?** BBRv1 is unfair to loss-based flows sharing a buffer (§E), and is the wrong
  choice on some paths. Real stacks ship both and select per-socket; so do we (the enum).

## 15. Honesty: what production BBR does that we don't

- **Per-packet rate samples.** Real BBR tags each packet with the `delivered` count and time at send,
  so each ACK yields a rate over the *correct* interval and can flag **app-limited** samples (when the
  app, not the network, capped the rate) to exclude them from the max-filter. We take a per-ACK delta
  and don't detect app-limited intervals.
- **Per-segment, hardware-grade pacing.** Production paces *every* segment (retransmits included) via
  an `fq` qdisc or NIC offload at sub-microsecond granularity. Ours paces *new* data in `poll_transmit`
  at millisecond granularity — one segment per `len/rate` interval, floored at 1 ms — which caps paced
  throughput near 1 segment/ms; fine for teaching, coarse for a 10 Gbit/s link.
- **Exact DRAIN / PROBE_RTT exits.** Production exits DRAIN when *inflight ≤ BDP* and holds PROBE_RTT
  until inflight drains to 4 packets *and* one round elapses; we use round-boundary / fixed-duration
  approximations (the connection doesn't hand inflight to the controller on every ACK).
- **`cwnd` quantization, long-term sampling, lt_bw.** BBRv1 has extra machinery (a long-term bandwidth
  estimator to detect policers, gain quantization) we omit.
- **Startup loss/ECN response.** Later BBR variants exit STARTUP on ECN or excessive loss; v1 (and we)
  exit only on the bandwidth plateau.

## 16. Rebuild it yourself — checklist + exercises

Checklist (blank `src/bbr.rs`):
1. `WindowedMax` monotonic-deque filter + a test that it tracks the max and expires it.
2. `Mode` enum; `Bbr` struct with the filters, the gains, the round/plateau/cycle bookkeeping.
3. `on_ack`: RTprop update (compute `rtprop_expired` once) → round counting → delivery-rate sample →
   `update_model` → `recompute_cwnd`.
4. The four-state machine with the gain schedule; `enter_probe_bw` and `maybe_enter_probe_rtt`.
5. `on_dup_ack` (true on 3rd, no cwnd cut), `on_timeout` (restart STARTUP), `in_recovery` (false).
6. Make `CongestionControl` an enum; thread the RTT sample through `on_ack`; add `Connection::use_bbr`.

Exercises:
- **(a)** Pacing of new data is implemented (`poll_transmit` releases a segment only at
  `now ≥ next_send_ms`, then schedules the next `segment_len / pacing_rate` later). Extend it: add a
  burst budget so a high `BtlBw` can release several segments per tick, and pace retransmits too;
  prove with a test that sustained throughput tracks `BtlBw` across a range of rates.
- **(b)** Add app-limited detection: mark a round app-limited when the send buffer emptied, and skip its
  rate sample. Show the BtlBw estimate stops sagging on a bursty sender.
- **(c)** Two BBR flows sharing a bottleneck (extend the loopback `TcpServer`): watch them converge —
  and observe BBRv1's RTT-unfairness (the longer-RTT flow gets more than its share).
- **(d)** Swap the time-based round counter for a real one (mark `delivered` at round start; end the
  round when an ACK passes the mark). Confirm the state machine still sequences correctly.

## 17. What comes after

BBR completes the **congestion-control family**: the stack now ships both a loss-based controller
(CUBIC over NewReno + RFC 6675) and a model-based one (BBR), selectable per connection — and the
sender now paces new data to BBR's modelled rate. The natural follow-ons are BBRv2/v3's ECN and loss
response (§E), finer-grained / burst pacing (exercise (a)), and the multi-connection server (Doc 29) that
lets several BBR flows run at once so you can watch them interact.

---

# Volume II — the exhaustive reference

## A. The BBR control loop, in pseudocode

From draft-cardwell-iccrg-bbr-congestion-control, condensed to what we implement:

```text
   on each ACK (acked bytes, rtt sample, now):
       update_round(now)                          # round_count++, round_start once per RTprop
       update_btlbw:                              # windowed-max over BW_WINDOW_ROUNDS rounds
           rate = acked / (now − last_ack_time)
           BtlBw = windowed_max(rate, round_count, 10)
       update_rtprop:                             # windowed-min over RTPROP_WINDOW_MS ms
           rtprop_expired = now − rtprop_stamp > 10 s
           if rtt ≤ RTprop or rtprop_expired: RTprop = rtt; rtprop_stamp = now
       update_state_machine(round_start, rtprop_expired, now)
       set_pacing_rate  = pacing_gain × BtlBw
       set_cwnd         = max(cwnd_gain × BtlBw × RTprop, 4·MSS)

   STARTUP:  gain = 2/ln2; exit when BtlBw grew < 1.25× for 3 rounds → DRAIN
   DRAIN:    gain = ln2/2; exit when inflight ≤ BDP (here: next round) → PROBE_BW
   PROBE_BW: cwnd_gain = 2; gain cycles [1.25,0.75,1,1,1,1,1,1], one phase/round
   PROBE_RTT: if RTprop not refreshed for 10 s → cwnd = 4·MSS for 200 ms, re-measure, resume
```

## B. Delivery-rate sampling, derived from first principles

Conservation of packets at the bottleneck: in steady state, the rate data *arrives* at the receiver
equals the rate the bottleneck *forwards* (it's the slowest hop). ACKs mirror arrivals, so the rate
ACKs free data is the bottleneck rate. Over an interval `[t₀, t₁]` during which `Δ` bytes were newly
acknowledged, `rate = Δ / (t₁ − t₀)`. The subtlety production handles and we don't: the interval should
be measured from when *that* data was sent, not from the previous ACK, and samples taken while the
application (not the network) limited the send rate must be discarded — otherwise an idle app drags the
max-filter down. Our per-ACK delta is the right idea with those two refinements omitted.

## C. The four states as a table — gains, entry and exit

```text
   state       pacing_gain         cwnd_gain   entered from        exit condition
   ─────────   ─────────────────   ─────────   ─────────────────   ──────────────────────────────
   STARTUP     2/ln2 ≈ 2.885       2/ln2       connection start;   BtlBw < 1.25× growth × 3 rounds
                                                RTO restart         (filled_pipe) → DRAIN
   DRAIN       ln2/2 ≈ 0.346       2/ln2       STARTUP             round boundary (≈ inflight ≤ BDP)
                                                                    → PROBE_BW
   PROBE_BW    cycle 1.25/0.75/1   2.0         DRAIN; PROBE_RTT    runs indefinitely; → PROBE_RTT
                                                                    when RTprop stale 10 s
   PROBE_RTT   1.0                 1.0         PROBE_BW            now ≥ probe_rtt_done (200 ms)
                                                                    → PROBE_BW (or STARTUP if !full)
```

## D. BBR vs CUBIC vs Reno — a side-by-side

```text
                         Reno (Doc 10)     CUBIC (Doc 25)        BBR (Doc 28)
   ────────────────────  ───────────────   ───────────────────   ─────────────────────────────
   signal                loss              loss                  measured BtlBw + RTprop
   on loss               cwnd ×0.5         cwnd ×0.7             retransmit; cwnd unchanged
   window growth         +1 MSS/RTT        cubic in time         cwnd = 2·BDP (not grown — set)
   queue at bottleneck   fills to overflow fills to overflow    ≈ empty (paces at BtlBw)
   random-loss tolerance poor              poor                  excellent
   bufferbloat           causes it         causes it            avoids it
   primary control       window            window               rate (pacing) + window cap
   fairness to loss-based —                 —                    BBRv1: can starve them (§E)
```

## E. BBRv1 vs BBRv2/v3 — what changed, and why v1 was unfair

BBRv1 (what we build) ignores loss and ECN entirely in steady state. Two consequences drove the
redesign: (1) **unfairness to CUBIC/Reno** — sharing a deep buffer, BBRv1 holds ~1.5·BDP in flight and
refuses to yield on the losses its neighbours react to, so it can take more than its share; (2)
**RTT-unfairness** — among BBRv1 flows, longer-RTT flows get *more* throughput (their `cwnd = 2·BDP` is
larger). **BBRv2** added an explicit response to loss and ECN (an `inflight_hi`/`inflight_lo` model and
a loss/ECN-driven cap), shrank the steady-state queue, and improved coexistence. **BBRv3** (the current
default in Linux/Google) refined the model further and fixed remaining fairness and convergence issues.
The four-state skeleton, the two filters, and the gain idea are unchanged across versions — they are
the durable core, which is why v1 is the right thing to learn first.

## F. Extended FAQ — twenty-five questions a careful reader asks

1. **Does BBR ignore loss completely?** In steady-state *control*, yes — loss doesn't move the window.
   But lost data is still *retransmitted* (dup-ACK/RACK/RTO); and a full RTO restarts STARTUP.
2. **Why `2/ln2` exactly?** It's the constant gain that makes delivery rate double per round in STARTUP;
   the `ln2` is the integral of the exponential ramp (§A).
3. **What if RTprop never gets a clean sample?** PROBE_RTT forces one every 10 s by draining to 4
   packets; until the first sample, `rtprop_ms = u64::MAX` and `cwnd` sits at the 4-packet floor.
4. **Can `cwnd` be smaller than 4 packets?** No — `MIN_PIPE_CWND = 4·MSS` is the floor, including
   during PROBE_RTT, so the connection never stalls.
5. **What clamps the bandwidth estimate down?** Only time: the high sample must age out of the 10-round
   window before a sustained lower rate becomes the max.
6. **Why 10 rounds for BtlBw but 10 seconds for RTprop?** Bandwidth changes on the scale of a few RTTs
   (a competing flow starts/stops); path length changes rarely, so RTprop uses a longer, time-based
   window.
7. **Does BBR need SACK/timestamps?** It benefits from timestamps (cleaner RTT samples) but doesn't
   require them; our `on_ack` feeds whatever RTT sample the connection measured (`Option<u64>`).
8. **Is PROBE_RTT visible to the application?** As a brief throughput dip every 10 s (~200 ms at 4
   packets). Multiple BBR flows on a path try to synchronize their PROBE_RTTs to share the measurement.
9. **What happens on an RTO under BBR?** `on_timeout` re-enters STARTUP, floors `cwnd`, resets the
   plateau detector, keeps `RTprop`. The connection re-probes bandwidth from scratch.
10. **Why doesn't BBR enter Reno fast recovery?** `in_recovery()` returns `false`; BBR's window comes
    from the model, not from packet-conservation accounting, so the recovery state machine is bypassed.
11. **How does BBR coexist with CUBIC?** Poorly in v1 on deep buffers (§E); that's a real deployment
    caveat and a reason to keep CUBIC selectable.
12. **Is BBR TCP-specific?** No — it's a sender-side control loop; QUIC uses BBR too. Nothing here
    depends on TCP beyond getting (acked, rtt, now) per ACK.
13. **What's the `delivered` counter for?** In full BBR it dates rate samples per packet; our simplified
    estimator doesn't need a running counter, so we removed it (only `delivered_time_ms` remains).
14. **Could the max-filter be a 3-sample running filter instead of a deque?** Yes — Linux uses Kathleen
    Nichols's 3-entry `minmax`. The monotonic deque is equivalent and clearer to read.
15. **Why is the probe phase order `1.25` then `0.75`?** Probe up first (build a little queue to look
    for spare capacity), then immediately give it back, so any queue you created is short-lived.
16. **Does `cwnd_gain = 2` cause bufferbloat?** It allows up to ~1·BDP of queue transiently; pacing
    keeps the *average* near `BDP`, so standing queue stays small. v2 tightened this.
17. **What if the bottleneck is a token-bucket policer?** BBRv1 can overrun it (it has no long-term
    bandwidth estimator here); production BBR's `lt_bw` detects policers. We don't model this.
18. **How is `round_count` advanced?** Time-based: a round elapses each `max(RTprop, 1)` ms. Production
    ends a round when the byte marked at the round's start is acked.
19. **Why does `recompute_cwnd` use `cwnd_gain`, which changes by state?** Because the in-flight cap
    should follow the regime: `2·BDP` while cruising, the high gain while filling, `1×` in PROBE_RTT.
20. **Is BBR's pacing rate the same as the cwnd-implied rate?** Roughly `cwnd/RTT`, but pacing is
    smoother (no bursts) and is the real control; `cwnd` is the cap.
21. **What stops STARTUP from overshooting forever?** The plateau detector: three rounds without ≥25%
    bandwidth growth means more sending only builds queue, so it stops and drains.
22. **Could a single random loss in STARTUP confuse the plateau detector?** No — the detector watches
    *bandwidth*, not loss; a lost packet just isn't delivered, lowering one rate sample the max-filter
    ignores.
23. **How do you test a 10-second behaviour quickly?** A simulated `now_ms` clock: the test advances
    time in 100 ms steps to cross the 10 s window in a loop, then asserts the PROBE_RTT transition.
24. **Does BBR replace the RTO?** No — the RTO still guards against total stalls and, under BBR, also
    triggers the STARTUP restart.
25. **Why keep `pacing_rate_bps` if the sender doesn't pace?** It is BBR's defining output and the live
    server logs it; surfacing it keeps the value live (not dead code) and sets up the pacing exercise.

## G. Anki starter deck

```text
   Q: What two quantities does BBR measure?  A: BtlBw (max delivery rate) and RTprop (min RTT).
   Q: What is the BDP and why does BBR target it?  A: BtlBw·RTprop; the in-flight that fills the pipe
      with an empty queue (Kleinrock's optimum).
   Q: Why can't BtlBw and RTprop be measured at once?  A: Measuring bandwidth fills the queue (inflates
      RTT); measuring RTprop drains it (hides bandwidth).
   Q: BBR's four states?  A: STARTUP, DRAIN, PROBE_BW, PROBE_RTT.
   Q: STARTUP gain and exit?  A: 2/ln2 ≈ 2.885; exit when BtlBw grows < 25% for 3 rounds.
   Q: PROBE_BW pacing-gain cycle?  A: [1.25, 0.75, 1,1,1,1,1,1], one phase per round.
   Q: PROBE_RTT trigger and action?  A: 10 s with no new min-RTT → cwnd = 4·MSS for 200 ms.
   Q: Filter for BtlBw? For RTprop?  A: Windowed-max over 10 rounds; windowed-min over 10 s.
   Q: What does BBR do on loss?  A: Retransmit; the window is unchanged (RTO restarts STARTUP).
   Q: cwnd formula?  A: max(cwnd_gain · BtlBw · RTprop, 4·MSS); cwnd_gain = 2 in PROBE_BW.
```

## H. Glossary

```text
   BtlBw        bottleneck bandwidth — max delivery rate, windowed-max over 10 rounds
   RTprop       round-trip propagation time — min RTT, windowed-min over 10 s
   BDP          bandwidth-delay product, BtlBw·RTprop — the pipe's "full, no queue" capacity
   pacing_gain  multiplier on send rate: pacing_rate = pacing_gain · BtlBw
   cwnd_gain    multiplier on in-flight cap: cwnd = cwnd_gain · BDP
   STARTUP      exponential ramp (gain 2/ln2) to discover BtlBw
   DRAIN        sub-1× pacing to drain STARTUP's overshoot
   PROBE_BW     steady state; gain cycling to probe for more bandwidth
   PROBE_RTT    periodic dip to 4 packets to re-measure RTprop
   filled_pipe  STARTUP's "bandwidth plateaued" flag → triggers DRAIN
   app-limited  a sample where the app, not the network, capped the rate (excluded in real BBR)
   bufferbloat  standing queue latency caused by loss-based control filling deep buffers
```

## I. Reference tables

```text
   constant            value                      meaning
   ─────────────────   ────────────────────────   ─────────────────────────────────────────
   HIGH_GAIN           2/ln2 ≈ 2.885              STARTUP pacing & cwnd gain
   DRAIN_GAIN          ln2/2 ≈ 0.346              DRAIN pacing gain
   CWND_GAIN           2.0                         PROBE_BW inflight cap multiplier
   PROBE_BW_GAINS      [1.25,0.75,1,1,1,1,1,1]    one phase per round
   BW_WINDOW_ROUNDS    10                          BtlBw max-filter length (rounds)
   RTPROP_WINDOW_MS    10 000                      RTprop min-filter length (ms)
   PROBE_RTT_DURATION  200 ms                      PROBE_RTT hold time
   MIN_PIPE_CWND       4·MSS                       cwnd floor and PROBE_RTT target
   FULL_BW_THRESH      1.25                         STARTUP "still growing" threshold
   FULL_BW_COUNT       3                            plateau rounds before STARTUP exits
```

| Path (BtlBw × RTprop) | BDP | cwnd (2·BDP) | pacing @ ×1.0 |
|---|---|---|---|
| 10 Mbit/s × 40 ms | 50 KB ≈ 34 MSS | 100 KB ≈ 68 seg | 1.25 MB/s |
| 1 Gbit/s × 10 ms | 1.25 MB ≈ 856 MSS | 2.5 MB | 125 MB/s |
| 100 Mbit/s × 100 ms | 1.25 MB ≈ 856 MSS | 2.5 MB | 12.5 MB/s |
| 1 Mbit/s × 300 ms (sat.) | 37.5 KB ≈ 25 MSS | 75 KB | 125 KB/s |
