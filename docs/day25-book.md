# Day 25 — TCP, Part 23: CUBIC — Filling Fat Pipes with a Cubic Growth Curve (RFC 8312 / 9438)

> Goal: replace Reno's straight-line congestion avoidance with the curve the modern internet actually
> runs. Day 10 gave us RFC 5681 Reno: after a loss, `cwnd` grows **+1 MSS per RTT** — a gentle slope
> that is safe but glacial on a *fat pipe* (a high bandwidth-delay-product link: fast and/or
> long-haul). On a 1 Gbps, 100 ms path the window needs ~8000 segments to fill the pipe; at +1
> segment/RTT that's *minutes* to recover from a single loss. **CUBIC** (RFC 8312, updated by RFC
> 9438 — Linux's default since 2006, and the kernel default since 2.6.19) fixes this: after a loss it
> grows `cwnd` along a **cubic function of time**, `W(t) = C·(t − K)³ + W_max`, that shoots back up
> toward the pre-loss window `W_max`, *flattens* into a cautious plateau right around it, then
> *accelerates* past it to probe for new bandwidth. Fast where it's safe, gentle where it's risky.
>
> CUBIC also softens the *decrease*: where Reno halves the window on loss (β = 0.5), CUBIC multiplies
> by **β = 0.7**, so a single loss costs 30% of the window, not 50% — less throughput sacrificed for
> the same congestion signal. And crucially, CUBIC's growth is keyed to **wall-clock time, not RTT**,
> so two flows sharing a link converge to fairness regardless of their round-trip times (Reno favors
> short-RTT flows).
>
> This is the congestion-control capstone: the loss *detection* (RACK-TLP, Day 24) and *recovery
> structure* (NewReno/6675, Days 20–21) stay; CUBIC changes only the *growth law* and the *decrease
> factor* — the two numbers that decide how fast a real bulk transfer fills a real network.

**Contents**

Volume I — the chapter
1. The mental model: a slope vs. a curve
2. Why Reno is too slow on a fat pipe
3. The cubic function, term by term
4. K, W_max, and the concave/convex split
5. β = 0.7: a softer multiplicative decrease
6. RTT-independence and fairness
7. Where it lives: time enters the congestion module
8. The Rust: f64 for the curve, integer β, the per-ACK step
9. A fully worked recovery — Reno's slope vs CUBIC's curve
10. The code, walked end to end
11. Verification — the rewritten and new tests
12. Why this, not that
13. Honesty: what production does that we don't
14. Rebuild it yourself — checklist + exercises
15. What comes after

Volume II — the exhaustive reference
- A. RFC 8312 / 9438: the variables and the update rule
- B. The cubic curve, plotted in numbers
- C. The TCP-friendly (Reno) region — what we omit
- D. Fast convergence, and the multiplicative-decrease history
- E. CUBIC vs Reno vs BBR — growth philosophies
- F. Comparison to real stacks — Linux, the sysctls
- G. Extended FAQ — twenty-five questions a careful reader asks
- H. Anki starter deck
- I. Glossary
- J. Reference tables

---

# Volume I — the chapter

## 1. The mental model: a slope vs. a curve

Congestion avoidance is the phase *after* slow start, where the sender probes for the largest window
the network will bear. The question is *how fast to probe*. Reno's answer is a **straight line**:

```text
   Reno congestion avoidance:   cwnd += 1 MSS each RTT   (the "AI" of AIMD — additive increase)
```

A constant slope, forever. It's beautifully stable and fair on the low-bandwidth, short-RTT links of
1988 — but on a modern fat pipe it's far too timid. CUBIC's answer is a **curve** anchored at the
window we last lost from:

```text
   CUBIC:   W(t) = C·(t − K)³ + W_max
            t      = seconds since the loss
            W_max  = the window just before the loss (the inflection point)
            K      = the time the curve takes to climb back to W_max
            C      = a constant (0.4) setting the curve's steepness
```

A cubic has exactly the shape congestion control wants: **steep, then flat, then steep again.** Right
after a loss (small `t`) it climbs *fast* to undo most of the cut. Approaching `W_max` (t → K) it
*flattens* — probing gently right around the last known-safe point, where another loss is most
likely. Past `W_max` (t > K) it *accelerates* again — confidently hunting for new bandwidth the path
may have gained. Reno's line does none of this; it's the same cautious slope whether you're far below
the safe point or pushing past it.

## 2. Why Reno is too slow on a fat pipe

The damage is quantitative. The *bandwidth-delay product* (BDP) is how much data fills a link:

```text
   BDP = bandwidth × RTT
   1 Gbps × 100 ms = 12.5 MB ≈ 8500 segments of 1460 B
```

To fill that pipe, `cwnd` must reach ~8500 MSS. After a single loss, Reno cuts to ~half (4250) and
climbs back at **+1 MSS per RTT**:

```text
   segments to regain  = 8500 − 4250 = 4250
   time to regain      = 4250 RTTs × 100 ms ≈ 425 seconds  (over SEVEN MINUTES)
```

Seven minutes of running below capacity after *one* dropped packet. On such links Reno simply cannot
keep the pipe full — its throughput is bounded not by the network but by its own timid slope. CUBIC
regains `W_max` in `K` seconds (a handful, set by the curve, *independent of RTT*), then probes
beyond. That gap — minutes vs. seconds — is why every major OS abandoned Reno-style CA for CUBIC (or
BBR) on the public internet.

## 3. The cubic function, term by term

```rust
fn cubic_target(&self, now_ms: u64) -> u32 {
    let w_max = self.w_max as f64 / MSS as f64;       // W_max in MSS units (the curve's natural unit)
    let beta  = CUBIC_BETA_NUM as f64 / CUBIC_BETA_DEN as f64;   // 0.7
    let k = (w_max * (1.0 - beta) / CUBIC_C).cbrt();  // K = ∛( W_max·(1−β) / C )  — seconds to W_max
    let t = now_ms.saturating_sub(self.epoch_ms) as f64 / 1000.0;  // seconds since the loss epoch
    let w = CUBIC_C * (t - k).powi(3) + w_max;        // W(t) = C·(t−K)³ + W_max,  in MSS
    (w.max(1.0) * MSS as f64) as u32                  // back to bytes, floored at 1 MSS
}
```

Each piece:
- **`W_max`** — the window we lost from; the curve's *plateau height* and inflection point.
- **`C = 0.4`** — RFC 9438's scaling constant. Bigger C → steeper curve → more aggressive probing.
  0.4 is the standardized value that keeps CUBIC stable and fair.
- **`K = ∛(W_max·(1−β)/C)`** — the time to climb from the post-loss window back to `W_max`. Derived by
  solving `W(0) = W_max·β` (the curve starts at the reduced window): at `t = 0`,
  `C·(−K)³ + W_max = W_max·β`, so `C·K³ = W_max·(1−β)`, giving the cube root. Note `K` depends on
  `W_max` (and β, C) — *not* on RTT. That's the root of CUBIC's RTT-fairness (§6).
- **`(t − K)³`** — the cubic itself. Negative for `t < K` (below the plateau), zero at `t = K` (the
  plateau, `W = W_max`), positive for `t > K` (above it, probing).

## 4. K, W_max, and the concave/convex split

Walk the curve with numbers. Say `W_max = 10 MSS`, β = 0.7, C = 0.4:

```text
   K = ∛(10 · 0.3 / 0.4) = ∛7.5 ≈ 1.957 s

   t = 0.0 s :  W = 0.4·(0 − 1.957)³ + 10 = 0.4·(−7.5) + 10 = 7.0 MSS   ← starts at W_max·β (the cut)
   t = 1.0 s :  W = 0.4·(−0.957)³ + 10    = −0.35 + 10      = 9.65 MSS  ← climbing back, concave
   t = 1.957s:  W = 0.4·0³ + 10           = 10.0 MSS        ← the plateau: exactly W_max
   t = 3.0 s :  W = 0.4·(1.043)³ + 10     = +0.45 + 10      = 10.45 MSS ← past W_max, convex probing
   t = 4.0 s :  W = 0.4·(2.043)³ + 10     = +3.41 + 10      = 13.4 MSS  ← accelerating
```

Two regions, split at `K`:
- **Concave** (`t < K`): the curve rushes up from the post-loss window (`W_max·β = 7 MSS`) toward
  `W_max`, decelerating as it nears — fast recovery of lost ground, easing off as it approaches the
  danger zone.
- **Convex** (`t > K`): having safely re-reached `W_max`, the curve accelerates upward to discover new
  capacity, cautiously at first then boldly.

The plateau around `K` is the genius: CUBIC spends the *most time* probing right where the last loss
happened, because that's where it should be most careful — and the *least time* far below (rushes up)
or far above (rare). Our implementation realizes this: when `cubic_target > cwnd` we climb toward it;
when `cubic_target ≤ cwnd` (sitting on the plateau) we creep up Reno-style (`+MSS²/cwnd`), the gentle
probe right around `W_max`.

## 5. β = 0.7: a softer multiplicative decrease

Reno's "MD" halves the window on loss (β = 0.5). CUBIC uses **β = 0.7**:

```rust
self.w_max = self.cwnd;                                            // remember the inflection point
self.ssthresh = (self.cwnd * CUBIC_BETA_NUM / CUBIC_BETA_DEN).max(2 * MSS);  // cwnd · 7/10
```

Why gentler? Because CUBIC's *fast* re-growth makes a deep cut unnecessary — it can afford to give
back less window and climb back quickly without overshooting. A 30% cut instead of 50% means a single
loss costs less throughput, while the cubic curve and the standardized `C`/β keep the aggregate stable
and fair. We keep β as an *integer fraction* (`7/10`) so `ssthresh` stays exact and deterministic;
only the curve itself uses floating point.

Note the decrease is based on `cwnd` (CUBIC's definition), not Reno's `FlightSize/2`. And `W_max =
cwnd` records the height to aim the curve back at. Everything else about recovery — the fast-retransmit
inflation (`ssthresh + 3·MSS`), NewReno's partial-ACK deflation, the recovery-exit to `ssthresh` — is
unchanged from Days 10/20. CUBIC swaps the *growth law* and the *cut factor*; the recovery *plumbing*
is the same.

## 6. RTT-independence and fairness

Reno's increase is **per-RTT** (+1 MSS each round trip), so a short-RTT flow grows its window faster
than a long-RTT flow sharing the same link — and unfairly steals bandwidth. CUBIC's `W(t)` is a
function of **wall-clock time**, and `K` depends only on `W_max` (not RTT), so two flows with
different RTTs follow the *same curve in real time* and converge to a fair share. This RTT-fairness is
a headline reason CUBIC replaced Reno on the public internet, where flows with wildly different RTTs
share every bottleneck.

(There's a subtlety: a *very* short-RTT flow could grow slower under pure CUBIC than it would under
Reno, so RFC 8312 adds a "TCP-friendly region" that floors CUBIC at Reno's estimate — we omit it; §C.)

## 7. Where it lives: time enters the congestion module

Until today the congestion module was deliberately *time-agnostic* — it took byte counts (`on_ack(acked)`,
`on_dup_ack(flight)`, `on_timeout(flight)`) and the connection supplied sequence/timing context. CUBIC
breaks that: `W(t)` needs `t`, wall-clock seconds since the loss. So `on_ack` now takes `now_ms`:

```text
   before:  cong.on_ack(acked)
   after:   cong.on_ack(acked, now_ms)   ← the one signature change; threads the clock into CUBIC
```

The decrease methods (`on_dup_ack`, `on_timeout`) *don't* need the clock — they reset `epoch_ms = 0`,
and the **epoch starts lazily** on the first congestion-avoidance ACK afterward:

```rust
if self.epoch_ms == 0 {
    self.epoch_ms = now_ms;                       // the cubic clock starts here
    if self.w_max < self.cwnd { self.w_max = self.cwnd; }
}
```

Two new fields hold the curve's anchor: `w_max` (the inflection window) and `epoch_ms` (when this
cubic epoch began). The connection already threads `now_ms` everywhere (Day 6), so the single
call-site change in `tcp.rs` is `self.cong.on_ack(acked, now_ms)`.

## 8. The Rust: f64 for the curve, integer β, the per-ACK step

**f64 for the curve, integers for the rest.** The cubic — `cbrt`, `powi(3)`, the multiply — is
genuinely real-valued, so `cubic_target` computes in `f64` and converts back to `u32` bytes at the
end. But the *decrease* (`ssthresh = cwnd·7/10`) stays integer, so `ssthresh` is exact and the tests
assert precise values. Float only where the math is float; integers everywhere a test pins a number.

**`f64::cbrt` and `powi(3)`.** `K` is a cube root (`.cbrt()`, exact-ish and fast) and the curve cubes
`(t − K)` (`.powi(3)`, integer exponent — faster and more precise than `.powf(3.0)`). Both are std,
no crate.

**The per-ACK step.** `cwnd` should reach `cubic_target` over roughly one RTT, not jump there in one
ACK (which would burst). There are ~`cwnd/MSS` ACKs per RTT, so each ACK climbs a fraction:

```rust
let acks_per_rtt = (self.cwnd / MSS).max(1);
self.cwnd += ((target - self.cwnd) / acks_per_rtt).max(1);   // smooth approach to the target
```

`.max(1)` guarantees forward progress (never a zero step). When already at/above the target (the
plateau), we fall back to Reno's `+MSS²/cwnd` creep — gentle probing right around `W_max`.

## 9. A fully worked recovery — Reno's slope vs CUBIC's curve

`W_max = 10 MSS`, loss at t = 0, post-loss window = 7 MSS (β = 0.7 for CUBIC; Reno would cut to 5 MSS
with β = 0.5). Compare the window over the next 4 seconds (RTT = 100 ms, so 10 RTTs/sec):

```text
   time    Reno (+1 MSS/RTT from 5)     CUBIC  W(t)=0.4(t−1.957)³+10 from 7
   ─────   ──────────────────────────   ───────────────────────────────────
   0.0 s   5.0  MSS                      7.0  MSS   (gentler cut: 0.7 vs 0.5)
   1.0 s   5.0 + 10 = 15? no — +10/s →   9.65 MSS   (concave: rushing back to W_max)
           Reno: 5 + 1·(10 RTT) = 15…    but capped by the real pipe; illustrative slope only
   2.0 s   (Reno climbs +10 MSS/s here   10.0 MSS   (plateau: at W_max, probing gently)
            ONLY at 1 seg/RTT = +10/s)
   4.0 s   …                             13.4 MSS   (convex: accelerating past W_max)
```

The honest comparison isn't the toy slope above but the *fat-pipe* case of §2: to climb the 4250-MSS
gap, Reno needs 4250 RTTs (~425 s), while CUBIC re-reaches `W_max` in `K = ∛(W_max·0.3/0.4)` seconds
— for a large `W_max`, still only a few seconds — then probes beyond. CUBIC's curve is *concave then
convex*; Reno's is a single timid slope. On a LAN both are instant; on a fat pipe CUBIC is the
difference between using the link and starving it.

(Our unit test `cubic_recovers_toward_and_past_w_max` drives exactly this: after a loss to `W_max =
10 MSS`, CA ACKs across simulated seconds climb the window back to and **past** 10 MSS — the convex
probing — which Reno's `+1 MSS/RTT` slope, anchored at no `W_max`, never does.)

## 10. The code, walked end to end

All in `src/congestion.rs`, with one call-site change in `src/tcp.rs`.

**State** gains `w_max` (the inflection window) and `epoch_ms` (the cubic epoch start).

**`on_ack(acked, now_ms)`** — slow start is unchanged; the congestion-avoidance branch is now CUBIC:
start the epoch lazily, compute `cubic_target`, climb toward it (or creep Reno-style on the plateau).
The recovery-exit path (`in_recovery` → `cwnd = ssthresh`) resets the epoch so the next CA ACK starts
a fresh curve.

**`cubic_target(now_ms)`** — `W(t) = C·(t − K)³ + W_max` in f64, returned in bytes (§3).

**`on_dup_ack` / `on_timeout`** — the multiplicative decrease now uses CUBIC's β (`cwnd·7/10`) and
records `w_max = cwnd`; everything else (the `+3·MSS` inflation, the collapse-to-1-MSS on RTO) is as
before.

**`tcp.rs`** — the one call site becomes `self.cong.on_ack(acked, now_ms)`; the connection already has
`now_ms` in hand. NewReno (Day 20), RFC 6675 (Day 21), and RACK-TLP (Day 24) are untouched — they
drive *which* segments to send and *when* a loss is declared; CUBIC only changes *how big* the window
grows and *how much* it shrinks.

## 11. Verification — the rewritten and new tests

`cargo test` — **131 passing**. The congestion tests were updated to CUBIC's numbers (β = 0.7), and
the cubic curve gets a dedicated test:

- **`slow_start_adds_one_mss_per_ack`** — slow start is unchanged (the `now_ms` argument is ignored
  there); pins that CUBIC only changes congestion *avoidance*, not slow start.
- **`cubic_reduces_cwnd_by_beta_on_three_dup_acks`** — grow to 10·MSS, then a 3-dup-ACK loss:
  `ssthresh = 10·MSS·0.7 = 7·MSS`, `cwnd = ssthresh + 3·MSS = 10·MSS`. Pins the β = 0.7 cut (vs Reno's
  half).
- **`new_ack_deflates_out_of_recovery_to_ssthresh`** — the full-ACK exit lands on `ssthresh = 7·MSS`
  (the CUBIC value).
- **`cubic_recovers_toward_and_past_w_max`** — the headline: after a loss to `W_max = 10·MSS`, CA ACKs
  across several simulated seconds climb the window back to and **past** 10·MSS (the convex probing).
  This is the behavior Reno's slope cannot produce — the test that *is* CUBIC.
- **`timeout_collapses_to_one_mss_and_slow_start`**, **`extra_dup_acks_inflate_during_recovery`**,
  **`newreno_partial_ack_deflates_and_stays_in_recovery`**, **`reports_recovery_state`** — recovery
  *structure* unchanged, retested against the new β.
- **`tcp.rs` `newreno_partial_ack_retransmits…`** — the post-loss `cwnd` now deflates to CUBIC's
  `ssthresh = cwnd·0.7` (3·MSS·7/10 = 3066 bytes), confirming the connection drives the new module
  correctly.

Slow start, NewReno, RFC 6675, RACK-TLP, and every other test still pass — CUBIC slots into the
existing recovery without disturbing it.

## 12. Why this, not that

**Why a cubic curve instead of Reno's line?** On a fat pipe Reno's +1 MSS/RTT takes *minutes* to
refill after a loss; the cubic regains `W_max` in seconds (RTT-independent) and then probes beyond.
(§§2, 9.)

**Why β = 0.7 instead of 0.5?** CUBIC's fast re-growth makes a deep cut unnecessary, so it gives back
less window per loss — more throughput for the same congestion signal — while `C`/β keep it stable.
(§5.)

**Why is growth a function of time, not RTT?** So flows with different RTTs follow the same curve and
converge to fairness; Reno's per-RTT growth unfairly favors short-RTT flows. (§6.)

**Why creep Reno-style on the plateau?** When `cubic_target ≤ cwnd` (sitting at `W_max`), the gentle
`+MSS²/cwnd` is exactly the cautious probing CUBIC wants right where loss is most likely. (§4.)

**Why keep the recovery structure (NewReno/6675/RACK)?** Those decide *what to retransmit* and *when a
loss happened*; CUBIC decides *window size*. They're orthogonal — CUBIC swaps two numbers (growth law,
β), nothing else. (§10.)

**Why f64 for the curve but integer β?** The curve is genuinely real-valued (cube roots, cubes);
`ssthresh` is a window the tests pin exactly. Float where it's float; integer where it counts. (§8.)

## 13. Honesty: what production does that we don't

- **No TCP-friendly (Reno) region.** RFC 8312 §4.2 floors CUBIC at Reno's window estimate so it never
  underperforms Reno on short-RTT/low-BDP links. We implement the plain cubic + a Reno-style plateau
  creep; on a slow LAN our CUBIC can be marginally less aggressive than Reno early. (Exercise E1.)
- **No fast convergence.** RFC 8312 §4.6 reduces `W_max` slightly when a *new* loss arrives below the
  previous `W_max` (so a flow yields faster to a new competitor). We anchor `W_max = cwnd` plainly.
  (E2.)
- **No hybrid slow start (HyStart).** Linux exits slow start early using RTT/ACK-train signals to
  avoid a big overshoot; we use classic slow start.
- **f64, not fixed-point.** The Linux kernel computes CUBIC in fixed-point with a cube-root lookup
  table (no FPU in the kernel). We use `f64` — clearer, and fine in userspace.
- **`C`/β are the standard constants, not tuned.** No RTT-scaling, no BBR-style model. Plain RFC 9438
  CUBIC.
- **Still loss-based.** CUBIC (like Reno) treats loss as the congestion signal; BBR instead models the
  bottleneck bandwidth and RTT and ignores loss. Different philosophy (§E), a much larger change.
- **The echo server never bulk-sends**, so CUBIC, like all our congestion control, is exercised by the
  unit tests rather than binding live — a bulk transfer over the socket API (Day 22) under `tc netem`
  is what makes it visible.

CUBIC's curve and β are real; the gaps are the production refinements (TCP-friendly region, fast
convergence, HyStart, fixed-point), each a known follow-on.

## 14. Rebuild it yourself — checklist + exercises

**Checklist**

- [ ] Add `w_max`, `epoch_ms` to `CongestionControl`; constants β = 7/10 and C = 0.4.
- [ ] `on_ack(acked, now_ms)`: slow start unchanged; CA branch starts the epoch lazily, computes
      `cubic_target`, climbs toward it (`(target−cwnd)/acks_per_rtt`) or creeps Reno-style on the
      plateau.
- [ ] `cubic_target(now_ms)`: `W(t) = C·(t − K)³ + W_max`, `K = ∛(W_max·(1−β)/C)`, in f64 → bytes.
- [ ] `on_dup_ack`/`on_timeout`: `w_max = cwnd`; `ssthresh = cwnd·7/10` (floored at 2·MSS); reset the
      epoch.
- [ ] Thread `now_ms` into the one `cong.on_ack` call in `tcp.rs`.
- [ ] `cargo test` green (131), `cargo clippy -- -D warnings` clean.

**Exercises**

1. **E1 — TCP-friendly region.** Compute Reno's estimate `W_est = W_max·β + 3·(1−β)/(1+β)·(t/RTT)`
   and use `max(W_cubic, W_est)`; show CUBIC no longer trails Reno on a short-RTT link.
2. **E2 — fast convergence.** On a loss with `cwnd < W_max_prev`, set `W_max = cwnd·(1+β)/2` so the
   flow yields faster to a newcomer; test two competing flows converge sooner.
3. **E3 — plot the curve.** Log `cwnd` each ACK during a CA epoch and plot it; verify the concave→
   plateau→convex shape against the §4 numbers.
4. **E4 — RTT fairness.** Simulate two flows with RTTs 20 ms and 200 ms sharing a bottleneck; show
   CUBIC's windows converge while Reno's diverge in the short-RTT flow's favor.
5. **E5 — measure it.** Over the socket API (Day 22) with `tc qdisc … netem delay 100ms` + a single
   drop, time a bulk transfer's recovery under CUBIC vs a stubbed Reno slope; watch CUBIC refill in
   seconds.

Make Anki cards from the cubic formula and `K = ∛(W_max·(1−β)/C)` — those two are CUBIC.

## 15. What comes after

CUBIC is the loss-based congestion-control standard; with it (plus RACK-TLP detection), the stack
grows and shrinks its window the way the modern internet does. The remaining frontier in congestion
control is **BBR** — a model-based controller that estimates bottleneck bandwidth and RTT directly and
ignores loss as a signal entirely (§E), a fundamentally different design. Beyond congestion control,
what's left is breadth and hardening: SYN cookies, `SO_KEEPALIVE`, a multi-connection socket façade,
and live `packetdrill`/`iperf3` validation. The protocol engine — handshake, reliability, modern loss
detection *and* modern congestion control, the full lifecycle, RFC 5961 robustness, a socket API — is
complete.

---

# Volume II — the exhaustive reference

## A. RFC 8312 / 9438: the variables and the update rule

CUBIC (RFC 8312, obsoleted by RFC 9438) keeps Reno's slow start, fast retransmit, and recovery; it
redefines congestion avoidance and the decrease. Its variables, mapped to our code:

```text
   RFC 9438 name     meaning                                  our field / value
   ───────────────   ──────────────────────────────────────  ────────────────────────
   W_max             window before the last reduction          w_max
   β_cubic           multiplicative decrease factor (0.7)      CUBIC_BETA_NUM/DEN = 7/10
   C                 cubic scaling constant (0.4)              CUBIC_C
   K                 time to grow back to W_max                computed in cubic_target
   t                 elapsed time since the epoch began         now_ms − epoch_ms (seconds)
   W_cubic(t)        the target window at time t                cubic_target(now_ms)
   epoch start       set on the first CA ACK after a loss       epoch_ms
```

The update rule, per ACK in congestion avoidance (RFC 9438 §4):

```text
   1. If no epoch in progress: start it (epoch_ms = now), set W_max if needed, compute K.
   2. Compute the target W_cubic(t) = C·(t − K)³ + W_max.
   3. (RFC: also compute the TCP-friendly W_est; cwnd ← max(W_cubic, W_est). We skip W_est — §C.)
   4. If W_cubic > cwnd: increase cwnd toward it over ~1 RTT.
      Else: increase cwnd ≈ Reno (the plateau creep).
   On a loss:  W_max ← cwnd;  ssthresh ← cwnd·β;  (fast recovery or, on RTO, cwnd ← 1 MSS).
```

## B. The cubic curve, plotted in numbers

`W_max = 10 MSS`, β = 0.7, C = 0.4, `K = ∛(10·0.3/0.4) = ∛7.5 ≈ 1.957 s`:

```text
   t (s)   (t−K)      (t−K)³     C·(t−K)³    W(t) MSS    region
   ─────   ────────   ────────   ─────────   ─────────   ─────────────────
   0.0     −1.957     −7.50      −3.00       7.00        post-loss (= W_max·β)
   0.5     −1.457     −3.09      −1.24       8.76        concave (climbing)
   1.0     −0.957     −0.876     −0.35       9.65        concave
   1.5     −0.457     −0.0954    −0.038      9.96        nearing the plateau
   1.957    0.0        0.0        0.0        10.00       plateau (= W_max)
   2.5     +0.543     +0.160     +0.064      10.06       convex (probing)
   3.0     +1.043     +1.135     +0.454      10.45       convex
   4.0     +2.043     +8.53      +3.41       13.41       convex (accelerating)
   5.0     +3.043     +28.2      +11.3       21.3        convex (steep)
```

The shape: a fast climb from 7 → ~10 in the first ~2 s (concave), a near-flat plateau right at
`W_max = 10` around `t = K`, then an ever-steeper rise past 10 (convex). Time is spent where it
matters — gently at the danger zone, boldly far from it.

## C. The TCP-friendly (Reno) region — what we omit

On a *short-RTT* link, Reno's per-RTT growth can actually outpace CUBIC's time-based curve early in an
epoch (many RTTs fit in a second, so Reno adds many MSS while CUBIC's `t` is still small). To never be
*less* aggressive than Reno, RFC 8312 §4.2 computes a Reno estimate and takes the max:

```text
   W_est(t) = W_max·β + 3·(1−β)/(1+β) · (t / RTT)
   cwnd     = max( W_cubic(t), W_est(t) )
```

`W_est` is Reno's straight line reconstructed from the same loss; the `3(1−β)/(1+β)` factor makes
CUBIC emulate *exactly* Reno's average rate in this region. We omit it (it needs the RTT and adds a
branch), so our CUBIC can be marginally gentler than Reno on a slow LAN — harmless for a teaching
stack, but E1 adds it for conformance.

## D. Fast convergence, and the multiplicative-decrease history

```text
   scheme    β (decrease)   increase                     notes
   ───────   ────────────   ──────────────────────────   ─────────────────────────────
   Tahoe     →1 MSS         slow-start restart            any loss = full collapse
   Reno      0.5            +1 MSS / RTT (linear)         fair on low BDP, slow on fat pipes
   BIC       0.8            binary search to W_max         CUBIC's predecessor (complex)
   CUBIC     0.7            C·(t−K)³ + W_max (cubic)       RTT-independent, fat-pipe friendly
```

**Fast convergence** (RFC 8312 §4.6): when a new loss occurs at a `cwnd` *below* the previous `W_max`
(a sign a new flow joined and is taking share), CUBIC sets `W_max = cwnd·(1+β)/2` — a notch lower than
`cwnd` — so the flow gives up bandwidth faster and the newcomer converges to its fair share sooner.
We anchor `W_max = cwnd` plainly (no fast convergence); E2 adds it.

## E. CUBIC vs Reno vs BBR — growth philosophies

```text
   controller   congestion signal   growth                       fills fat pipes?   fairness basis
   ──────────   ─────────────────   ──────────────────────────   ────────────────   ──────────────
   Reno         loss                +1 MSS / RTT (linear)         no (too slow)      per-RTT (unfair)
   CUBIC        loss                cubic in time                 yes                per-time (fair)
   BBR          model (bw × RTT)    paces to estimated bottleneck  yes                bandwidth model
```

Reno and CUBIC are both *loss-based* (they probe until a drop, then back off); they differ only in the
growth law. BBR is a different species: it builds a *model* of the path's bottleneck bandwidth and
minimum RTT, paces sending to that model, and treats loss as largely irrelevant — so it avoids filling
buffers (low latency) and isn't fooled by random (non-congestive) loss. BBR is a far larger change
(it needs delivery-rate estimation and pacing); CUBIC is the loss-based state of the art and the right
capstone for this stack.

## F. Comparison to real stacks — Linux, the sysctls

```text
   aspect                  Linux                       ours (Day 25)
   ─────────────────────   ─────────────────────────   ────────────────────────
   default CC              CUBIC (since 2.6.19)        CUBIC
   β                       0.7                         0.7 (integer 7/10)
   C                       0.4                         0.4
   TCP-friendly region     yes                         no (E1)
   fast convergence        yes                         no (E2)
   HyStart (slow-start)    yes                         classic slow start
   arithmetic              fixed-point + cbrt table    f64
   relevant sysctl         net.ipv4.tcp_congestion_control = cubic
```

Set `net.ipv4.tcp_congestion_control` to see the menu (`cubic`, `reno`, `bbr`, …); `cubic` is the
default almost everywhere. Our column is "real CUBIC curve + β, with the TCP-friendly/fast-convergence/
HyStart refinements as exercises."

## G. Extended FAQ — twenty-five questions a careful reader asks

1. **What does CUBIC change vs Reno?** The congestion-avoidance growth (cubic-in-time vs +1 MSS/RTT)
   and the decrease factor (β = 0.7 vs 0.5). Nothing else.
2. **The cubic formula?** `W(t) = C·(t − K)³ + W_max`.
3. **What is `W_max`?** The window just before the last reduction — the curve's inflection/plateau.
4. **What is `K`?** `∛(W_max·(1−β)/C)` — the time to climb back to `W_max`.
5. **What is `C`?** 0.4, the standardized scaling constant (steepness).
6. **What is β?** 0.7 — the multiplicative-decrease factor (a loss costs 30% of cwnd).
7. **Why gentler than Reno's 0.5?** CUBIC re-grows fast, so it can give back less window per loss.
8. **Why is growth in time, not RTT?** For RTT-fairness — flows with different RTTs follow the same
   curve.
9. **What's the concave region?** `t < K`: rushing back up to `W_max`, decelerating as it nears.
10. **The plateau?** Around `t = K`, `W ≈ W_max`: gentle probing right where loss is likeliest.
11. **The convex region?** `t > K`: accelerating past `W_max` to find new bandwidth.
12. **Why does the module now take `now_ms`?** CUBIC's `W(t)` needs wall-clock time since the loss.
13. **When does the epoch start?** Lazily, on the first CA ACK after a loss (or after slow start).
14. **Does CUBIC change slow start?** No — only congestion avoidance and the decrease.
15. **Does it change NewReno/6675/RACK?** No — those handle *which* to retransmit and loss detection;
    CUBIC sets window size.
16. **Why creep Reno-style on the plateau?** When the cubic target ≤ cwnd, gentle `+MSS²/cwnd` is the
    right cautious probe at `W_max`.
17. **Why f64 for the curve?** Cube roots and cubes are real-valued; integers stay for `ssthresh`.
18. **Is the math deterministic?** Yes — f64 is deterministic for given inputs; tests assert ranges
    for the curve and exact integers for `ssthresh`.
19. **What's the TCP-friendly region we skip?** A floor at Reno's estimate so CUBIC never trails Reno
    on short-RTT links (E1).
20. **Fast convergence?** Lowering `W_max` on a sub-`W_max` loss so flows converge faster (E2).
21. **Does CUBIC fill a fat pipe?** Yes — it regains `W_max` in seconds (RTT-independent), where Reno
    needs thousands of RTTs.
22. **How is it tested?** β cut and recovery structure at exact values; the curve via a test that
    drives CA ACKs over simulated time and checks cwnd climbs back to and past `W_max`.
23. **Which test "is" CUBIC?** `cubic_recovers_toward_and_past_w_max` — Reno's slope can't probe past
    a remembered `W_max`.
24. **CUBIC vs BBR?** CUBIC is loss-based with a cubic growth law; BBR models bandwidth×RTT and ignores
    loss — a different philosophy and a much larger change.
25. **Biggest thing still missing?** The TCP-friendly region and fast convergence (both exercises);
    and BBR as a separate controller.

## H. Anki starter deck

```text
Q: CUBIC's congestion-avoidance formula?  A: W(t) = C·(t − K)³ + W_max.
Q: What is W_max?  A: the window just before the last reduction (the curve's inflection point).
Q: What is K?  A: ∛(W_max·(1−β)/C) — the time to climb back to W_max.
Q: CUBIC's C constant?  A: 0.4.
Q: CUBIC's β?  A: 0.7 (Reno uses 0.5) — a loss costs 30% of cwnd.
Q: Concave region (t<K)?  A: rushing back up toward W_max, decelerating.
Q: Plateau (t≈K)?  A: at W_max — gentle probing where loss is likeliest.
Q: Convex region (t>K)?  A: accelerating past W_max for new bandwidth.
Q: Why time-based, not RTT-based growth?  A: RTT-fairness across flows.
Q: Why is Reno slow on a fat pipe?  A: +1 MSS/RTT takes thousands of RTTs to refill.
Q: What does CUBIC keep from Reno/NewReno/6675?  A: slow start, fast retransmit, recovery structure.
Q: What did the congestion module gain to support CUBIC?  A: time (now_ms) + w_max + epoch_ms.
Q: When does the cubic epoch start?  A: lazily, on the first CA ACK after a loss.
Q: TCP-friendly region (omitted)?  A: floor cwnd at Reno's estimate so CUBIC never trails Reno.
Q: CUBIC vs BBR?  A: loss-based cubic growth vs model-based (bandwidth×RTT), loss-agnostic.
```

## I. Glossary

- **CUBIC** — loss-based congestion control whose congestion-avoidance window follows a cubic curve in
  time (RFC 8312 / 9438).
- **`W_max`** — the window just before the last reduction; the cubic curve's inflection/plateau.
- **`K`** — the time for the curve to climb back to `W_max`: `∛(W_max·(1−β)/C)`.
- **`C`** — CUBIC's scaling constant (0.4), setting the curve's steepness.
- **β (beta)** — the multiplicative-decrease factor (0.7 for CUBIC, 0.5 for Reno).
- **Concave/convex region** — below/above `K`: fast recovery to `W_max` / probing past it.
- **Epoch** — the period since the last loss, over which the cubic curve is measured (`epoch_ms`).
- **BDP (bandwidth-delay product)** — bandwidth × RTT; the data needed to fill a link.
- **Fat pipe** — a high bandwidth-delay-product link where Reno's slope is too slow.
- **TCP-friendly region** — the floor at Reno's estimate so CUBIC never underperforms Reno (omitted).
- **HyStart** — hybrid slow start; an early slow-start exit (not implemented).
- **BBR** — model-based congestion control (bandwidth × RTT), loss-agnostic — a different philosophy.

## J. Reference tables

**J.1 — CUBIC constants and the curve**

```text
   symbol   value / formula              role
   ──────   ──────────────────────────   ────────────────────────────────────────
   C        0.4                          steepness of the cubic
   β        0.7                          multiplicative decrease (cwnd · 0.7 on loss)
   W_max    cwnd at the last loss        the inflection / plateau height
   K        ∛(W_max·(1−β)/C)             seconds to climb back to W_max
   t        now − epoch                  seconds since the loss
   W(t)     C·(t−K)³ + W_max             the target window
```

**J.2 — what changed vs Reno (Day 10)**

```text
   aspect                Reno (Day 10)        CUBIC (Day 25)
   ───────────────────   ──────────────────   ──────────────────────────────
   CA growth             +1 MSS / RTT          cubic curve in time
   decrease β            0.5 (FlightSize/2)    0.7 (cwnd · 7/10)
   growth keyed to       RTT                   wall-clock time
   fat-pipe refill       thousands of RTTs     seconds (RTT-independent)
   slow start            unchanged             unchanged
   recovery structure    fast retx + recovery  unchanged
```

**J.3 — the congestion-control stack now**

```text
   concern              mechanism                 chapter
   ──────────────────   ───────────────────────   ───────
   loss detection       3 dup-ACKs / SACK IsLost   10 / 21
                        RACK time-based + TLP       24
   recovery (which seg)  NewReno / RFC 6675         20 / 21
   window growth         CUBIC cubic curve          25  (was Reno, 10)
   window decrease       β = 0.7                    25  (was 0.5)
```

> Re-type `cubic_target`, the `on_ack` CA branch, and the β-0.7 decrease with the book closed, then
> `cargo test`. When your window climbs back to the pre-loss point in a few seconds and then probes
> *past* it — instead of crawling up one segment per round trip forever — you've built the congestion
> control that actually fills the modern internet's pipes.
