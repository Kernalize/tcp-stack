# Doc 24 — TCP, Part 22: RACK-TLP — Time-Based Loss Detection and the Tail Loss Probe (RFC 8985)

> Goal: fix the loss the rest of the stack can't see. Docs 10–21 built loss recovery on *counting*:
> three duplicate ACKs (RFC 5681), three SACKed segments above a hole (RFC 6675's `IsLost`). Counting
> has two blind spots. First, **reordering** inflates and deflates the count, so a reordered (not
> lost) segment can trigger a needless fast retransmit, and a genuine loss behind reordering can be
> missed. Second — and worse — the **tail of a transfer**: when the *last* segment is dropped, nothing
> arrives after it, so there are no dup-ACKs and nothing to SACK above it. The count never reaches
> three, and recovery falls all the way back to the **retransmission timeout** — hundreds of
> milliseconds of dead air at the very end of a flow, exactly where short web responses live.
>
> **RACK-TLP** (RFC 8985) replaces counting with *time*. **RACK** (Recent ACKnowledgment): a segment
> is lost if a segment sent *later* has already been acknowledged **and** a small reordering window
> has elapsed since the earlier one was sent — reordering-tolerant by construction. **TLP** (Tail Loss
> Probe): when the tail is outstanding with nothing new to send, send one probe at ≈ RTO/2 to elicit
> an ACK/SACK *before* the full RTO, turning a tail loss into an ordinary RACK recovery.
>
> This is the modern capstone on everything: it uses Doc 16's per-segment timing and Doc 18's SACK
> scoreboard, and it's what Linux and the rest of the internet actually run today (it supersedes the
> count-based DupThresh of RFC 5681/6675). We add it *additively* — the count-based paths remain — so
> the stack gains time-based detection and fast tail recovery without losing what already works.

**Contents**

Volume I — the chapter
1. The mental model: counting vs. timing
2. The two blind spots of counting — reordering and the tail
3. RACK: a segment is lost if a later one was acked, plus slack
4. The reordering window
5. TLP: probing the tail before the RTO
6. Where it lives: the queue times, the connection clocks
7. Keeping it additive — not breaking the count-based paths
8. The Rust: per-segment timestamps, `rev().find`, the PTO < RTO invariant
9. A fully worked tail-loss trace — RTO vs TLP
10. The code, walked end to end
11. Verification — the two new tests (and the one we updated)
12. Why this, not that
13. Honesty: what production does that we don't
14. Rebuild it yourself — checklist + exercises
15. What comes after

Volume II — the exhaustive reference
- A. RFC 8985 in full: RACK and TLP, step by step
- B. The reordering window, and DSACK adaptation
- C. TLP: PTO computation and the two-probe schedule
- D. RACK-TLP vs dup-ACK / RFC 6675 — what each catches
- E. Comparison to real stacks — Linux, the sysctls
- F. Extended FAQ — twenty-five questions a careful reader asks
- G. Anki starter deck
- H. Glossary
- I. Reference tables

---

# Volume I — the chapter

## 1. The mental model: counting vs. timing

Every loss-recovery scheme answers "is this segment lost?" Until today, ours answered by **counting**:

```text
   signal                         "lost" when…                              chapter
   ────────────────────────────   ───────────────────────────────────────   ───────
   duplicate ACKs (RFC 5681)      3 dup-ACKs for the same cumulative point    10
   SACK IsLost (RFC 6675)         3 SACKed segments sequenced above a hole    21
```

Counting is simple and works well in the common case. But "three of something arrived after the gap"
is a *proxy* for "enough time passed that the gap is really a loss, not a reorder." RACK measures that
**directly**, in time:

```text
   RACK (RFC 8985):  a segment is lost if a LATER-sent segment has been acked/SACKed, AND more than a
                     small reordering window has elapsed since the earlier segment was sent.
```

The shift from *count* to *time* is the whole idea. Time doesn't get confused by reordering (a
reordered segment just arrives a little late, within the window), and time doesn't need three
*somethings* to arrive — so it works even at the **tail**, where nothing arrives after the loss
(that's what TLP, §5, is for: manufacture the "later segment" by probing).

## 2. The two blind spots of counting — reordering and the tail

**Reordering.** The network can deliver segments out of order. Three dup-ACKs from *reordering* look
identical to three from *loss*, so a pure count fast-retransmits data that wasn't lost — a spurious
retransmit that needlessly cuts cwnd. (TCP's older mitigations: timestamps/Eifel, DSACK.) RACK's
reordering window absorbs this: a segment only counts as lost once it's *later* than a delivered one
**by more than the window**, so ordinary reordering (which displaces by less than the window) never
triggers it.

**The tail.** This is the one our stack genuinely can't handle. Picture a 5-segment response whose
**last** segment is dropped:

```text
   sent:      [s1][s2][s3][s4][s5]
   arrived:   [s1][s2][s3][s4]  ✗      (s5 lost)
   the peer ACKs through s4 — and then there is SILENCE.
   nothing is sent after s5, so:  no dup-ACKs (nothing arrives to re-ACK),
                                  no SACK above s5 (there is nothing above s5),
                                  IsLost never fires (needs 3 SACKed above).
   → recovery falls back to the RTO: hundreds of ms of dead air at the end of the flow.
```

For a bulk transfer the tail is a rounding error; for a short HTTP response (which is *almost all*
web traffic) the tail loss is the *whole* tail of the user-visible latency. TLP exists to kill it.

## 3. RACK: a segment is lost if a later one was acked, plus slack

RACK keeps, per outstanding segment, the time it was (most recently) sent — which our retransmission
queue already records as `sent_at_ms` (Doc 12). When an ACK or SACK acknowledges some segment, RACK
remembers the **most recently sent** segment among those now acknowledged:

```rust
// in RetxQueue::ack and ::mark_sacked, as segments are acked/SACKed:
if s.sent_at_ms >= rack_xmit_ts { rack_xmit_ts = s.sent_at_ms; rack_end_seq = s.end_seq; }
```

`rack_xmit_ts` / `rack_end_seq` are RACK's reference point: "the latest-sent thing the receiver has."
Then any still-outstanding segment that was sent *before* that reference, and far enough in the past,
is lost:

```rust
pub fn rack_mark_lost(&mut self, now_ms: u64, reo_wnd_ms: u64) -> Vec<Vec<u8>> {
    let (rack_ts, rack_end) = (self.rack_xmit_ts, self.rack_end_seq);
    let mut out = Vec::new();
    for s in &mut self.segments {
        if s.sacked { continue; }
        let sent_before_acked = s.sent_at_ms < rack_ts && seq::before(s.start_seq, rack_end);
        if sent_before_acked && now_ms.saturating_sub(s.sent_at_ms) > reo_wnd_ms {
            s.retries += 1; s.sent_at_ms = now_ms;      // retransmit; reset its timer
            out.push(s.packet.clone());
        }
    }
    out
}
```

Read the condition aloud: *"this segment is unacked; a later-sent segment (`sent_at_ms < rack_ts`)
sequenced above it (`start_seq before rack_end`) has been delivered; and more than the reordering
window has passed since it was sent."* That's a loss — retransmit it, without waiting for three of
anything. Resetting `sent_at_ms` means it won't be re-picked next tick (its send time is now `>=
rack_ts`), so each hole is retransmitted once per detection.

## 4. The reordering window

How much slack? Enough to let genuine reordering settle, but no more. RFC 8985 sizes it adaptively —
`reo_wnd ≈ min(SRTT/4, ...)`, grown when DSACK reveals the network reorders more than assumed. We use
a simple fixed fraction of the RTO:

```rust
let reo_wnd = (self.rtt.rto() / 4).max(1);   // ≈ SRTT/4, the RFC's starting point
```

`RTO/4` ≈ `(SRTT + 4·RTTVAR)/4`, a touch larger than the RFC's `SRTT/4` — fine for a teaching cut: a
slightly larger window is *more* conservative (fewer spurious retransmits), at the cost of detecting a
real loss a few milliseconds later. The book's exercise E2 adds DSACK-based adaptation (the part that
makes the window *shrink* on a path that doesn't reorder, for faster detection).

## 5. TLP: probing the tail before the RTO

RACK needs "a later segment was acked" to fire. At the tail there is no later segment — so TLP
**manufactures** the ACK. When data is outstanding, nothing new is queued (a possible tail), and we're
not already recovering, arm a **Probe Timeout (PTO)** at roughly half the RTO:

```rust
// end of poll_transmit:
if self.flight_size() > 0 && self.send_buf.is_empty() && !self.cong.in_recovery() {
    if self.tlp_deadline_ms == 0 {
        self.tlp_deadline_ms = now_ms.saturating_add((self.rtt.rto() / 2).max(1));
    }
} else { self.tlp_deadline_ms = 0; self.tlp_sent = false; }
```

When the PTO fires (in `on_tick`), retransmit the **last** segment — one probe:

```rust
if self.tlp_deadline_ms != 0 && now_ms >= self.tlp_deadline_ms
    && self.flight_size() > 0 && !self.cong.in_recovery() && !self.tlp_sent
{
    if let Some(probe) = self.retx.retransmit_last(now_ms) { out.push(probe); self.tlp_sent = true; }
    self.tlp_deadline_ms = 0;
}
```

Two outcomes:
- **The tail was lost.** The probe *is* the retransmission — the peer receives it and ACKs, recovering
  the loss at ≈ RTO/2 instead of a full RTO. (If earlier segments were also lost, the probe's ACK now
  acknowledges a later segment, so RACK can mark those holes lost too.)
- **The tail wasn't lost** (the ACK was just slow). The probe is a duplicate; the peer dup-ACKs it,
  harmless. (A full RACK-TLP uses DSACK to *detect* this spurious probe and undo any cwnd reaction; we
  simply tolerate it.)

`PTO ≈ RTO/2` guarantees the probe fires *before* the RTO — the whole point is to beat the timeout.
One probe per tail (`tlp_sent`); a fresh ACK that makes forward progress re-arms it.

## 6. Where it lives: the queue times, the connection clocks

The split mirrors every prior recovery day:

```text
   ┌─────────────────────────────────────────────┐   ┌──────────────────────────────────────┐
   │ RetxQueue — owns per-segment send times      │   │ Connection — owns the clocks/policy   │
   │ • rack_xmit_ts / rack_end_seq (the reference)│   │ • on_tick: rack_mark_lost(reo_wnd)    │
   │ • rack_mark_lost(now, reo_wnd)  (detection)  │◀──│   then the TLP fire (retransmit_last) │
   │ • retransmit_last(now)          (the probe)  │   │ • poll_transmit: arm the PTO          │
   └─────────────────────────────────────────────┘   └──────────────────────────────────────┘
```

The queue knows *when each segment was sent* and *which were acked/SACKed* — so RACK's reference and
loss test live there. The connection owns the RTT estimator (for `reo_wnd` and the PTO), the
congestion state (don't probe during recovery), and the event loop (arm in `poll_transmit`, fire in
`on_tick`). The queue computes facts; the connection schedules.

## 7. Keeping it additive — not breaking the count-based paths

RFC 8985 is meant to *replace* the DupThresh-based detection. We add it *alongside* the existing
dup-ACK fast retransmit (Doc 10), NewReno (Doc 20), and RFC 6675 (Doc 21), for two reasons: it's far
lower risk against a suite of 100+ tests that pin the count-based behavior, and it lets the chapter
show RACK-TLP as a *complement* you can reason about in isolation. The ordering in `on_tick` keeps
them from fighting:

```text
   on_tick:  1. RACK_mark_lost   → retransmit time-detected holes (resets their send timers)
             2. TLP fire         → probe the tail (resets the probed segment's timer)
             3. RTO due()        → the backstop; a segment just retransmitted by 1 or 2 is no longer
                                    "due" (its timer was reset), so there's no double retransmit
```

Because RACK and TLP fire *earlier* (RTO/4 and RTO/2) and reset `sent_at_ms`, the RTO `due()` check
that runs after them sees those segments as freshly sent and skips them. The RTO remains the final
backstop for anything RACK/TLP didn't catch. (A real stack collapses these into one RACK-driven timer;
ours keeps three timers that compose cleanly.)

One deliberate simplification: a RACK-detected loss here retransmits *without* a congestion reaction
(no cwnd collapse), and TLP is a probe (also no reaction). A fully conformant RACK enters loss
recovery and reduces cwnd on real losses; we note this in §13 and leave it as exercise E3.

## 8. The Rust: per-segment timestamps, `rev().find`, the PTO < RTO invariant

**Per-segment timestamps, already there.** RACK needs each segment's send time — which `Unacked.sent_at_ms`
has recorded since Doc 12 (for the RTO) and Doc 16 (for RTT). RACK is almost free on top: two new
`u64`/`u32` fields on the queue (`rack_xmit_ts`, `rack_end_seq`) and a comparison. Reusing the
existing timing infrastructure is why a "modern" algorithm lands in ~40 lines.

**`rev().find` for the tail.** The probe target is the highest-sequence outstanding segment. Since the
queue records in ascending order, that's the last non-SACKed entry:

```rust
let idx = (0..self.segments.len()).rev().find(|&i| !self.segments[i].sacked)?;
```

`rev()` walks indices high-to-low; `find` returns the first (= highest-sequence) non-SACKed one; `?`
yields `None` when nothing's outstanding. Reverse-iterate-and-find is the idiom for "the last element
matching a predicate."

**The PTO < RTO invariant.** TLP must fire *before* the RTO or it's pointless. `PTO = RTO/2` makes
that true by construction, with no special cases — a cleaner guarantee than RFC 8985's `2·SRTT` (which
can equal or exceed the RTO when RTTVAR is tiny). We document it as a simplification; the property
that matters (probe early, RTO as backstop) holds unconditionally.

## 9. A fully worked tail-loss trace — RTO vs TLP

A 1-segment tail (the unit test), `MSS`-irrelevant, no RTT sample yet so `RTO = 200 ms`,
`PTO ≈ 100 ms`. We send "hi"; the segment is lost.

```text
   t(ms)  without TLP (pre-Doc-24)              with TLP (Doc 24)
   ─────  ──────────────────────────────────    ─────────────────────────────────────────
   0      send [1,3); arm nothing                send [1,3); arm PTO = 0 + 100 = 100
   50     on_tick: nothing (RTO not due)         on_tick: PTO not due; RTO not due → nothing
   ~100   on_tick: nothing (RTO not due)         on_tick: PTO due → RETRANSMIT [1,3) (the probe)
   ...                                            peer receives the probe → ACKs → recovered (~1 RTT)
   200    on_tick: RTO fires → retransmit [1,3)  (segment already probed+acked; nothing due)
          peer ACKs → recovered (~1 RTT + RTO)
```

Without TLP the loss costs a full RTO (200 ms here, often far more on a real path) of dead air before
the retransmit even goes out. With TLP the probe goes at 100 ms — and for a short response that 100 ms
is a visible chunk of the page-load time. The test asserts exactly this: `on_tick(50)` is empty, and
`on_tick(120)` returns the retransmitted segment.

## 10. The code, walked end to end

All in `src/tcp.rs`.

**`RetxQueue`** gains the RACK reference (`rack_xmit_ts`, `rack_end_seq`), updated in `ack` and
`mark_sacked` as segments are acknowledged/SACKed (§3); plus two methods — `rack_mark_lost`
(time-based detection, §3) and `retransmit_last` (the probe target, §5).

**`Connection`** gains the TLP schedule (`tlp_deadline_ms`, `tlp_sent`), armed at the end of
`poll_transmit` when the tail is outstanding (§5), fired in `on_tick` before the RTO backstop, with
RACK detection run first (§7). A forward-progress ACK resets the probe (`tlp_sent = false`).

**The `on_tick` order** is RACK → TLP → RTO `due()` (§7), so the earlier, lighter detectors run first
and the RTO only catches what's left.

Nothing else changed: the dup-ACK / NewReno / RFC 6675 paths are untouched and still tested.

## 11. Verification — the two new tests (and the one we updated)

`cargo test` — **131 passing** (129 + 2). One existing test was updated for TLP timing.

- **`tail_loss_probe_retransmits_the_last_segment`** (connection) — the §9 trace: send a tail, and
  the probe retransmits the last segment at the PTO (~100 ms), *before* the RTO (200 ms); it fires only
  once. This is the capability the stack lacked — fast tail-loss recovery.
- **`rack_marks_earlier_segment_lost_once_reorder_window_passes`** (queue) — a later segment is
  SACKed; the earlier one is *not* declared lost within the reordering window, *is* once it elapses,
  and isn't resent again after its timer resets. This pins RACK's time-based rule and its
  reordering tolerance.
- **`connection_retransmits_then_clears_on_ack`** (updated) — previously asserted the retransmit came
  at the RTO; now the **TLP** resends the tail at ~RTO/2, and the ack-clears-it / Karn behavior holds
  (no fresh sample; the RTO stays the 200 ms default since a probe doesn't back off). The change *is*
  the feature: the tail is now repaired earlier.

## 12. Why this, not that

**Why time-based detection over counting?** Counting (3 dup-ACKs / 3 SACKed above) is fooled by
reordering and blind to the tail. Time — "a later segment was delivered and the reorder window
passed" — is robust to both. (§§1–2.)

**Why a Tail Loss Probe instead of just shortening the RTO?** A short RTO would spuriously fire on
every RTT spike, collapsing cwnd needlessly. TLP is a *single, surgical* probe that only fires when
the tail is genuinely idle, leaving the (conservative) RTO as the backstop. (§5.)

**Why `PTO = RTO/2` instead of RFC 8985's `2·SRTT`?** To guarantee `PTO < RTO` with no special cases,
so the probe always beats the timeout. It's a documented simplification; the property that matters
holds unconditionally. (§8, §C.)

**Why additive, not a replacement?** Lower risk against the existing tested recovery, and it lets the
chapter present RACK-TLP cleanly on its own. A production stack replaces DupThresh with RACK; we
compose them, RACK/TLP firing first. (§7.)

**Why `reo_wnd = RTO/4`?** ≈ SRTT/4 (the RFC's starting window), erring slightly conservative. DSACK
adaptation (shrinking it on non-reordering paths) is the exercise. (§4.)

## 13. Honesty: what production does that we don't

- **No congestion reaction on RACK loss.** A real RACK enters loss recovery and reduces cwnd when it
  declares a loss; ours retransmits the hole without a cwnd change (TLP is a probe, also no reaction).
  Correct retransmission, simplified congestion response (E3).
- **Fixed reordering window.** RFC 8985 adapts `reo_wnd` using DSACK (grows it when the path reorders,
  shrinks it otherwise); we use a fixed `RTO/4`. No DSACK feedback (E2).
- **`PTO = RTO/2`, not `2·SRTT` + delayed-ACK budget.** A simplification (§8); the RFC's PTO also adds
  a `WCDelAckT` term for the receiver's delayed-ACK timer.
- **TLP sends a retransmission, not (optionally) new data.** RFC 8985 allows the probe to be *new*
  unsent data when available (more useful than a duplicate); we always retransmit the last segment.
- **No spurious-probe detection.** A TLP that turns out unnecessary should be detected via DSACK and
  its (potential) cwnd reaction undone; we just tolerate the duplicate.
- **Three timers, not one.** We keep dup-ACK, RACK/TLP, and the RTO as separate composed mechanisms;
  Linux unifies loss detection under RACK with the RTO as backstop.

None of these are bugs in what we built — RACK's time-based detection and TLP's tail recovery are
real and tested. They're the refinements that make it fully conformant.

## 14. Rebuild it yourself — checklist + exercises

**Checklist**

- [ ] Add `rack_xmit_ts: u64`, `rack_end_seq: u32` to `RetxQueue`; update both in `ack` and
      `mark_sacked` to the most-recently-sent acked/SACKed segment.
- [ ] `rack_mark_lost(now, reo_wnd)`: retransmit each unacked segment sent before `rack_xmit_ts`,
      sequenced below `rack_end_seq`, with `now − sent_at > reo_wnd`.
- [ ] `retransmit_last(now)`: the highest-sequence non-SACKed segment (the probe).
- [ ] `Connection`: `tlp_deadline_ms`, `tlp_sent`; arm in `poll_transmit` (tail outstanding, not
      recovering) at `now + RTO/2`; reset on a forward-progress ACK.
- [ ] `on_tick`: RACK (`reo_wnd = RTO/4`) → TLP fire → RTO `due()` backstop, in that order.
- [ ] `cargo test` green (131), `cargo clippy -- -D warnings` clean.

**Exercises**

1. **E1 — multi-loss tail.** Send several segments, lose the last *two*; show the TLP probe's ACK lets
   RACK mark the second-to-last lost too, recovering both before the RTO.
2. **E2 — DSACK-adaptive `reo_wnd`.** Parse duplicate SACK blocks (RFC 2883) and grow `reo_wnd` when
   the peer reports it received a duplicate (the path reordered); shrink it otherwise.
3. **E3 — congestion reaction.** On a RACK-declared loss, enter fast recovery (set ssthresh, reduce
   cwnd) like a dup-ACK loss; test that cwnd halves.
4. **E4 — TLP new-data probe.** When unsent data is available at the PTO, probe with *new* data
   instead of a retransmission; verify it's more useful than a duplicate.
5. **E5 — measure it.** Under `tc qdisc … netem loss 5%`, time a series of short HTTP responses with
   TLP on vs off; watch the tail-latency tail (the p99) shrink.

Make Anki cards from the RACK loss condition and `PTO ≈ RTO/2` — those are the two ideas that *are*
RACK-TLP.

## 15. What comes after

RACK-TLP is the modern loss-detection capstone; with it, the stack detects loss the way today's
internet does. The remaining frontiers are breadth, not core: **CUBIC/BBR** congestion control (RACK
handles *detection*; these change the *growth/probe* law), **SYN cookies** and **`SO_KEEPALIVE`** for
the last robustness corners, a **multi-connection socket façade**, and the live validation that needs
a network (`packetdrill`, `iperf3`). The protocol engine — handshake through modern recovery and
RFC 5961 hardening — is complete.

---

# Volume II — the exhaustive reference

## A. RFC 8985 in full: RACK and TLP, step by step

RFC 8985 ("The RACK-TLP Loss Detection Algorithm for TCP") has two cooperating parts.

**RACK** (Recent ACKnowledgment), per ACK that acks/SACKs new data:

```text
   1. Update RACK.rtt and, for each newly acked/SACKed segment, track the most-recently-SENT one:
        RACK.xmit_ts = that segment's transmit time;  RACK.end_seq = its end sequence.
   2. Compute reo_wnd (≈ RACK.min_RTT / 4, grown via DSACK).
   3. For each outstanding segment S sequenced below RACK.end_seq and sent before RACK.xmit_ts:
        if  now − S.xmit_ts > reo_wnd   → S is lost (retransmit it);
        else                             → schedule a reordering timer to recheck later.
```

**TLP** (Tail Loss Probe):

```text
   1. After transmitting, if all sent data is acked OR more remains to send, do nothing special.
      If the tail is outstanding with nothing new to send, arm PTO = 2·SRTT (+ delayed-ACK budget),
      bounded below the RTO.
   2. On PTO: transmit a probe — new data if available, else retransmit the last segment. Arm the RTO.
   3. The probe's ACK either recovers the tail directly or, via RACK, exposes the losses to repair.
```

Our implementation: step RACK-1 is in `ack`/`mark_sacked`; RACK-2 uses `RTO/4`; RACK-3 is
`rack_mark_lost` (we retransmit when over the window; we don't keep a separate reordering timer — the
next `on_tick` rechecks). TLP-1 arms `tlp_deadline = now + RTO/2` in `poll_transmit`; TLP-2 is the
`on_tick` fire (`retransmit_last`); TLP-3 is ordinary ACK processing + RACK.

## B. The reordering window, and DSACK adaptation

`reo_wnd` trades detection speed against spurious retransmits:

```text
   reo_wnd too small  → real reordering looks like loss → spurious retransmits, needless cwnd cuts
   reo_wnd too large  → real losses detected late → throughput dips
   RFC 8985 start      → reo_wnd = min(RACK.min_RTT/4, SRTT/4)
   DSACK adaptation    → each time a DSACK shows we retransmitted unnecessarily (the path reordered
                         more than reo_wnd assumed), grow reo_wnd; decay it back on quiet paths.
```

We use a fixed `RTO/4` (≈ SRTT/4, slightly larger). DSACK (RFC 2883) reports a *duplicate* receipt —
"I already had that byte" — which is precisely the signal that a retransmit was spurious; feeding it
back to grow `reo_wnd` (E2) is what makes RACK self-tuning on reordering paths.

## C. TLP: PTO computation and the two-probe schedule

RFC 8985's PTO:

```text
   PTO = 2·SRTT + WCDelAckT          (WCDelAckT ≈ the receiver's worst-case delayed-ACK timer, ~200ms)
   if a single packet is outstanding, PTO = max(PTO, that packet's expected ACK time)
   PTO is capped so it never exceeds the RTO (the RTO must remain the final backstop).
```

The RFC allows **up to two** TLP probes before falling to the RTO. We send **one** (`tlp_sent`), then
rely on the RTO — simpler, and one probe already converts the common single-tail-loss into a fast
recovery. Our `PTO = RTO/2` folds the "must be < RTO" cap into the formula directly.

## D. RACK-TLP vs dup-ACK / RFC 6675 — what each catches

```text
   scenario                         dup-ACK (5681)   RFC 6675 (SACK)   RACK-TLP (8985)
   ──────────────────────────────   ──────────────   ───────────────   ───────────────
   mid-stream single loss           yes (3 dup)      yes               yes (time)
   mid-stream multiple losses       NewReno: 1/RTT   yes (all holes)   yes (all, by time)
   reordering (not loss)            spurious retx    spurious retx     tolerated (reo_wnd)
   tail loss (last segment)         NO (no dup-ACKs) NO (nothing above) YES (TLP probe)
   needs SACK?                      no               yes               no (RACK), SACK helps
```

RACK-TLP is the superset: it catches everything the count-based detectors do, plus reordering
tolerance and the tail. That's why it's the modern default — Linux uses RACK-TLP as the primary
detector, with dup-ACK/6675 effectively subsumed and the RTO as backstop.

## E. Comparison to real stacks — Linux, the sysctls

```text
   aspect                  Linux                         ours (Doc 24)
   ─────────────────────   ───────────────────────────   ──────────────────────────
   primary loss detection  RACK (replaces DupThresh)     RACK additive to dup-ACK/6675
   reo_wnd                  adaptive (DSACK), min_RTT/4   fixed RTO/4 (E2)
   TLP                      yes, up to 2 probes, 2·SRTT   1 probe, RTO/2
   TLP probe payload        new data if available         retransmit last (E4)
   spurious-probe undo      DSACK-based                   tolerated
   congestion on RACK loss  yes (recovery)                no (E3)
   relevant sysctl          net.ipv4.tcp_recovery (RACK)  —
```

Linux enabled RACK by default in 4.18 (`tcp_recovery` bit 1). The shape is identical; our column is
"real RACK-TLP core, with the adaptive/congestion refinements as exercises."

## F. Extended FAQ — twenty-five questions a careful reader asks

1. **What does RACK stand for?** Recent ACKnowledgment — loss detection based on the *time* the most
   recent acked segment was sent.
2. **What's the core RACK rule?** A segment is lost if a later-sent segment was acked/SACKed and more
   than the reordering window has elapsed since the earlier one was sent.
3. **Why is that better than counting dup-ACKs?** It's robust to reordering and works at the tail,
   where no dup-ACKs arrive.
4. **What's the tail-loss problem?** The last segment is lost → nothing arrives after it → no
   dup-ACKs, nothing to SACK → recovery waits for the full RTO.
5. **How does TLP fix it?** It sends one probe at ≈ RTO/2; the probe's ACK either recovers the tail or
   lets RACK see the loss — before the RTO.
6. **What's the PTO?** The Probe Timeout — when the TLP fires. We use RTO/2; RFC 8985 uses ≈ 2·SRTT
   capped below the RTO.
7. **Why must PTO < RTO?** So the probe fires before the timeout; otherwise it's pointless.
8. **What does the probe send?** We retransmit the last segment; RFC allows new data if available.
9. **How does RACK know "the most recently sent acked segment"?** We track `rack_xmit_ts`/`rack_end_seq`
   in `ack`/`mark_sacked` as segments are acknowledged.
10. **What's the reordering window?** The slack before declaring loss; we use RTO/4 (≈ SRTT/4).
11. **What if it's too small?** Reordering looks like loss → spurious retransmits.
12. **Too large?** Real losses detected late → throughput dips.
13. **Does RACK need SACK?** No — RACK works on cumulative ACKs too; SACK makes it more precise.
14. **Where does RACK run in our code?** `on_tick` calls `rack_mark_lost(reo_wnd)` before the RTO
    check.
15. **Where is the TLP armed?** At the end of `poll_transmit`, when the tail is outstanding and we're
    not recovering.
16. **Where does it fire?** `on_tick`, before the RTO backstop.
17. **Why run RACK/TLP before the RTO `due()`?** They fire earlier and reset send timers, so the RTO
    won't double-retransmit the same segment.
18. **One probe or many?** One per tail (`tlp_sent`); a forward-progress ACK re-arms it. RFC allows up
    to two.
19. **Does a RACK loss cut cwnd?** Not in our implementation (a simplification); a full RACK enters
    recovery. TLP is a probe and never cuts cwnd.
20. **What about a spurious TLP (the tail wasn't lost)?** The probe is a duplicate; the peer dup-ACKs;
    harmless. DSACK would let a real stack detect and undo it.
21. **Is this additive or a replacement?** Additive here (alongside dup-ACK/NewReno/6675); a
    production stack replaces DupThresh with RACK.
22. **What existing test changed and why?** `connection_retransmits_then_clears_on_ack` — the tail is
    now probed at ~RTO/2 (TLP) instead of waiting for the RTO.
23. **Does RACK use timestamps (Doc 16)?** It uses per-segment *send* times (recorded since Doc 12);
    Doc 16's TCP timestamps option is a related but separate RTT mechanism.
24. **What's `retransmit_last`?** The TLP target: the highest-sequence non-SACKed outstanding segment.
25. **Biggest thing still missing?** DSACK-adaptive `reo_wnd`, a congestion reaction on RACK loss, and
    new-data probes — all exercises.

## G. Anki starter deck

```text
Q: RACK detects loss by…?  A: TIME — a later-sent segment was acked + the reorder window elapsed.
Q: The count-based detectors' two blind spots?  A: reordering (spurious retx) and the tail (no dup-ACKs).
Q: The tail-loss problem?  A: last segment lost → no dup-ACKs / nothing to SACK → wait for the RTO.
Q: TLP fixes it how?  A: one probe at ~RTO/2 elicits an ACK/SACK before the RTO.
Q: PTO in our stack?  A: RTO/2 (RFC 8985: ~2·SRTT, capped below the RTO).
Q: Why must PTO < RTO?  A: the probe must fire before the timeout to help.
Q: RACK's reference point?  A: xmit_ts/end_seq of the most recently SENT acked/SACKed segment.
Q: RACK loss condition?  A: unacked, sent before RACK.xmit_ts, below RACK.end_seq, now−sent > reo_wnd.
Q: reo_wnd value here?  A: RTO/4 (≈ SRTT/4); RFC adapts it via DSACK.
Q: Does RACK need SACK?  A: no (works on cumulative ACKs; SACK sharpens it).
Q: on_tick order?  A: RACK → TLP → RTO due() (earlier detectors first, RTO as backstop).
Q: One TLP probe or more?  A: one per tail here; RFC allows up to two.
Q: Does RACK loss cut cwnd in our stack?  A: no (simplification); a full RACK enters recovery.
Q: What does the TLP retransmit?  A: the last (highest-seq) outstanding segment.
Q: Linux default since 4.18?  A: RACK-TLP (tcp_recovery).
```

## H. Glossary

- **RACK** — Recent ACKnowledgment: time-based loss detection (RFC 8985).
- **TLP** — Tail Loss Probe: a probe at ≈ RTO/2 to recover tail loss before the RTO.
- **PTO** — Probe Timeout: when the TLP fires.
- **reo_wnd** — reordering window: the slack before a gap is declared a loss.
- **RACK.xmit_ts / end_seq** — the send time and right edge of the most-recently-sent acked segment.
- **Tail loss** — loss of the last segment(s) of a flow, invisible to dup-ACK/SACK counting.
- **DSACK** — Duplicate SACK (RFC 2883): reports a duplicate receipt; the signal for adapting reo_wnd.
- **Spurious retransmit** — retransmitting data that wasn't actually lost (reordering mistaken for loss).
- **min_RTT** — the smallest RTT observed; the basis for the reordering window in RFC 8985.

## I. Reference tables

**I.1 — RACK loss condition (per outstanding segment S)**

```text
   condition                                            meaning
   ──────────────────────────────────────────────────  ───────────────────────────────────────
   !S.sacked                                            still outstanding
   S.sent_at_ms < rack_xmit_ts                          a later-sent segment was already acked
   seq::before(S.start_seq, rack_end_seq)               S is sequenced below that acked segment
   now − S.sent_at_ms > reo_wnd                         the reordering window has elapsed → LOST
```

**I.2 — the three loss-recovery timers, by when they fire**

```text
   mechanism     fires at        catches                         congestion reaction
   ───────────   ─────────────   ─────────────────────────────   ───────────────────
   RACK          ~RTO/4 (reo)    reordering-tolerant losses      none (ours; E3)
   TLP           ~RTO/2 (PTO)    tail loss                       none (a probe)
   RTO due()     full RTO        anything left (backstop)        cwnd → 1 MSS, slow start
```

**I.3 — what RACK-TLP adds over Docs 10/20/21**

```text
   capability                         before Doc 24   after Doc 24
   ────────────────────────────────   ─────────────   ────────────
   single mid-stream loss             yes             yes
   multiple losses / RTT (SACK)       yes (6675)      yes
   reordering tolerance               no              yes (reo_wnd)
   tail-loss recovery before the RTO  no              yes (TLP)
```

> Re-type `rack_mark_lost`, `retransmit_last`, and the `on_tick` RACK→TLP→RTO order with the book
> closed, then `cargo test`. When your stack recovers a dropped *last* segment at half the RTO instead
> of waiting it out — and shrugs off reordering instead of retransmitting needlessly — you've built
> the loss detection the modern internet runs on.
