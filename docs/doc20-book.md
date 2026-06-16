# Doc 20 — TCP, Part 18: NewReno — Recovering From *Multiple* Losses in One Window (RFC 6582)

> Goal: fix the one place our congestion control quietly falls off a cliff. Doc 10 gave us RFC 5681
> Reno — slow start, congestion avoidance, fast retransmit, fast recovery. It recovers beautifully
> from a *single* lost segment without an RTO. But drop **two** segments in the same window and Reno
> recovers the first, declares victory on the very next ACK, deflates its window, and then has to
> *wait for a retransmission timeout* to even notice the second loss — a multi-hundred-millisecond
> stall that tanks throughput exactly when the network is already stressed.
>
> **NewReno** (RFC 6582) is a tiny, surgical change that fixes this without SACK: remember the
> sequence number that was outstanding when recovery began (`recover`), and on each new ACK during
> recovery ask one question — *did this ACK cover everything up to `recover`?* If yes, it's a **full
> ACK** and recovery is genuinely done. If no, it's a **partial ACK**: one segment came through but
> another is still missing, so retransmit the next hole *immediately* and stay in recovery. Repeat
> until the window is whole. No timeout, no stall, one new state variable.
>
> This is the natural partner to Doc 18's SACK: SACK tells us *which* islands the receiver has;
> NewReno is how a sender *without* SACK still escapes the multiple-loss trap using nothing but the
> cumulative ACK. Tomorrow (RFC 6675) we wire SACK into loss recovery proper; today we make the
> SACK-less path correct first, because every real stack keeps it as the fallback.

**Contents**

Volume I — the chapter
1. The mental model: one hole vs several in a window
2. Reno's flaw, watched in slow motion
3. NewReno's fix in one sentence
4. Full ACK vs partial ACK — the single comparison
5. The `recover` variable: why SND.NXT, frozen at entry
6. cwnd during recovery: inflate, deflate, and the pipe it's tracking
7. Where the logic lives: byte-oriented module, sequence-aware connection
8. The Rust: a clean seam between cwnd math and recovery sequencing
9. A fully worked two-loss trace — Reno stalls, NewReno doesn't
10. The code, walked end to end
11. Verification — the three new tests, and why each exists
12. Why this, not that
13. Honesty: what production does that we don't
14. Rebuild it yourself — checklist + exercises
15. What the next day adds

Volume II — the exhaustive reference
- A. RFC 6582 in full: the algorithm, step by step
- B. RFC 5681 fast recovery recap — the six steps
- C. The two-loss arithmetic, exhaustively
- D. The family tree: Tahoe → Reno → NewReno → SACK/6675 → CUBIC → BBR
- E. "Careful" vs "less careful" NewReno, and the bugfix variable
- F. Comparison to real stacks — Linux, FreeBSD, lwIP, smoltcp
- G. Performance — what NewReno buys, and where it still loses
- H. Extended FAQ — thirty questions a careful reader asks
- I. Anki starter deck
- J. Glossary
- K. Reference tables

---

# Volume I — the chapter

## 1. The mental model: one hole vs several in a window

Recall the shape of fast retransmit/recovery from Doc 10. A sender has a window of segments in
flight. One is lost. Every segment that arrives *after* the hole makes the receiver re-send the same
cumulative ACK (it can't advance past the gap). Three of those **duplicate ACKs** are the sender's
cue that a segment is lost — without waiting for the retransmission timer — so it retransmits the
hole and halves its window. That's fast retransmit (the trigger) and fast recovery (the window
management while the retransmission is in flight).

This works perfectly for **one** loss. The trouble is a window with **two or more** losses:

```text
   window in flight:   [S1][S2][S3][S4][S5][S6]      (six segments)
   lost:                    ✗            ✗            (S2 and S5 both dropped)
   arrives:            [S1]    [S3][S4]    [S6]
```

When the retransmitted S2 finally reaches the receiver, the receiver can deliver S2, S3, S4 — but
*not* S5 (still missing) — so its cumulative ACK jumps to the start of S5 and stops. That ACK
acknowledges *new* data (S2–S4), so it is **not** a duplicate ACK. It's a real, forward-moving ACK
— but it does **not** acknowledge everything that was outstanding when we started recovering. It is a
**partial ACK**, and what a stack does with it is the entire difference between Reno and NewReno.

## 2. Reno's flaw, watched in slow motion

Plain RFC 5681 Reno (our Doc 10 code) has exactly one rule for "a new ACK arrives during fast
recovery": *recovery is over.* Re-read the old congestion code:

```rust
pub fn on_ack(&mut self, acked: u32) {
    self.dup_acks = 0;
    if self.in_recovery {
        self.in_recovery = false;     // ← ANY new ACK ends recovery
        self.cwnd = self.ssthresh;    //   deflate to ssthresh
        return;
    }
    /* … slow start / congestion avoidance … */
}
```

Watch it handle the two-loss window above:

```text
   t0  S1..S6 in flight; S2, S5 lost.
   t1  3 dup ACKs for "give me S2"  → fast retransmit S2; ssthresh = FlightSize/2; in_recovery = true.
   t2  retransmitted S2 arrives; receiver delivers S2,S3,S4 → ACK jumps to start-of-S5 (PARTIAL).
   t3  Reno sees a new ACK → "recovery done!" → in_recovery = false, cwnd = ssthresh.
   t4  …but S5 is still lost. There are no more dup ACKs coming (nothing is arriving past S5 yet).
   t5  Reno waits. And waits. Until the RETRANSMISSION TIMER fires (hundreds of ms) for S5.
   t6  RTO → cwnd collapses to 1 MSS, slow-start restart. Throughput falls off a cliff.
```

The killer is t3→t5: Reno *exits recovery on the partial ACK*, so it has no mechanism left to notice
the second loss quickly. The connection idles until the RTO. On a path with even modest loss, a
window routinely loses two segments, and Reno pays an RTO every time — its throughput under loss is
far worse than the math says it should be.

## 3. NewReno's fix in one sentence

> Stay in recovery until an ACK covers **everything** that was outstanding when recovery began; treat
> every ACK short of that as "retransmit the next hole and keep going."

That's it. NewReno adds one variable, `recover`, set to the highest sequence number transmitted at
the instant recovery starts (i.e. `SND.NXT`). Then:

- A new ACK with `SEG.ACK ≥ recover` is a **full ACK** — every segment from the lossy window is now
  acknowledged → recovery is genuinely complete, deflate and exit.
- A new ACK with `SEG.ACK < recover` is a **partial ACK** — at least one more segment in that window
  was lost → retransmit the segment at `SEG.ACK` (the next hole), partially deflate, and **stay in
  recovery**.

In the two-loss trace, t3 becomes: "partial ACK → retransmit S5 right now, stay in recovery." The
retransmitted S5 arrives an RTT later, the receiver delivers S5,S6, the ACK reaches `recover` → full
ACK → exit. Two losses, two RTTs, **no RTO**, no cliff.

## 4. Full ACK vs partial ACK — the single comparison

Everything hinges on one wrap-safe comparison. In `src/tcp.rs`, in the new-data branch of the ACK
handler:

```rust
if self.cong.in_recovery() && seq::before(th.ack, self.recover) {
    // PARTIAL ACK: SEG.ACK < recover → more holes remain
    self.cong.on_partial_ack(acked);
    if let Some(pkt) = self.retx.fast_retransmit(now_ms) {
        return Some(pkt);            // retransmit the next hole at once
    }
} else {
    // either not in recovery (ordinary slow start / CA),
    // or a FULL ACK (SEG.ACK ≥ recover) that ends recovery
    self.cong.on_ack(acked);
}
```

`seq::before(th.ack, self.recover)` is "`SEG.ACK` is strictly behind `recover` on the wrapping
32-bit circle." Its negation, the `else`, is `SEG.ACK ≥ recover` — the full ACK. We deliberately let
the full ACK fall into `on_ack`, whose existing in-recovery branch (unchanged from Doc 10) deflates
to `ssthresh` and clears `in_recovery`. So we reused Reno's *exit* and only added the *partial-ACK*
path. Minimal surface, maximal reuse.

Why is the full ACK routed to `on_ack` rather than handled inline? Because Reno's `on_ack` already
does exactly the right thing for a full ACK — deflate, exit — and it's already tested. NewReno only
needed to *intercept the partial case before* it reaches that code.

## 5. The `recover` variable: why SND.NXT, frozen at entry

`recover` is the answer to "what counts as 'everything that was outstanding when we started
recovering?'" The moment we enter fast recovery, the highest byte we've sent is `SND.NXT`. Every
segment in the lossy window has a sequence number `< SND.NXT`. So `recover = SND.NXT` at entry is
precisely "the right edge of the window we're trying to repair."

```rust
if self.cong.on_dup_ack(self.flight_size()) {   // returns true on the 3rd dup ACK
    self.recover = self.send.nxt;                // freeze the recovery point (RFC 6582)
    if let Some(pkt) = self.retx.fast_retransmit(now_ms) {
        return Some(pkt);
    }
}
```

Two subtleties:

- **Frozen.** We snapshot `SND.NXT` *once*, at entry. During recovery we may transmit *new* data too
  (the inflated cwnd can allow it), pushing `SND.NXT` higher — but `recover` does not move. A full
  ACK only needs to cover the original window, not the new data. (New data sent during recovery is
  itself protected by the *next* recovery episode if it's lost.)
- **It lives in the `Connection`, not the congestion module.** `recover` is a *sequence number*, and
  sequence space is the connection's concern. The congestion module stays blissfully
  sequence-agnostic — it only ever sees byte *counts*. (More on this seam in §7.)

`recover` is meaningless outside recovery; we initialise it to the ISS and simply never read it
unless `in_recovery()` is true.

## 6. cwnd during recovery: inflate, deflate, and the pipe it's tracking

Fast recovery's window arithmetic is an estimate of "how much data is actually in the network right
now" (the *pipe*), so we can keep sending without overflowing it. Tracing one episode:

```text
   entry (3rd dup ACK):  ssthresh = max(FlightSize/2, 2·MSS)
                         cwnd     = ssthresh + 3·MSS        (the 3 segments that triggered dup ACKs
                                                             have LEFT the network → room for 3 more)
   each extra dup ACK:   cwnd += MSS                        (another segment drained → room for 1 more)
   partial ACK:          cwnd  = cwnd − acked + MSS         (acked bytes left; 1 seg's worth freed)
   full ACK (exit):      cwnd  = ssthresh                   (deflate to the post-loss steady state)
```

The partial-ACK line is NewReno's contribution. `on_partial_ack`:

```rust
pub fn on_partial_ack(&mut self, acked: u32) {
    self.dup_acks = 0;
    self.cwnd = self.cwnd.saturating_sub(acked).saturating_add(MSS).max(MSS);
}
```

`− acked` removes the data the partial ACK confirmed has left the network; `+ MSS` adds back room for
the one segment we're about to retransmit (RFC 6582 §3 step 5: "add back one SMSS"). The net effect
keeps the pipe estimate honest across a multi-loss recovery instead of letting it either balloon or
collapse. `dup_acks = 0` because a partial ACK is a *real* (forward-moving) ACK, not a duplicate.

(RFC 6582's exit is technically `cwnd = min(ssthresh, max(FlightSize, MSS) + MSS)`; we deflate to
`ssthresh`, matching our existing Reno exit, which is the common simplification — §13.)

## 7. Where the logic lives: byte-oriented module, sequence-aware connection

A design note worth dwelling on, because it's why today's change is so small. Our `CongestionControl`
(Doc 10) was deliberately built to know *nothing* about sequence numbers — it takes byte counts
(`on_ack(acked)`, `on_dup_ack(flight_size)`, `on_timeout(flight_size)`) and returns cwnd. That made
it trivially unit-testable in isolation (its tests are pure arithmetic, no packets).

NewReno is fundamentally about *sequence numbers* (`recover`, "does this ACK reach it?"). So rather
than pollute the clean byte-oriented module, we split the responsibility:

```text
   ┌─────────────────────────────────────────┐     ┌──────────────────────────────────────┐
   │ Connection (src/tcp.rs) — knows seqs     │     │ CongestionControl — knows bytes/cwnd  │
   │ • recover = SND.NXT at entry             │     │ • in_recovery()  (query)              │
   │ • full vs partial: seq::before(ack,recov)│ ──▶ │ • on_partial_ack(acked)  (deflate)    │
   │ • drives retx.fast_retransmit(next hole) │     │ • on_ack(acked)  (exit, unchanged)    │
   └─────────────────────────────────────────┘     └──────────────────────────────────────┘
```

The connection decides *what kind* of ACK this is (a sequence question) and *which segment* to
retransmit (a sequence question); the module only adjusts cwnd (a byte question). The module gained
two tiny methods and not one line of sequence logic. Every existing congestion test still passes
untouched.

## 8. The Rust: a clean seam between cwnd math and recovery sequencing

Two small Rust points.

**`in_recovery()` as a `&self` query keeps the decision in the caller.** The connection asks the
module "are we recovering?" and combines that with its own sequence comparison. The alternative —
passing `th.ack` and `recover` *into* the module — would have forced the module to import `seq` and
reason about wraparound, duplicating logic the connection already owns. A boolean query is the
narrowest possible interface across the seam.

**`saturating_sub`/`saturating_add` for window arithmetic.** `cwnd` is `u32` and recovery math
subtracts then adds; a naive `cwnd - acked` could underflow if `acked > cwnd` (possible with an ACK
that jumps a long way). `saturating_sub` floors at 0, `saturating_add` caps at `u32::MAX`, and the
trailing `.max(MSS)` guarantees the window never drops below one segment — you can always send *one*
packet. Three combinators encode "do the arithmetic, but never produce a nonsensical window."

**The early `return Some(pkt)` on a partial ACK** mirrors the existing fast-retransmit return: a
partial ACK is a pure acknowledgement (no data, no FIN), so once we've queued its retransmission
there is nothing else to do in `on_segment` — return the packet and let the event loop send it.

## 9. A fully worked two-loss trace — Reno stalls, NewReno doesn't

Concrete numbers, `MSS = 1460`. The connection has grown `cwnd` to `3·MSS` and has three segments in
flight; the first two are lost. (This is exactly the scenario the unit test drives.)

Setup after two slow-start rounds: `SND.UNA = 1+3·MSS`, three segments out —
`S4=[1+3·MSS, 1+4·MSS)`, `S5=[1+4·MSS, 1+5·MSS)`, `S6=[1+5·MSS, 1+6·MSS)` — so `SND.NXT = 1+6·MSS`.
S4 and S5 are lost; S6 arrives.

```text
   #   event                                    NewReno action                         cwnd / state
   ──  ───────────────────────────────────────  ────────────────────────────────────   ─────────────────────
   1   S6 arrives at peer; gap at S4            peer dup-ACKs 1+3·MSS                    (3 dup ACKs follow)
   2   dup ACK #1 (ack 1+3·MSS)                 dup_acks = 1                            cwnd 3·MSS, no recovery
   3   dup ACK #2                               dup_acks = 2                            cwnd 3·MSS
   4   dup ACK #3                               recover = SND.NXT = 1+6·MSS;            ssthresh = max(3·MSS/2,
                                                fast-retransmit S4                       2·MSS) = 2·MSS;
                                                                                         cwnd = 2·MSS + 3·MSS = 5·MSS
                                                                                         in_recovery = true
   5   retx S4 arrives; S5 still lost          peer delivers S4 (+ buffered S6? no,    —
                                                S5 gap) → ACK 1+4·MSS  ← PARTIAL
   6   partial ACK 1+4·MSS (< recover)         on_partial_ack(MSS): cwnd =             cwnd = 5·MSS
                                                5·MSS − MSS + MSS; fast-retransmit S5    still in_recovery
   7   retx S5 arrives                          peer delivers S5, S6 →                  —
                                                ACK 1+6·MSS  ← FULL (== recover)
   8   full ACK 1+6·MSS (≥ recover)            on_ack: deflate, exit recovery          cwnd = ssthresh = 2·MSS
                                                                                         in_recovery = false
```

Now overlay what **Reno** would have done at step 6: it sees a new ACK, declares recovery over,
deflates to `ssthresh`, and — because S5's loss only reveals itself through dup ACKs that aren't
coming — sits idle until S5's retransmission *timer* fires (step "7-Reno": RTO → cwnd = 1·MSS,
slow-start restart). NewReno repairs S5 at step 6 in the same RTT; Reno eats a timeout. Same two
losses, wildly different throughput.

## 10. The code, walked end to end

The whole feature is one new field, two new module methods, and a five-line decision.

**The field** (`src/tcp.rs`):

```rust
struct Connection {
    /* … */
    recover: u32,   // RFC 6582: SND.NXT frozen at fast-recovery entry
}
// initialised to `iss` in both accept() and connect(); only read while in_recovery().
```

**The module methods** (`src/congestion.rs`):

```rust
pub fn in_recovery(&self) -> bool { self.in_recovery }

pub fn on_partial_ack(&mut self, acked: u32) {
    self.dup_acks = 0;
    self.cwnd = self.cwnd.saturating_sub(acked).saturating_add(MSS).max(MSS);
}
```

**Entry** — snapshot `recover` when the 3rd dup ACK triggers fast retransmit:

```rust
if self.cong.on_dup_ack(self.flight_size()) {
    self.recover = self.send.nxt;
    if let Some(pkt) = self.retx.fast_retransmit(now_ms) { return Some(pkt); }
}
```

**Partial vs full** — on every new-data ACK:

```rust
if self.cong.in_recovery() && seq::before(th.ack, self.recover) {
    self.cong.on_partial_ack(acked);
    if let Some(pkt) = self.retx.fast_retransmit(now_ms) { return Some(pkt); }
} else {
    self.cong.on_ack(acked);   // slow start / CA, or full-ACK exit (unchanged Reno)
}
```

`retx.fast_retransmit` (Doc 12/18) already resends "the oldest segment the peer hasn't SACKed" and
resets its timer — which, after `SND.UNA` has advanced over the just-acked data, is exactly the next
hole. NewReno didn't need a new retransmission primitive; it only needed to *call* the existing one
on a partial ACK.

## 11. Verification — the three new tests, and why each exists

`cargo test` — **114 passing** (111 + 3). Two are pure congestion-module arithmetic; one drives a
full recovery through the connection.

- **`reports_recovery_state`** (congestion) — `in_recovery()` is false initially, true after the 3rd
  dup ACK, false after a full ACK. Pins the query the connection relies on.
- **`newreno_partial_ack_deflates_and_stays_in_recovery`** (congestion) — `on_partial_ack(MSS)`
  leaves cwnd unchanged (`−MSS+MSS`) and *stays* in recovery; `on_partial_ack(2·MSS)` deflates by one
  MSS and stays. Contrast the existing `new_ack_deflates_out_of_recovery`, where `on_ack` (a full
  ACK) deflates to ssthresh and *exits*. Together they pin the partial/full distinction at the
  module level.
- **`newreno_partial_ack_retransmits_the_next_hole_and_stays_in_recovery`** (connection) — the §9
  trace, end to end: grow cwnd to 3·MSS, lose two of three segments, and assert the *sequence
  numbers* of the retransmissions — first the 3rd-dup-ACK fast retransmit of S4 (`seq = 1+3·MSS`),
  then the partial-ACK retransmit of S5 (`seq = 1+4·MSS`), still in recovery — and that the full ACK
  exits recovery with `cwnd = ssthresh`. This is the test that would fail against plain Reno (Reno
  would *not* retransmit S5 on the partial ACK).

## 12. Why this, not that

**Why NewReno and not "just enable SACK"?** SACK (Doc 18) is negotiated — both ends must support it.
NewReno needs *nothing* from the peer; it works with the bare cumulative ACK every TCP speaks. It's
the universal fallback, which is why every stack ships it even alongside SACK. (Tomorrow's RFC 6675
is the SACK-aware recovery that supersedes NewReno *when SACK is on*.)

**Why route the full ACK through the old `on_ack` instead of handling it inline?** Reuse: Reno's
in-recovery exit (deflate to ssthresh, clear the flag) is already correct and already tested. NewReno
only needed to *intercept the partial case first*. Less new code, less new risk.

**Why keep `recover` in the connection, not the congestion module?** It's a sequence number;
sequence space is the connection's domain. Keeping the module byte-only preserved all its existing
tests and its isolation. (See §7.)

**Why retransmit on the partial ACK immediately, rather than wait for more dup ACKs?** Because a
partial ACK is *proof* the next segment is lost (the receiver advanced *past* the first hole but
stopped) — there's nothing to wait for. Waiting would reintroduce exactly the stall NewReno exists to
remove.

**Why `cwnd − acked + MSS` and not just leave cwnd alone?** The partial ACK is information: `acked`
bytes have demonstrably left the network. Subtracting keeps the pipe estimate from over-counting;
adding one MSS funds the retransmission. Leaving cwnd alone would slowly inflate it across a long
multi-loss recovery.

## 13. Honesty: what production does that we don't

- **No SACK-based recovery yet.** When SACK is negotiated, RFC 6675 (tomorrow) uses the SACK
  scoreboard and a `pipe` estimator to retransmit *all* known holes and keep sending new data during
  recovery — far better than NewReno's "one hole per RTT." NewReno is the no-SACK fallback; today we
  made that fallback correct.
- **Simplified exit.** RFC 6582 §3 step 5 sets `cwnd = min(ssthresh, max(FlightSize, MSS) + MSS)` on
  the full ACK; we deflate to `ssthresh`. The difference matters only at the margins of a drained
  pipe; our simplification matches our Doc 10 Reno exit and keeps one code path.
- **No "careful" NewReno / `recover` entry guard.** RFC 6582 §4 adds a guard so that dup ACKs for
  data already past `recover` (e.g. after an RTO) don't spuriously *re-enter* fast recovery for the
  same window. We rely on the `in_recovery` flag + dup-ACK reset, which handles the common cases; the
  full guard is exercise E2.
- **Still Reno-family, not CUBIC/BBR.** Modern Linux defaults to CUBIC (a cubic-growth curve that
  fills high bandwidth-delay-product pipes faster) or BBR (model-based, rate/RTT rather than
  loss-based). NewReno is the conformance baseline they're all measured against; implementing CUBIC
  is a natural later exercise.
- **No ECN.** Explicit Congestion Notification lets routers *mark* instead of *drop*, signalling
  congestion without loss. We react only to loss (dup ACKs / RTO).
- **The echo server never bulk-sends**, so cwnd rarely binds in practice — as noted since Doc 10. The
  machinery is real and tested; a bulk sender (the Doc 22 socket API) is what exercises it on the
  wire.

## 14. Rebuild it yourself — checklist + exercises

**Checklist**

- [ ] Add `in_recovery()` and `on_partial_ack(acked)` to `CongestionControl` (don't touch `on_ack`).
- [ ] Add `recover: u32` to the TCB; init to `iss` in both constructors.
- [ ] On the 3rd dup ACK (when `on_dup_ack` returns true), set `recover = SND.NXT` before
      retransmitting.
- [ ] On a new-data ACK: if `in_recovery() && seq::before(ack, recover)` → `on_partial_ack` +
      `fast_retransmit` + return; else → `on_ack`.
- [ ] `cargo test` green (114), `cargo clippy -- -D warnings` clean.

**Exercises**

1. **E1 — RFC 6582 exact exit.** Change the full-ACK exit to `cwnd = min(ssthresh, FlightSize + MSS)`
   and add a test showing the difference from a plain deflate when the pipe is nearly drained.
2. **E2 — the `recover` entry guard ("careful" NewReno, RFC 6582 §4).** Only enter fast recovery when
   the cumulative ACK is beyond the previous `recover`. Construct a post-RTO scenario where stale dup
   ACKs would otherwise re-trigger recovery, and show the guard prevents it.
3. **E3 — measure it.** With the live stack and `tc qdisc … netem loss 5%`, run a bulk transfer
   (needs the Doc 22 socket API) and compare completion time with the partial-ACK branch enabled vs
   stubbed out (force Reno). Watch the RTO stalls disappear.
4. **E4 — CUBIC.** Replace the congestion-avoidance growth with CUBIC's cubic function of time since
   the last loss; keep NewReno's recovery. Compare ramp-up on a high-BDP `netem delay 100ms` link.
5. **E5 — three losses.** Extend the unit test to a window with *three* losses and assert three
   successive partial-ACK retransmissions before the full ACK. Convince yourself NewReno is "one hole
   per RTT."

Make Anki cards from the partial-vs-full comparison and the `recover = SND.NXT` snapshot — those are
the two ideas that *are* NewReno.

## 15. What the next day adds

Tomorrow is **RFC 6675**: SACK-based loss recovery. Where NewReno repairs one hole per RTT using only
the cumulative ACK, RFC 6675 uses Doc 18's SACK scoreboard to know *every* hole at once, plus a
`pipe` estimator (bytes actually in flight) so the sender can keep transmitting *new* data during
recovery instead of going quiet. It's the difference between "limp out of loss one segment at a time"
and "repair everything and stay at line rate." NewReno is the floor; 6675 is the ceiling — and today
we made sure the floor is solid, because 6675 falls back to it whenever the peer doesn't speak SACK.

---

# Volume II — the exhaustive reference

## A. RFC 6582 in full: the algorithm, step by step

RFC 6582 ("The NewReno Modification to TCP's Fast Recovery Algorithm") modifies RFC 5681's fast
recovery. Its variable `recover` and six steps, in our terms:

```text
   On entering fast retransmit (the 3rd duplicate ACK), in addition to RFC 5681:
     (1)  record:  recover = SND.NXT                         ← the NewReno addition

   On each ACK that acknowledges NEW data, while in fast recovery:
     full ACK   (SEG.ACK ≥ recover):
        (2)  set cwnd = min(ssthresh, max(FlightSize, MSS) + MSS)   [we: cwnd = ssthresh]
        (3)  exit fast recovery
     partial ACK (SEG.ACK < recover):
        (4)  retransmit the first unacknowledged segment
        (5)  cwnd = cwnd − (bytes acked); if (bytes acked ≥ MSS) cwnd += MSS
        (6)  do NOT exit fast recovery; reset the retransmit timer for the retransmitted segment
```

Our `on_partial_ack` folds (5) into `cwnd − acked + MSS` (we always add the MSS back, the common
case where a partial ACK frees at least a segment); (4) and (6) are the connection's
`fast_retransmit` (which resends the first unacked, un-SACKed segment and resets its `sent_at_ms`).
(2)/(3) are our reused Reno exit via `on_ack`.

## B. RFC 5681 fast recovery recap — the six steps

For completeness, the RFC 5681 §3.2 fast retransmit/recovery NewReno modifies:

```text
   1.  On the 3rd dup ACK: ssthresh = max(FlightSize/2, 2·SMSS).
   2.  Retransmit the lost segment.
   3.  cwnd = ssthresh + 3·SMSS  (the 3 segments that triggered the dup ACKs have left the net).
   4.  For each additional dup ACK: cwnd += SMSS  (another segment has left); send if cwnd allows.
   5.  Transmit new data if cwnd and rwnd allow.
   6.  On the ACK of new data ("recovery ACK"): cwnd = ssthresh ("deflation"); exit.
```

Reno's step 6 fires on *any* new ACK — that's the flaw. NewReno splits step 6 into full (exit) vs
partial (retransmit, stay), per §A. Our code keeps steps 1–4 in `on_dup_ack`, step 6-full in
`on_ack`, and adds step 6-partial in `on_partial_ack` + the connection's routing.

## C. The two-loss arithmetic, exhaustively

`MSS = 1460`. Window of 3 segments, `cwnd = 3·MSS = 4380`, `SND.UNA = U`, `SND.NXT = U + 3·MSS`.
Segments `S4=[U, U+MSS)`, `S5=[U+MSS, U+2·MSS)`, `S6=[U+2·MSS, U+3·MSS)`. S4, S5 lost.

```text
   step  cumulative ACK     classification     cwnd                              FlightSize
   ────  ─────────────────  ─────────────────  ────────────────────────────────  ──────────────
   3 dup ACK U              enter recovery     ssthresh = max(3·MSS/2,2·MSS)=2·MSS  3·MSS
                                               cwnd = 2·MSS + 3·MSS = 5·MSS
   partial  U+MSS           U+MSS < U+3·MSS    cwnd = 5·MSS − MSS + MSS = 5·MSS    2·MSS (S5,S6)
            (S4 delivered)  → retransmit S5
   full     U+3·MSS         = recover          cwnd = ssthresh = 2·MSS            0
            (S5,S6 deliv.)  → exit recovery
```

The connection test asserts the *retransmission sequence numbers* at each step: `U = 1+3·MSS`, so the
fast retransmit is `seq = 1+3·MSS` (S4) and the partial-ACK retransmit is `seq = 1+4·MSS` (S5), with
the final cwnd `= 2·MSS`.

## D. The family tree: Tahoe → Reno → NewReno → SACK/6675 → CUBIC → BBR

```text
   algorithm   year   loss recovery                                    what it added
   ─────────   ────   ──────────────────────────────────────────────  ─────────────────────────────
   Tahoe       1988   any loss → slow-start restart (cwnd→1)           slow start, AIMD, fast retransmit
   Reno        1990   1 loss → fast recovery (no RTO); 2+ → RTO        fast recovery (Doc 10)
   NewReno     1999   2+ losses → partial ACKs, 1 hole/RTT, no RTO     the recover variable (TODAY)
   SACK/6675   2012   all holes known; pipe keeps sending new data     SACK scoreboard + pipe (Doc 21)
   CUBIC       2008   loss-based, cubic cwnd growth (high BDP)         time-based growth curve
   BBR         2016   model-based (bottleneck bw × RTT), not loss      probes bandwidth/RTT, ignores loss
```

NewReno is the hinge: it's the last refinement that needs *nothing from the peer*. Everything to its
right either needs SACK (6675) or is a different growth/probe philosophy (CUBIC/BBR) layered on top
of the same recovery machinery.

## E. "Careful" vs "less careful" NewReno, and the bugfix variable

RFC 6582 discusses two subtleties beyond the core:

- **The retransmit timer on partial ACKs (§3 step 6).** Resetting the timer for the segment
  retransmitted on a partial ACK (which `fast_retransmit` does) avoids a spurious RTO during a long
  recovery. We get this for free.
- **The `recover` entry guard (§4, "careful" variant).** After an RTO, `SND.NXT` has data that may
  draw dup ACKs which shouldn't *re-enter* fast recovery for a window already being handled. The
  guard: enter fast recovery only if the cumulative ACK is `> recover`. We use the simpler
  `in_recovery` flag, which prevents double-entry *within* an episode; the post-RTO interaction is
  exercise E2. RFC 6582 also distinguishes "Impatient" vs "Slow-but-Steady" variants for *when* to
  reset the retransmit timer during very long recoveries — beyond our scope.

## F. Comparison to real stacks — Linux, FreeBSD, lwIP, smoltcp

```text
   aspect                Linux             FreeBSD          lwIP             smoltcp        ours (Doc 20)
   ───────────────────   ───────────────   ──────────────   ──────────────   ───────────    ──────────────
   default CC            CUBIC             CUBIC/NewReno    NewReno-ish      Reno/NewReno   NewReno (this day)
   NewReno partial ACK   yes               yes              yes              yes            yes
   SACK recovery (6675)  yes               yes              partial          yes            tomorrow
   recover entry guard   yes               yes              simplified       simplified     simplified (E2)
   exit cwnd             min(ssthresh,…)   min(ssthresh,…)  ssthresh         ssthresh       ssthresh (E1)
   ECN                   yes               yes              optional         optional       no
```

Once again the column shape is "real algorithm, simplified hardening." Our NewReno *is* NewReno; the
gaps (exact exit, entry guard, CUBIC, ECN) are refinements, each an exercise.

## G. Performance — what NewReno buys, and where it still loses

The win is bounded by how many losses a window typically takes:

```text
   losses in one window   Reno cost              NewReno cost          SACK/6675 cost
   ────────────────────   ────────────────────   ───────────────────   ────────────────────
   0                      0                      0                     0
   1                      1 RTT (no RTO)         1 RTT                 1 RTT
   2                      1 RTT + 1 RTO          2 RTT                 ~1 RTT
   k                      1 RTT + (k−1) RTOs     k RTT                 ~1 RTT (+ pipe-paced)
```

NewReno converts Reno's `(k−1)` *timeouts* into `(k−1)` extra *round trips* — a few ms each on a LAN
instead of a few hundred. Where NewReno still loses to SACK: it repairs only **one hole per RTT**
(the cumulative ACK can only reveal the next hole after the previous one is filled), and it goes
*quiet* during recovery (it mostly retransmits rather than sending new data). RFC 6675 fixes both by
knowing all holes up front and pacing new data by the `pipe` estimate — tomorrow.

## H. Extended FAQ — thirty questions a careful reader asks

1. **What's a partial ACK, precisely?** A new (forward-moving) ACK during fast recovery whose
   `SEG.ACK < recover` — it acknowledges *some* but not *all* of the data outstanding when recovery
   began.
2. **And a full ACK?** A new ACK with `SEG.ACK ≥ recover` — everything from the lossy window is now
   acknowledged; recovery is done.
3. **Why does Reno break on two losses?** It exits recovery on the *first* new ACK (the partial one),
   so it has no fast mechanism left to find the second loss → it waits for an RTO.
4. **What single fact does NewReno add?** `recover` = `SND.NXT` at recovery entry, so it can tell
   partial from full.
5. **Why `SND.NXT` specifically?** It's the right edge of the window we're repairing — every
   in-flight segment is below it.
6. **Why freeze `recover` instead of tracking SND.NXT live?** New data sent *during* recovery is
   beyond the lossy window; a full ACK only needs to cover the original window. Freezing draws that
   line.
7. **Where is `recover` stored?** In the `Connection` — it's a sequence number, the connection's
   domain. The congestion module stays byte-only.
8. **What does a partial ACK do to cwnd?** `cwnd − acked + MSS`: remove what left the network, fund
   one retransmission.
9. **Does a partial ACK reset dup_acks?** Yes — it's a real ACK, not a duplicate.
10. **Does a partial ACK exit recovery?** No. That's the whole point. Only a full ACK exits.
11. **What gets retransmitted on a partial ACK?** The first unacknowledged (un-SACKed) segment —
    i.e. the next hole — via the existing `fast_retransmit`.
12. **Did NewReno need a new retransmission primitive?** No — `fast_retransmit` already resends the
    oldest non-SACKed segment and resets its timer.
13. **How does NewReno interact with SACK today?** `fast_retransmit` skips SACKed ranges (Doc 18), so
    on a partial ACK it naturally resends a genuine hole. Tomorrow's 6675 makes SACK the primary
    driver.
14. **What if `fast_retransmit` returns None on a partial ACK?** Nothing to resend; we deflated cwnd
    and fall through (no packet). Rare edge.
15. **Why route full ACKs through `on_ack`?** Reuse — Reno's in-recovery exit already deflates and
    clears the flag, and is already tested.
16. **Is the comparison wrap-safe?** Yes — `seq::before` is modular 32-bit comparison.
17. **What initial value does `recover` get?** `iss`; it's never read unless `in_recovery()`.
18. **Does NewReno change the dup-ACK threshold?** No — still 3 (RFC 5681).
19. **Does it change slow start / congestion avoidance?** No — only the in-recovery ACK handling.
20. **What about an RTO during NewReno recovery?** `on_timeout` collapses cwnd to 1·MSS and clears
    `in_recovery` (Doc 10), same as always — NewReno is about *avoiding* that RTO, not changing it.
21. **Why `saturating_sub`/`max(MSS)`?** To keep cwnd a sane `u32` ≥ one segment under any ACK.
22. **How is this tested without a network?** Two congestion-unit tests (arithmetic) + one connection
    test that drives a real two-loss recovery and asserts the retransmission sequence numbers.
23. **Which test would fail under plain Reno?**
    `newreno_partial_ack_retransmits_the_next_hole_and_stays_in_recovery` — Reno wouldn't retransmit
    S5 on the partial ACK.
24. **Is NewReno still relevant with SACK everywhere?** Yes — it's the mandatory fallback when SACK
    isn't negotiated, and the conceptual base 6675 builds on.
25. **What's the cost vs Reno?** One `u32` field and one comparison per ACK. Essentially free.
26. **Does NewReno help with reordering (not loss)?** Not really — three dup ACKs from reordering can
    still trigger a spurious fast retransmit; that's what TCP timestamps/Eifel/DSACK address.
27. **What's `recover` called in the kernel?** Linux tracks `high_seq`/`snd_high` for the same idea.
28. **Why not just always use SACK recovery?** SACK must be negotiated; ~all peers support it, but
    not all — and middleboxes sometimes strip it. NewReno needs nothing.
29. **Does NewReno keep sending new data during recovery?** Minimally (cwnd is tight and it's busy
    retransmitting). Keeping the pipe full during recovery is 6675's job.
30. **Biggest thing still missing after today?** SACK-driven recovery with a `pipe` estimator
    (tomorrow) — repair *all* holes at once and stay at line rate.

## I. Anki starter deck

```text
Q: Reno recovers from how many losses per window without an RTO?  A: one.
Q: What does Reno do on the 2nd loss in a window?  A: stalls until the RTO (the flaw).
Q: NewReno's one new variable?  A: recover = SND.NXT, frozen at fast-recovery entry.
Q: Partial ACK definition?  A: a new ACK during recovery with SEG.ACK < recover.
Q: Full ACK definition?  A: a new ACK with SEG.ACK ≥ recover → recovery complete.
Q: On a partial ACK, NewReno does what?  A: retransmit the next hole, deflate a bit, STAY in recovery.
Q: On a full ACK, NewReno does what?  A: deflate to ssthresh, exit recovery.
Q: Partial-ACK cwnd adjustment?  A: cwnd − acked + MSS.
Q: Why freeze recover at entry?  A: new data sent during recovery is beyond the window being repaired.
Q: NewReno needs what from the peer?  A: nothing — only the cumulative ACK.
Q: How many holes does NewReno repair per RTT?  A: one.
Q: What repairs all holes at once?  A: SACK recovery (RFC 6675).
Q: Where does `recover` live in our code?  A: the Connection (it's a sequence number).
Q: Where does cwnd math live?  A: the byte-oriented CongestionControl module.
Q: NewReno converts Reno's timeouts into…?  A: extra round trips (one per extra loss).
Q: Default Linux CC today?  A: CUBIC (NewReno is the conformance baseline).
```

## J. Glossary

- **NewReno** — RFC 6582 refinement of fast recovery that handles multiple losses per window using
  the cumulative ACK and a recovery point.
- **`recover`** — the value of `SND.NXT` captured when fast recovery begins; the right edge of the
  window being repaired.
- **Partial ACK** — a new ACK during recovery that doesn't reach `recover`; signals another hole.
- **Full ACK** — a new ACK that reaches/exceeds `recover`; recovery is complete.
- **Fast recovery** — the window-management phase after a fast retransmit, keeping the pipe estimate
  while the retransmission is outstanding.
- **Deflation** — restoring cwnd to ssthresh when recovery ends.
- **Pipe** — the estimate of bytes actually in flight; cwnd is a proxy for it during recovery.
- **ssthresh** — slow-start threshold; the cwnd boundary between exponential and linear growth, set
  to half FlightSize on loss.
- **Reno** — RFC 5681 fast recovery; the single-loss-per-window predecessor.
- **CUBIC / BBR** — modern congestion controls layered on this recovery machinery.

## K. Reference tables

**K.1 — ACK handling by phase**

```text
   phase                ACK kind        action                                  cwnd
   ──────────────────   ─────────────   ─────────────────────────────────────   ──────────────────
   not in recovery      new data        slow start / congestion avoidance        grow
   not in recovery      duplicate ×3    enter recovery, recover=SND.NXT, retx     ssthresh + 3·MSS
   in recovery          duplicate       inflate                                   += MSS
   in recovery          partial (new)   retransmit next hole, stay               − acked + MSS
   in recovery          full (new)      exit recovery                             = ssthresh
   any                  RTO             collapse, slow-start restart              = MSS
```

**K.2 — recovery cost by loss count (one window)**

```text
   losses   Reno              NewReno          SACK/6675
   ──────   ───────────────   ──────────────   ─────────────
   1        1 RTT             1 RTT            1 RTT
   2        1 RTT + 1 RTO     2 RTT            ~1 RTT
   k        1 RTT + (k−1)RTO  k RTT            ~1 RTT
```

**K.3 — what each congestion method touches**

```text
   method            phase            in our code
   ───────────────   ──────────────   ───────────────────────────────────
   on_ack            growth / exit    slow start, CA, full-ACK recovery exit
   on_dup_ack        loss detect      3 dup ACKs → enter recovery + inflate
   on_partial_ack    NewReno (Day20)  partial ACK → deflate, stay in recovery
   on_timeout        RTO              collapse to 1 MSS, slow-start restart
   in_recovery       query (Day20)    lets the connection route ACKs
```

> Re-type `on_partial_ack`, the `recover = SND.NXT` snapshot, and the
> `in_recovery() && seq::before(ack, recover)` decision with the book closed, then `cargo test`. When
> your stack can lose two segments in one window and repair both in two round trips — no timeout, no
> cliff — you own NewReno, and you're ready for SACK recovery tomorrow.
