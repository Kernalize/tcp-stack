# Doc 21 — TCP, Part 19: SACK-Based Loss Recovery — `pipe`, `IsLost`, `NextSeg` (RFC 6675)

> Goal: turn Doc 18's selective acknowledgements from a *retransmission hint* into a full
> *loss-recovery engine*. SACK (Doc 18) lets the receiver tell us exactly which islands it holds
> above a hole; NewReno (Doc 20) recovers from multiple losses but only *one hole per round trip* and
> goes nearly silent while it does. RFC 6675 ("A Conservative Loss Recovery Algorithm Based on SACK")
> uses the SACK scoreboard to do far better: infer **every** lost segment at once (`IsLost`),
> estimate the bytes genuinely in flight (`pipe`), and then — gated by `pipe < cwnd` — retransmit
> *all* the holes **and** push new data, keeping the link full throughout recovery. A window that
> loses three segments is repaired in a single round trip instead of three, and the pipe never
> drains.
>
> This is the capstone of the reliability arc that began on Doc 6: retransmission queue (Doc 12),
> reassembly (Doc 9), congestion control (Doc 10), SACK blocks (Doc 18), NewReno (Doc 20), and now
> the algorithm that ties the scoreboard to the congestion window. We keep NewReno as the fallback
> for peers that don't speak SACK; RFC 6675 is what runs when they do — which, on today's internet,
> is almost always.

**Contents**

Volume I — the chapter
1. The mental model: from "resend the oldest" to "fill the pipe"
2. Why NewReno still under-performs, concretely
3. The three primitives: `IsLost`, `pipe`, `NextSeg`
4. `IsLost` — inferring loss from the scoreboard
5. `pipe` — the bytes actually in flight
6. `NextSeg` — what to put on the wire next
7. The recovery loop: `while pipe < cwnd`
8. Where it lives: the queue computes, the connection paces
9. The Rust: borrows, ascending order, and `wrapping` arithmetic
10. A fully worked three-loss trace — NewReno vs 6675
11. The code, walked end to end
12. Verification — the three new tests, and why each exists
13. Why this, not that
14. Honesty: what production does that we don't
15. Rebuild it yourself — checklist + exercises
16. What the next day adds

Volume II — the exhaustive reference
- A. RFC 6675 in full: the variables and the four routines
- B. `IsLost` precisely — blocks vs bytes vs our segment count
- C. `pipe` precisely — the per-octet definition and our per-segment one
- D. `NextSeg`'s four rules, and which we implement
- E. Rescue retransmission and the limited-retransmit corner
- F. RFC 6675 vs NewReno vs DSACK vs RACK-TLP
- G. Comparison to real stacks — Linux, FreeBSD, lwIP, smoltcp
- H. Performance — what the pipe estimator buys
- I. Extended FAQ — thirty questions a careful reader asks
- J. Anki starter deck
- K. Glossary
- L. Reference tables

---

# Volume I — the chapter

## 1. The mental model: from "resend the oldest" to "fill the pipe"

Every loss-recovery scheme answers two questions on each ACK: **what should I retransmit?** and **how
much may I send right now?** Trace how our answers have evolved:

```text
   scheme      "what to retransmit?"              "how much may I send?"
   ─────────   ────────────────────────────────  ─────────────────────────────────────
   Reno (D10)  the oldest unacked (1 segment)     cwnd − FlightSize, deflate on recovery exit
   NewReno(D20) the oldest unacked, one per RTT   same — and mostly silent during recovery
   6675 (D21)  EVERY segment IsLost says is gone  cwnd − pipe  (pipe = bytes truly in flight)
```

The leap is the second column. `FlightSize = SND.NXT − SND.UNA` counts *every* byte between UNA and
NXT as "in flight" — including bytes the receiver has already SACKed (it has them; they're not in the
network) and bytes we believe are lost (they're gone). During loss, `FlightSize` wildly over-counts,
so `cwnd − FlightSize` says "you may send 0" and the sender freezes — waiting for ACKs that only
trickle in. RFC 6675 replaces `FlightSize` with **`pipe`**, an honest estimate of what's *actually*
in the network, so the sender can keep transmitting (holes first, then new data) right through the
loss episode. That single substitution — pace by `pipe`, not `FlightSize` — is the soul of SACK
recovery.

## 2. Why NewReno still under-performs, concretely

NewReno (Doc 20) fixed the *correctness* of multiple-loss recovery — no more RTO stalls — but not its
*speed*. It learns about holes through the **cumulative** ACK, which can only reveal the *next* hole
after the *previous* one is filled:

```text
   window: [s1][s2][s3][s4][s5][s6]   lose s2, s4, s6
   RTT 1:  3 dup ACKs → retransmit s2
   RTT 2:  partial ACK (s2 filled, s3 delivered, gap at s4) → retransmit s4
   RTT 3:  partial ACK (s4 filled, s5 delivered, gap at s6) → retransmit s6
   RTT 4:  full ACK → done.        ← three losses cost THREE round trips, pipe near-empty throughout
```

The receiver knew it had s3 and s5 buffered the whole time — it *said so* in SACK blocks — but
NewReno ignores them; it only watches the cumulative ACK. RFC 6675 reads the scoreboard:

```text
   RTT 1:  one SACK ACK names s3, s5 as held → IsLost flags s2, s4, s6 → retransmit ALL THREE,
           and (if pipe < cwnd) send new data too.
   RTT 2:  full ACK → done.        ← three losses cost ONE round trip, pipe kept full.
```

Same information on the wire; 6675 simply *uses* it.

## 3. The three primitives: `IsLost`, `pipe`, `NextSeg`

RFC 6675 is built from three pure functions over the retransmission queue + the SACK scoreboard:

- **`IsLost(seq)`** — "is this segment presumed lost?" True when enough higher segments have been
  SACKed that this gap can't just be reordering.
- **`pipe()`** — "how many bytes are actually in flight?" Sum the segments that are neither SACKed nor
  lost-and-unretransmitted, plus retransmitted ones.
- **`NextSeg()`** — "what do I send next?" The next lost hole to retransmit; or, when no holes remain,
  new data.

In our code these are methods on `RetxQueue` (which already tracks `sacked` per segment from Doc 18,
and `retries` from Doc 12), plus a driver in `Connection::poll_transmit`. Let's take them in turn.

## 4. `IsLost` — inferring loss from the scoreboard

A gap below SACKed data could be a *loss* or merely *reordering* (a segment taking a slower path,
arriving late). We must not retransmit on mere reordering — that wastes the network and can trigger
spurious congestion response. RFC 6675's rule mirrors the three-duplicate-ACK heuristic: presume a
segment lost once **`DupThresh` (3)** segments *above* it have been SACKed. Three later arrivals past
a hole is strong evidence the hole was dropped, not delayed.

```rust
fn is_lost(&self, idx: usize, dup_thresh: u32) -> bool {
    let seg = &self.segments[idx];
    if seg.sacked {
        return false;                    // already received → not lost
    }
    let sacked_above = self.segments.iter()
        .filter(|s| s.sacked && seq::after(s.start_seq, seg.start_seq))
        .count() as u32;
    sacked_above >= dup_thresh
}
```

We count SACKed *segments* with a higher starting sequence number. RFC 6675 phrases the threshold
two ways — "≥ DupThresh discontiguous SACKed blocks above" or "> (DupThresh−1)·SMSS bytes SACKed
above" — which for our one-record-per-MSS queue are equivalent to counting three SACKed segments
above. `seq::after` keeps the comparison correct across the 32-bit wrap.

## 5. `pipe` — the bytes actually in flight

`pipe` is the heart of the day. For each outstanding segment, decide whether it's currently occupying
space in the network:

```rust
pub fn pipe(&self, dup_thresh: u32) -> u32 {
    let mut pipe = 0u32;
    for i in 0..self.segments.len() {
        let s = &self.segments[i];
        if s.sacked {
            continue;                                  // receiver holds it → not in flight
        }
        let retransmitted = s.retries > 0;
        if !self.is_lost(i, dup_thresh) || retransmitted {
            pipe = pipe.wrapping_add(s.end_seq.wrapping_sub(s.start_seq));
        }
        // a lost, never-retransmitted segment has left the network → contributes nothing
    }
    pipe
}
```

The truth table per segment:

```text
   SACKed?   IsLost?   retransmitted?   in pipe?   why
   ───────   ───────   ──────────────   ────────   ──────────────────────────────────────────
   yes       —         —                no         the receiver has it; it's not in the network
   no        no        —                YES        genuinely in flight, no loss inferred
   no        yes       no               no         presumed dropped, not yet resent → gone
   no        yes       yes              YES         we retransmitted it → back on the wire
```

`pipe` is what we compare against `cwnd`. Where `cwnd − FlightSize` would say "0, freeze," `cwnd −
pipe` says "you have room; the SACKed and lost bytes aren't really out there — send."

## 6. `NextSeg` — what to put on the wire next

When the recovery loop has room (`pipe < cwnd`), it asks for the next thing to send. RFC 6675's
`NextSeg` has four rules; the primary one — and the one we implement — is "the next lost segment we
haven't retransmitted yet":

```rust
pub fn next_lost_retransmit(&mut self, dup_thresh: u32, now_ms: u64) -> Option<Vec<u8>> {
    let idx = (0..self.segments.len()).find(|&i| {
        let s = &self.segments[i];
        !s.sacked && s.retries == 0 && self.is_lost(i, dup_thresh)
    })?;
    let s = &mut self.segments[idx];
    s.retries += 1;          // mark retransmitted (RFC 6675 "HighRxt")
    s.sent_at_ms = now_ms;   // reset its retransmission timer
    Some(s.packet.clone())
}
```

`None` means "no lost, un-retransmitted segment remains" — the signal for the caller to switch to
sending *new* data (RFC 6675 `NextSeg` rule (2)). Segments are recorded in ascending sequence order,
so `find` returns the lowest-sequence hole first — we heal holes oldest-to-newest.

## 7. The recovery loop: `while pipe < cwnd`

The driver lives in `poll_transmit`, active only when SACK is negotiated and we're in fast recovery:

```rust
if self.sack_ok && self.cong.in_recovery() {
    let limit = self.send.wnd.min(self.cong.window());     // min(rwnd, cwnd)
    // (1) retransmit every hole the scoreboard reveals, oldest first
    while self.retx.pipe(DUP_THRESH) < limit {
        match self.retx.next_lost_retransmit(DUP_THRESH, now_ms) {
            Some(pkt) => out.push(pkt),
            None => break,                                 // no more known holes
        }
    }
    // (2) then fill the remaining pipe with NEW data
    let mss = self.send_mss as usize;
    while !self.send_buf.is_empty() {
        let pipe = self.retx.pipe(DUP_THRESH);
        if pipe >= limit { break; }
        let n = ((limit - pipe) as usize).min(mss).min(self.send_buf.len());
        if n == 0 { break; }
        /* … build PSH|ACK segment, advance SND.NXT, record for retx … */
    }
    return out;
}
```

Two phases, one invariant: never let `pipe` exceed `min(cwnd, rwnd)`. Phase (1) drains the known
holes; phase (2) keeps the link busy with fresh bytes once the holes are healing. Each retransmission
and each new segment bumps `pipe` (the former via `retries`, the latter via a new `record`), so the
loop is self-terminating. Nagle is deliberately skipped here — during recovery we *want* to fill the
window, not coalesce.

## 8. Where it lives: the queue computes, the connection paces

The same separation-of-concerns that made Doc 20 small applies again:

```text
   ┌────────────────────────────────────────────┐    ┌──────────────────────────────────────┐
   │ RetxQueue — owns the scoreboard             │    │ Connection — owns cwnd/rwnd & sending │
   │ • is_lost(idx, DupThresh)   (loss inference)│    │ • poll_transmit recovery loop          │
   │ • pipe(DupThresh)           (bytes in net)  │ ◀─ │   while pipe < min(cwnd, rwnd):        │
   │ • next_lost_retransmit(...)  (which hole)   │    │     retransmit hole, else send new     │
   └────────────────────────────────────────────┘    └──────────────────────────────────────┘
```

The queue knows *which bytes are where* (SACKed, lost, retransmitted); the connection knows *how much
the network and receiver will take* (`cwnd`, `rwnd`) and *owns the send buffer*. The queue computes
pure facts; the connection makes the pacing decisions. This is why the three queue primitives are
unit-testable with no connection at all (and two of our three new tests do exactly that).

## 9. The Rust: borrows, ascending order, and `wrapping` arithmetic

**Immutable borrows during the search, mutable after.** `next_lost_retransmit` calls `self.is_lost`
(which borrows `&self`) inside `find`'s closure, then takes `&mut self.segments[idx]` *after* the
search completes. The closure only ever borrows immutably (multiple immutable borrows coexist), and
the mutable borrow begins after `find` returns its `usize`. The borrow checker enforces that we never
hold the mutable borrow while still searching — which would be a real aliasing bug.

**Ascending insertion order is a load-bearing invariant.** We always `record` segments in increasing
sequence order, so `find` returning the *first* matching index returns the *lowest-sequence* hole —
no explicit sort needed. The doc comment on `next_lost_retransmit` states this dependency so a future
refactor that reorders the queue knows to revisit it.

**`wrapping_sub` for lengths, `seq::after` for comparisons.** `s.end_seq − s.start_seq` uses
`wrapping_sub` so a segment that straddles the 32-bit wrap still yields its true length; "is this
SACKed segment above that one?" uses the modular `seq::after`, not `>`. Every sequence comparison in
the file goes through `seq::` for exactly this reason (Doc 3).

## 10. A fully worked three-loss trace — NewReno vs 6675

`MSS = 1460`, `cwnd` grown to `5·MSS`, five segments in flight: `s11..s15` covering
`[U, U+5·MSS)` where `U = SND.UNA`. The peer loses `s11` and `s12`, receives `s13,s14,s15`.

```text
   #  event                                   6675 action                              pipe / state
   ── ──────────────────────────────────────  ───────────────────────────────────────  ────────────────────
   1  s13,s14,s15 arrive; s11,s12 lost        peer SACKs [U+2·MSS, U+5·MSS), cum=U      (3 dup ACKs follow)
   2  dup ACK #1 (SACK marks s13,s14,s15)     mark_sacked                               s13–15 out of pipe
   3  dup ACK #2                              —                                         —
   4  dup ACK #3                              enter recovery; recover = SND.NXT;        ssthresh, cwnd set;
                                              fast-retransmit s11                        s11 retransmitted
   5  poll_transmit (same ACK round):                                                    pipe = 1·MSS (just s11)
        pipe 1·MSS < cwnd → NextSeg = s12     retransmit s12                            pipe = 2·MSS
        pipe 2·MSS < cwnd → NextSeg = None    (no more holes); send_buf empty → stop    out = [s12]
   6  s11,s12 arrive → peer delivers s11..s15 full ACK (≥ recover) → exit recovery       pipe = 0, done
```

Both holes (`s11` via the dup-ACK entry, `s12` via the `poll_transmit` loop) are retransmitted in the
**same ACK round** (step 4–5). The connection test asserts exactly this: `s11` from the third dup
ACK, then `s12` from `poll_transmit`, before any new RTT. NewReno would have stopped at `s11` and
waited a whole round trip for a partial ACK to reveal `s12`. With three or four losses the gap widens
linearly — that's the throughput RFC 6675 recovers.

## 11. The code, walked end to end

The feature is three `RetxQueue` methods, one `poll_transmit` branch, and one constant.

**The constant** (`src/tcp.rs`): `const DUP_THRESH: u32 = 3;` — the SACK loss threshold, the
scoreboard analogue of three duplicate ACKs.

**The queue primitives** (`src/tcp.rs`, on `RetxQueue`): `is_lost` (private), `pipe`,
`next_lost_retransmit` — §§4–6. They read `sacked` (Doc 18) and `retries` (Doc 12); no new per-segment
state was needed.

**The pacing** (`src/tcp.rs`, in `poll_transmit`): the `sack_ok && in_recovery()` branch of §7,
placed *before* the ordinary `usable_window`/Nagle path so it intercepts recovery while leaving
steady-state sending (and the whole non-SACK NewReno world) untouched.

**Entry is unchanged.** We still enter recovery via the third duplicate ACK (`on_dup_ack`), which
sets `recover` (Doc 20) and fast-retransmits the first hole. RFC 6675 then takes over the *rest* of
the retransmissions through `poll_transmit`. The SACK marking (`mark_sacked`, Doc 18) already happens
on every ACK, so the scoreboard is current before the loop reads it.

**Fallback is automatic.** When `sack_ok` is false, the `poll_transmit` branch is skipped entirely
and NewReno (Doc 20) handles recovery through the cumulative ACK. One stack, two recovery engines,
selected by whether the peer offered SACK in its SYN.

## 12. Verification — the three new tests, and why each exists

`cargo test` — **117 passing** (114 + 3). Two pin the queue arithmetic; one drives a full SACK
recovery through the connection.

- **`pipe_excludes_sacked_and_lost_counts_retransmitted`** — five 100-byte segments, top three
  SACKed → bottom two `IsLost`. Asserts `pipe == 0` (nothing really in flight), then that
  retransmitting each hole adds it back (`pipe` 100, then 200), then that no un-retransmitted lost
  segment remains. This is the pipe truth table (§5) made executable.
- **`pipe_does_not_presume_loss_below_threshold`** — only *two* SACKed above the holes (< DupThresh)
  → nothing is `IsLost`, `pipe` counts both holes as in flight, `next_lost_retransmit` returns
  `None`. Pins the reordering-vs-loss boundary: two later arrivals are not yet proof of loss.
- **`sack_recovery_retransmits_all_holes_in_one_round`** — the §10 trace end to end: ramp cwnd to
  5·MSS, lose two of five segments, and assert that the third dup ACK fast-retransmits `s11` *and*
  the subsequent `poll_transmit` retransmits `s12` — both in one ACK round, by sequence number. This
  is the test that fails under NewReno (which wouldn't retransmit `s12` until the next RTT).

## 13. Why this, not that

**Why pace by `pipe` instead of `FlightSize`?** Because during loss `FlightSize` counts SACKed and
lost bytes as "in flight," which they aren't — it under-estimates available window to zero and
freezes the sender. `pipe` is the honest count, so the sender keeps working. (§1.)

**Why retransmit all holes at once instead of one per RTT?** Because the scoreboard already tells us
all of them; waiting an RTT each to "rediscover" what we already know is pure latency. (§2.)

**Why keep NewReno at all?** SACK is negotiated; a peer (or a middlebox) might not offer it. NewReno
is the cumulative-ACK-only fallback, mandatory for interop. 6675 *uses* SACK when present and *defers*
to NewReno when absent. (§11.)

**Why count SACKed *segments* above rather than RFC 6675's blocks/bytes?** Our queue stores one
record per transmitted segment (≈ one MSS), so "three SACKed segments above" is equivalent to "three
discontiguous SACKed blocks / 3·MSS bytes above." Same threshold, simpler to compute on our data
structure. (§4, §B.)

**Why mark retransmits with `retries` rather than a separate `Retran` flag?** `retries > 0` already
means "this segment has been resent," which is exactly RFC 6675's `HighRxt`/Retran predicate for
`pipe` and `NextSeg`. Reusing it avoids redundant state that could drift out of sync. (§5.)

**Why do the retransmits in `poll_transmit` and not `on_segment`?** `on_segment` returns a single
packet; recovery needs to emit *several*. `poll_transmit` already returns a `Vec` and is already
called after every segment by the event loop — the natural home for "send as much as the pipe
allows." (§7.)

## 14. Honesty: what production does that we don't

- **`NextSeg` rules (3) and (4) — rescue retransmission.** RFC 6675 has two more `NextSeg` cases: a
  "rescue" retransmission of the highest-sequence un-SACKed segment when nothing else is available
  (to avoid an RTO when the last segments are lost), and handling for segments past `RecoveryPoint`.
  We implement rule (1) (lost holes) and rule (2) (new data); rescue is exercise E3.
- **No explicit `RecoveryPoint`/`HighRxt`/`HighData` variables.** RFC 6675 names several scoreboard
  cursors; we derive their effect from `SND.UNA`, `SND.NXT`, `sacked`, and `retries`. Equivalent for
  our queue, but a larger stack tracks them explicitly for the corner cases.
- **No reneging handling.** If a receiver *discards* data it previously SACKed (legal but rare under
  memory pressure), a real stack must clear the scoreboard and fall back to cumulative recovery (RFC
  6675 §5.1). We keep SACK state across RTOs (Doc 18) and don't detect reneging.
- **No DSACK (RFC 2883) feedback into recovery.** DSACK reports *duplicate* receipt, letting a sender
  detect a *spurious* retransmit and undo its congestion reaction. We parse SACK blocks but don't act
  on duplicate ones.
- **Still loss-based, and segment-granular.** `pipe`/`IsLost` work per recorded segment, not per
  octet; a partially-SACKed segment isn't split. Fine for our one-segment-per-record queue; a
  byte-granular scoreboard is what large stacks keep.
- **The echo server never bulk-sends**, so this engine, like cwnd, rarely binds in the live binary —
  it's exercised by the unit tests and would bind under the Doc 22 socket API doing a real transfer.

None of these are wrong in what we built; they're the next refinements. Our `pipe`/`IsLost`/`NextSeg`
core is faithful RFC 6675 for the common multi-loss case.

## 15. Rebuild it yourself — checklist + exercises

**Checklist**

- [ ] Add `const DUP_THRESH: u32 = 3`.
- [ ] `RetxQueue::is_lost(idx, dup_thresh)` — `≥ dup_thresh` SACKed segments above, and not itself
      SACKed.
- [ ] `RetxQueue::pipe(dup_thresh)` — sum lengths of segments that are `!sacked && (!is_lost ||
      retransmitted)`.
- [ ] `RetxQueue::next_lost_retransmit(dup_thresh, now)` — first `!sacked && retries==0 && is_lost`,
      mark retransmitted, return bytes.
- [ ] `poll_transmit`: when `sack_ok && in_recovery()`, loop `while pipe < min(cwnd, rwnd)`
      retransmitting holes then sending new data; `return` before the ordinary path.
- [ ] `cargo test` green (117), `cargo clippy -- -D warnings` clean.

**Exercises**

1. **E1 — three-loss test.** Extend the connection test to lose *three* of six segments and assert
   all three holes are retransmitted in one round (two via `poll_transmit`). Convince yourself 6675
   is O(1) round trips in the number of losses.
2. **E2 — `pipe` vs `FlightSize`.** Add an assertion comparing `pipe()` to `SND.NXT − SND.UNA` mid-
   recovery; show `pipe` is strictly smaller and explain by how much (the SACKed + lost bytes).
3. **E3 — rescue retransmission (NextSeg rule 4).** When no `IsLost` segment remains but the pipe has
   room and the highest un-SACKed segment is still outstanding, retransmit *it* to avoid an RTO on a
   tail loss. Test a scenario where the *last* two segments are lost.
4. **E4 — reneging.** Simulate a receiver that SACKs `[a,b)` then later cumulatively ACKs *below* `a`
   while un-SACKing it; detect the inconsistency and clear `sacked` flags (RFC 6675 §5.1).
5. **E5 — measure it.** Under `tc qdisc … netem loss 8%`, run a bulk transfer (Doc 22 socket API)
   with SACK on vs off (force NewReno) and compare completion time and the retransmission timeline in
   `tcpdump`.

Make Anki cards from the `pipe` truth table and the `while pipe < cwnd` loop — those are the two
ideas that *are* RFC 6675.

## 16. What the next day adds

Tomorrow we finally give all of this an **application to drive it**: a blocking `TcpListener` /
`TcpStream` façade over the event loop (the doc11-book §11 exercise), plus **outgoing segmentation**
below one delivered run and **multi-request / keep-alive HTTP** with full header buffering. Until now
our "application" has been a hard-coded echo that never bulk-sends, so cwnd, NewReno, and the `pipe`
estimator have been exercised only by tests. Doc 22 builds the API a real program calls — at which
point a single `stream.write_all(big_buffer)` finally puts this whole reliability stack under genuine
load.

---

# Volume II — the exhaustive reference

## A. RFC 6675 in full: the variables and the four routines

RFC 6675 ("A Conservative Loss Recovery Algorithm Based on SACK") layers on RFC 5681/6582. Its state
and routines, mapped to our code:

```text
   RFC 6675 concept     meaning                                  our analogue
   ──────────────────   ──────────────────────────────────────  ─────────────────────────────────
   HighACK              highest cumulatively ACKed sequence       SND.UNA
   HighData             highest sequence transmitted              SND.NXT
   HighRxt              highest sequence retransmitted             (per-segment retries > 0)
   RecoveryPoint        SND.NXT at recovery start                  recover (Doc 20)
   the scoreboard       per-range SACK state                      Unacked.sacked (Doc 18)
   IsLost(SeqNum)       loss inference                            RetxQueue::is_lost
   SetPipe()/Pipe       bytes in flight                           RetxQueue::pipe
   NextSeg()            what to (re)transmit next                 next_lost_retransmit (+ new data)
   Update()             ingest a SACK block                       mark_sacked (Doc 18)
```

The control flow on each ACK during recovery (RFC 6675 §5, simplified to what we implement):

```text
   1. Update() the scoreboard from the SACK blocks.                  (mark_sacked, on every ACK)
   2. If a full ACK (cum ≥ RecoveryPoint): exit recovery.            (on_ack, Doc 20)
   3. Else SetPipe(); while (pipe < cwnd):                           (poll_transmit loop)
        a. (re)transmit NextSeg();                                   (next_lost_retransmit / new data)
        b. pipe += the bytes just sent.
```

## B. `IsLost` precisely — blocks vs bytes vs our segment count

RFC 6675 §4 defines `IsLost(SeqNum)` as true iff `SeqNum` has not been SACKed **and** either:

```text
   (a) at least DupThresh discontiguous SACKed sequences have arrived above SeqNum, OR
   (b) more than (DupThresh − 1) * SMSS bytes have been SACKed above SeqNum.
```

For a queue with one record per ≈MSS-sized segment, "DupThresh discontiguous blocks above" and
"(DupThresh−1)·SMSS bytes above" both reduce to **three SACKed segments above** — which is what we
count. The two RFC forms exist because real scoreboards are byte-granular and must handle partial and
coalesced blocks; ours is segment-granular by construction, so the simpler count is exact for us. The
threshold of 3 deliberately matches the three-duplicate-ACK rule: three pieces of evidence past a gap
before we call it loss, so ordinary reordering (which rarely displaces by three segments) doesn't
trigger a spurious retransmit.

## C. `pipe` precisely — the per-octet definition and our per-segment one

RFC 6675 §4 `SetPipe()` walks every octet `S1` in `(HighACK, HighData]`:

```text
   pipe = 0
   for each octet S1 in (HighACK, HighData]:
       if not IsLost(S1):    pipe += 1     // believed still in the network
       if S1 <= HighRxt:     pipe += 1     // has been retransmitted → also in the network
```

Our per-segment `pipe()` computes the same quantity one record at a time:

```text
   for each outstanding segment S:
       if S.sacked:                       contribute 0     (≈ IsLost-style exclusion of received data)
       else if is_lost(S) && !retransmitted: contribute 0  (lost, not resent → not in network)
       else:                              contribute len(S) (in flight, or retransmitted)
```

The one cosmetic difference: the RFC's literal "if not IsLost → pipe++" would *also* count a SACKed
octet (IsLost is false for it), then rely on the surrounding algorithm not to send it; we exclude
SACKed segments up front, which is the same net `pipe` for the cases that matter and avoids
double-counting. Both yield "bytes genuinely occupying the pipe right now."

## D. `NextSeg`'s four rules, and which we implement

RFC 6675 §4 `NextSeg()` returns the next sequence to transmit, trying in order:

```text
   (1) the smallest SeqNum with IsLost(SeqNum) true and not yet retransmitted  ← we implement (holes)
   (2) if none, NEW data at HighData (SND.NXT), if cwnd/rwnd allow             ← we implement (new data)
   (3) a not-IsLost hole above HighRxt not yet retransmitted (early retransmit)  — not implemented
   (4) "rescue": the highest outstanding un-SACKed segment, to avoid a tail RTO  — exercise E3
```

We implement (1) in `next_lost_retransmit` and (2) in the `poll_transmit` new-data loop — the two
rules that carry the common multi-loss case. Rules (3) and (4) handle tail-loss corners (the last
segments of a transfer lost, where there's nothing "above" to SACK and thus nothing to make them
`IsLost`); without them a tail loss falls back to the RTO, which is correct but slower. E3 adds
rescue.

## E. Rescue retransmission and the limited-retransmit corner

The classic gap that rules (3)/(4) cover: a transfer's **last** few segments are lost. Nothing arrives
after them, so no SACK block ever appears "above" them, so `IsLost` never fires, so `NextSeg` rule (1)
never selects them — and recovery stalls until the RTO. Rescue retransmission (rule 4) says: if the
pipe has room and you've exhausted the lost holes, retransmit the highest outstanding segment anyway,
on spec, to coax an ACK before the timer. Related is **Limited Transmit** (RFC 3042): on the first
*two* duplicate ACKs (before the third triggers recovery), send *new* data if the window allows, to
keep ACKs flowing and improve the odds of reaching DupThresh. We implement neither; both are natural
follow-ons and noted here so the gap is explicit.

## F. RFC 6675 vs NewReno vs DSACK vs RACK-TLP

```text
   scheme       needs SACK?   loss signal              holes/RTT   tail-loss   spurious-retx detect
   ──────────   ───────────   ──────────────────────   ─────────   ─────────   ────────────────────
   NewReno      no            cumulative ACK / partial  1           RTO         no
   RFC 6675     yes           SACK scoreboard (IsLost)  all         RTO (+rescue) no
   DSACK 2883   yes           duplicate SACK            —           —           YES (undo cwnd cut)
   RACK-TLP     yes+TS        time since send (RACK)    all         probe (TLP) yes
   (RFC 8985)
```

RFC 6675 is the SACK-era standard our stack now implements. The modern frontier is **RACK-TLP** (RFC
8985), which replaces the *count*-based DupThresh with a *time*-based test ("a segment is lost if a
segment sent later has been ACKed and enough time has passed"), eliminating the reordering
sensitivity and handling tail loss with a Tail Loss Probe. RACK builds directly on our Doc 16
timestamps + Doc 18 SACK; it's the natural successor day.

## G. Comparison to real stacks — Linux, FreeBSD, lwIP, smoltcp

```text
   aspect                Linux             FreeBSD         lwIP            smoltcp       ours (Doc 21)
   ───────────────────   ───────────────   ─────────────   ─────────────   ───────────   ──────────────
   SACK recovery         RACK-TLP (6675+)  6675 + RACK     basic/none      6675-ish      6675 core
   pipe estimator        yes               yes             no              yes           yes
   IsLost                time-based (RACK)  count + time    n/a             count         count (3 seg)
   rescue / tail-loss    TLP               TLP             RTO             partial       RTO (E3)
   reneging handling     yes               yes             n/a             partial       no
   DSACK                 yes               yes             no              partial       parse only
```

Linux moved past pure 6675 to RACK-TLP years ago, but 6675 remains the conformance baseline and the
thing RACK is described *relative to*. Our column is "faithful 6675 core, RTO for the tail" — the
right place for a teaching stack that already has the SACK scoreboard and timestamps to build RACK on
next.

## H. Performance — what the pipe estimator buys

Two wins, both about *not wasting round trips*:

```text
   losses in window   NewReno round trips   6675 round trips
   ────────────────   ───────────────────   ────────────────
   1                  1                     1
   2                  2                     1
   3                  3                     1
   k                  k                     1   (all holes known at once)
```

and, less visibly but just as important, **the pipe stays full**. NewReno mostly *retransmits* during
recovery and sends little new data, so throughput sags even when it isn't stalled. 6675's `pipe <
cwnd` loop sends new data the moment the holes are covered, so the bottleneck link keeps draining the
window. On a high bandwidth-delay-product path with sporadic loss, that's the difference between
sawtoothing far below capacity and riding near it.

The cost is bookkeeping: O(segments) per `pipe()` call, called O(segments) times per recovery → O(n²)
in the worst case for our linear-scan queue. Fine for our window sizes; production stacks keep the
scoreboard in a balanced tree / interval structure for O(log n) updates.

## I. Extended FAQ — thirty questions a careful reader asks

1. **What problem does 6675 solve that NewReno doesn't?** Recovering *all* losses in a window in one
   round trip, and keeping the pipe full during recovery — NewReno does one hole per RTT and goes
   quiet.
2. **What is `pipe`?** An estimate of bytes actually in flight: outstanding minus SACKed minus
   lost-unretransmitted, plus retransmitted.
3. **Why not just use `FlightSize`?** It counts SACKed and lost bytes as in flight, so during loss it
   over-counts and freezes the sender.
4. **What makes a segment `IsLost`?** Three (DupThresh) SACKed segments above it and itself not
   SACKed.
5. **Why three?** It mirrors the three-duplicate-ACK rule — enough evidence past a gap to rule out
   ordinary reordering.
6. **What does `NextSeg` return?** The next lost hole to retransmit; or, when none remain, new data.
7. **Which `NextSeg` rules do we implement?** (1) lost holes and (2) new data; not (3) early-retx or
   (4) rescue.
8. **What's the recovery loop invariant?** `pipe < min(cwnd, rwnd)` — never put more in flight than
   the network and receiver allow.
9. **Where does the loop live?** `poll_transmit`, which already returns a `Vec` and runs after every
   ACK.
10. **How do we enter recovery?** Still via three duplicate ACKs (`on_dup_ack`) — SACK rides on those
    dup ACKs. 6675 then drives the rest of the retransmissions.
11. **Where does the scoreboard come from?** `mark_sacked` (Doc 18), called on every ACK before the
    loop reads it.
12. **What marks a segment "retransmitted" for `pipe`?** `retries > 0` (Doc 12) — reused as RFC
    6675's HighRxt/Retran predicate.
13. **Does a SACKed segment count in `pipe`?** No — the receiver has it; it's not in the network.
14. **Does a lost-but-retransmitted segment count?** Yes — it's back on the wire.
15. **Does a lost-not-yet-retransmitted segment count?** No — it has left the network.
16. **What if `pipe ≥ cwnd`?** Send nothing this round — the pipe is full; wait for ACKs to open it.
17. **Why skip Nagle during recovery?** We *want* to fill the window with retransmits and new data;
    coalescing would defeat that.
18. **What happens when SACK isn't negotiated?** The `poll_transmit` branch is skipped; NewReno (Doc
    20) handles recovery via the cumulative ACK.
19. **How is the loop self-terminating?** Each (re)transmission raises `pipe`; once `pipe ≥ limit` or
    no holes/new-data remain, it stops.
20. **Is the order of retransmission defined?** Oldest hole first — `find` returns the lowest-sequence
    `IsLost` segment because the queue is in ascending order.
21. **Can `pipe` exceed cwnd?** Momentarily, if cwnd shrinks, but we never *add* when `pipe ≥ limit`,
    so it converges down as ACKs arrive.
22. **Does 6675 change how we *exit* recovery?** No — the full-ACK exit is NewReno's (Doc 20), via
    `recover`.
23. **What's reneging and do we handle it?** A receiver discarding previously-SACKed data; we don't
    detect it (exercise E4).
24. **What about tail loss (last segments dropped)?** No SACK appears above them, so `IsLost` never
    fires → we fall back to the RTO. Rescue retransmission (E3) fixes this.
25. **Why is `is_lost` private but `pipe`/`next_lost_retransmit` public?** `is_lost` is an internal
    helper; the other two are the interface `poll_transmit` (and tests) call.
26. **How is this tested without a network?** Two unit tests on `RetxQueue` (pipe/threshold) and one
    connection test driving a real two-loss recovery, asserting retransmission sequence numbers.
27. **Which test fails under NewReno?** `sack_recovery_retransmits_all_holes_in_one_round` — NewReno
    wouldn't retransmit the second hole in the same round.
28. **Complexity?** O(segments) per `pipe`, O(segments) calls per recovery → O(n²) worst case for our
    linear queue; production uses a tree for O(log n).
29. **Does this interact with timestamps (Doc 16)?** Not directly today, but RACK-TLP (the successor)
    uses timestamps to replace the count-based `IsLost` — a natural next day.
30. **Single biggest thing still missing?** Rescue/TLP for tail loss, and RACK's time-based loss
    detection (RFC 8985).

## J. Anki starter deck

```text
Q: RFC 6675 in one line?  A: SACK-based loss recovery: infer all holes, pace by pipe, fill the link.
Q: pipe is?  A: estimated bytes actually in flight (outstanding − SACKed − lost-unretransmitted + retransmitted).
Q: Why pace by pipe not FlightSize?  A: FlightSize over-counts SACKed/lost bytes and freezes the sender.
Q: IsLost(S) is true when?  A: S not SACKed AND ≥ DupThresh (3) segments SACKed above it.
Q: NextSeg primary rule?  A: the lowest-sequence lost, not-yet-retransmitted segment.
Q: NextSeg when no holes remain?  A: send new data (keep the pipe full).
Q: The recovery loop invariant?  A: while pipe < min(cwnd, rwnd): (re)transmit.
Q: How many round trips to fix k losses — NewReno vs 6675?  A: k vs 1.
Q: A SACKed segment's contribution to pipe?  A: zero (the receiver has it).
Q: A retransmitted lost segment's contribution to pipe?  A: its length (back on the wire).
Q: What marks "retransmitted" in our code?  A: retries > 0 (RFC 6675 HighRxt).
Q: How do we enter 6675 recovery?  A: 3 duplicate ACKs (carrying SACK), same as before.
Q: Fallback when SACK isn't negotiated?  A: NewReno (cumulative ACK), Doc 20.
Q: Tail-loss weakness of 6675?  A: nothing SACKs above the last segments → RTO (rescue/TLP fixes it).
Q: The modern successor to 6675?  A: RACK-TLP (RFC 8985), time-based loss detection.
```

## K. Glossary

- **SACK scoreboard** — the per-segment record of which outstanding data the receiver has SACKed.
- **`pipe`** — RFC 6675's estimate of bytes actually in flight; the rate-control signal for recovery.
- **`IsLost`** — loss inference: a segment with ≥ DupThresh SACKed segments above it is presumed lost.
- **`NextSeg`** — RFC 6675's "what to send next" routine: lost holes, then new data (then rescue).
- **DupThresh** — the loss threshold (3); the SACK analogue of three duplicate ACKs.
- **HighRxt / Retran** — the highest retransmitted sequence; a segment is "retransmitted" if resent.
- **RecoveryPoint** — SND.NXT frozen at recovery entry (our `recover`, Doc 20); recovery ends when the
  cumulative ACK reaches it.
- **Rescue retransmission** — retransmitting the highest outstanding segment to avoid a tail-loss RTO.
- **Reneging** — a receiver discarding data it previously SACKed.
- **RACK-TLP** — the time-based successor (RFC 8985) to count-based loss detection.

## L. Reference tables

**L.1 — segment contribution to `pipe`**

```text
   state of segment                         in pipe?   bytes contributed
   ──────────────────────────────────────   ────────   ─────────────────
   SACKed                                    no         0
   in flight, not lost                       yes        its length
   lost (IsLost), not retransmitted          no         0
   lost, retransmitted (retries > 0)         yes        its length
```

**L.2 — recovery cost by loss count (one window)**

```text
   losses   Reno (D10)        NewReno (D20)    RFC 6675 (D21)
   ──────   ───────────────   ──────────────   ──────────────
   1        1 RTT             1 RTT            1 RTT
   2        1 RTT + 1 RTO     2 RTT            1 RTT
   3        1 RTT + 2 RTO     3 RTT            1 RTT
   k        1 RTT + (k−1)RTO  k RTT            1 RTT
```

**L.3 — the RFC 6675 routines and our code**

```text
   routine    purpose                         our method                         tested by
   ────────   ─────────────────────────────   ────────────────────────────────   ───────────────────────────
   Update()   ingest a SACK block             mark_sacked (Doc 18)               out_of_order_data_acks… etc.
   IsLost()   loss inference                  RetxQueue::is_lost (private)        via pipe / next_lost tests
   SetPipe()  bytes in flight                 RetxQueue::pipe                     pipe_excludes_sacked…
   NextSeg()  what to (re)transmit            next_lost_retransmit + new data    sack_recovery_retransmits…
```

> Re-type `is_lost`, `pipe`, `next_lost_retransmit`, and the `while pipe < min(cwnd, rwnd)` loop with
> the book closed, then `cargo test`. When your stack can lose three segments in one window and put
> all three retransmissions on the wire in a single round trip — while still sending new data — you
> own RFC 6675, and you're ready to give it a real application to push tomorrow.
